using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using SentinelCore.Demon3.Core.AI;

namespace SentinelCore.ControlCenter;

public enum OllamaServerState
{
    AlreadyRunning,
    StartedByThisManager,
    Unavailable
}

public enum OllamaSelectedModelState
{
    Present,
    Absent,
    Unknown
}

public enum OllamaStopState
{
    Stopped,
    NotOwned,
    AlreadyExited,
    StopFailed
}

public sealed record OllamaServerManagerResult(
    OllamaServerState ServerState,
    OllamaSelectedModelState ModelState,
    string SelectedModel,
    string? ReasonCode)
{
    public bool IsServerAvailable => ServerState is OllamaServerState.AlreadyRunning or OllamaServerState.StartedByThisManager;
}

/// <summary>
/// Checks and optionally starts the local Ollama server. It never downloads models and never
/// stops a process unless <see cref="StopOwnedServerAsync"/> is explicitly called.
/// </summary>
public sealed class OllamaServerManager
{
    private const int MaximumTagsResponseBytes = 1024 * 1024;
    private static readonly Uri TagsEndpoint = new("http://127.0.0.1:11434/api/tags", UriKind.Absolute);
    private static readonly HttpClient LoopbackHttp = new(new SocketsHttpHandler { UseProxy = false })
    { Timeout = Timeout.InfiniteTimeSpan };

    private readonly SemaphoreSlim _operationGate = new(1, 1);
    private readonly TimeSpan _startupTimeout;
    private readonly TimeSpan _probeTimeout;
    private readonly TimeSpan _pollInterval;
    private Process? _ownedProcess;
    private Task? _stdoutDrain;
    private Task? _stderrDrain;

    public OllamaServerManager(TimeSpan? startupTimeout = null, TimeSpan? probeTimeout = null, TimeSpan? pollInterval = null)
    {
        _startupTimeout = startupTimeout ?? TimeSpan.FromSeconds(25);
        _probeTimeout = probeTimeout ?? TimeSpan.FromSeconds(2);
        _pollInterval = pollInterval ?? TimeSpan.FromMilliseconds(350);

        if (_startupTimeout < TimeSpan.FromSeconds(1) || _startupTimeout > TimeSpan.FromSeconds(90))
            throw new ArgumentOutOfRangeException(nameof(startupTimeout), "Le délai de démarrage doit être compris entre 1 et 90 secondes.");
        if (_probeTimeout < TimeSpan.FromMilliseconds(100) || _probeTimeout > TimeSpan.FromSeconds(10))
            throw new ArgumentOutOfRangeException(nameof(probeTimeout), "Le délai de sonde doit être compris entre 100 ms et 10 secondes.");
        if (_pollInterval < TimeSpan.FromMilliseconds(100) || _pollInterval > TimeSpan.FromSeconds(2))
            throw new ArgumentOutOfRangeException(nameof(pollInterval), "L’intervalle de sonde doit être compris entre 100 ms et 2 secondes.");
    }

    /// <summary>Ensures the local API is ready, starting Ollama only when the API is unavailable.</summary>
    public async Task<OllamaServerManagerResult> EnsureRunningAsync(
        string selectedModel,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selectedModel);
        if (!IsValidLocalModelName(selectedModel))
            return Unavailable(selectedModel, "INVALID_LOCAL_MODEL_NAME");

        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var initialProbe = await ProbeTagsAsync(cancellationToken).ConfigureAwait(false);
            if (initialProbe.ApiAvailable)
                return CreateResult(GetAvailableServerState(), selectedModel, initialProbe);

            if (_ownedProcess is { HasExited: false } existingProcess)
                return await WaitForServerAsync(existingProcess, selectedModel, cancellationToken).ConfigureAwait(false);

            await ReleaseExitedOwnedProcessAsync().ConfigureAwait(false);
            var executable = FindOllamaExecutable();
            if (executable is null)
                return Unavailable(selectedModel, "OLLAMA_EXECUTABLE_NOT_FOUND");

            Process? process = null;
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    WorkingDirectory = Path.GetDirectoryName(executable)!,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                startInfo.ArgumentList.Add("serve");

                process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
                if (!process.Start())
                {
                    process.Dispose();
                    return Unavailable(selectedModel, "OLLAMA_PROCESS_START_FAILED");
                }
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
            {
                process?.Dispose();
                return Unavailable(selectedModel, "OLLAMA_PROCESS_START_FAILED");
            }

            if (process is null) return Unavailable(selectedModel, "OLLAMA_PROCESS_START_FAILED");
            _ownedProcess = process;
            // Ollama can write continuously. Drain both redirected streams and discard the text;
            // this avoids pipe back-pressure and prevents server output from entering app logs.
            _stdoutDrain = DrainAndDiscardAsync(process.StandardOutput);
            _stderrDrain = DrainAndDiscardAsync(process.StandardError);
            return await WaitForServerAsync(process, selectedModel, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _operationGate.Release();
        }
    }

    /// <summary>Stops and releases only the Ollama process started and retained by this manager.</summary>
    public async Task<OllamaStopState> StopOwnedServerAsync(CancellationToken cancellationToken = default)
    {
        await _operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var process = _ownedProcess;
            if (process is null) return OllamaStopState.NotOwned;

            if (HasExited(process))
            {
                await ReleaseExitedOwnedProcessAsync().ConfigureAwait(false);
                return OllamaStopState.AlreadyExited;
            }

            try
            {
                process.Kill(entireProcessTree: false);
                await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(8), cancellationToken)
                    .ConfigureAwait(false);
                await ReleaseExitedOwnedProcessAsync().ConfigureAwait(false);
                return OllamaStopState.Stopped;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or TimeoutException)
            {
                return OllamaStopState.StopFailed;
            }
        }
        finally
        {
            _operationGate.Release();
        }
    }

    private async Task<OllamaServerManagerResult> WaitForServerAsync(
        Process process,
        string selectedModel,
        CancellationToken cancellationToken)
    {
        var deadline = Stopwatch.GetTimestamp() + (long)(_startupTimeout.TotalSeconds * Stopwatch.Frequency);
        while (Stopwatch.GetTimestamp() < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var probe = await ProbeTagsAsync(cancellationToken).ConfigureAwait(false);
            if (probe.ApiAvailable)
            {
                var state = HasExited(process) ? OllamaServerState.AlreadyRunning : OllamaServerState.StartedByThisManager;
                return CreateResult(state, selectedModel, probe);
            }

            if (HasExited(process))
            {
                var finalProbe = await ProbeTagsAsync(cancellationToken).ConfigureAwait(false);
                if (finalProbe.ApiAvailable)
                    return CreateResult(OllamaServerState.AlreadyRunning, selectedModel, finalProbe);
                return Unavailable(selectedModel, "OLLAMA_PROCESS_EXITED_BEFORE_API_READY");
            }

            var remaining = TimeSpan.FromSeconds((deadline - Stopwatch.GetTimestamp()) / (double)Stopwatch.Frequency);
            if (remaining <= TimeSpan.Zero) break;
            await Task.Delay(remaining < _pollInterval ? remaining : _pollInterval, cancellationToken).ConfigureAwait(false);
        }

        return Unavailable(selectedModel, "OLLAMA_STARTUP_TIMEOUT");
    }

    private async Task<TagsProbe> ProbeTagsAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_probeTimeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, TagsEndpoint);
            using var response = await LoopbackHttp.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return new(false, null, "OLLAMA_API_HTTP_ERROR");
            if (response.Content.Headers.ContentLength is long size && size > MaximumTagsResponseBytes)
                return new(true, null, "OLLAMA_TAGS_RESPONSE_TOO_LARGE");

            var json = await ReadBoundedAsync(response.Content, MaximumTagsResponseBytes, timeout.Token).ConfigureAwait(false);
            if (json is null) return new(true, null, "OLLAMA_TAGS_RESPONSE_TOO_LARGE");

            using var document = JsonDocument.Parse(json);
            if (!document.RootElement.TryGetProperty("models", out var models) || models.ValueKind != JsonValueKind.Array)
                return new(true, null, "OLLAMA_TAGS_RESPONSE_INVALID");

            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var model in models.EnumerateArray())
            {
                if (model.ValueKind == JsonValueKind.Object
                    && model.TryGetProperty("name", out var name)
                    && name.ValueKind == JsonValueKind.String
                    && !string.IsNullOrWhiteSpace(name.GetString()))
                    names.Add(name.GetString()!);
            }
            return new(true, names, null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, null, "OLLAMA_API_TIMEOUT");
        }
        catch (HttpRequestException)
        {
            return new(false, null, "OLLAMA_API_UNREACHABLE");
        }
        catch (IOException)
        {
            return new(false, null, "OLLAMA_API_READ_FAILED");
        }
        catch (JsonException)
        {
            return new(true, null, "OLLAMA_TAGS_RESPONSE_INVALID");
        }
    }

    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, int maximumBytes, CancellationToken cancellationToken)
    {
        await using var source = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) return destination.ToArray();
            if (destination.Length + read > maximumBytes) return null;
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private OllamaServerManagerResult CreateResult(OllamaServerState state, string selectedModel, TagsProbe probe)
    {
        var modelState = probe.ModelNames is null
            ? OllamaSelectedModelState.Unknown
            : probe.ModelNames.Contains(selectedModel) ? OllamaSelectedModelState.Present : OllamaSelectedModelState.Absent;
        var reasonCode = modelState == OllamaSelectedModelState.Absent ? "SELECTED_MODEL_NOT_INSTALLED" : probe.ReasonCode;
        return new(state, modelState, selectedModel, reasonCode);
    }

    private OllamaServerState GetAvailableServerState()
        => _ownedProcess is { } process && !HasExited(process)
            ? OllamaServerState.StartedByThisManager
            : OllamaServerState.AlreadyRunning;

    private static OllamaServerManagerResult Unavailable(string selectedModel, string reasonCode)
        => new(OllamaServerState.Unavailable, OllamaSelectedModelState.Unknown, selectedModel, reasonCode);

    private async Task ReleaseExitedOwnedProcessAsync()
    {
        var process = _ownedProcess;
        if (process is null || !HasExited(process)) return;

        _ownedProcess = null;
        try { if (_stdoutDrain is not null) await _stdoutDrain.ConfigureAwait(false); } catch (IOException) { }
        try { if (_stderrDrain is not null) await _stderrDrain.ConfigureAwait(false); } catch (IOException) { }
        process.Dispose();
        _stdoutDrain = null;
        _stderrDrain = null;
    }

    private static bool HasExited(Process process)
    {
        try { return process.HasExited; }
        catch (InvalidOperationException) { return true; }
    }

    private static async Task DrainAndDiscardAsync(StreamReader reader)
    {
        try
        {
            while (await reader.ReadLineAsync().ConfigureAwait(false) is not null) { }
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }

    private static string? FindOllamaExecutable()
    {
        var candidates = new List<string>();
        var path = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(path))
        {
            foreach (var entry in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var directory = Environment.ExpandEnvironmentVariables(entry.Trim('"'));
                if (Path.IsPathRooted(directory)) candidates.Add(Path.Combine(directory, "ollama.exe"));
            }
        }

        AddInstallCandidate(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Ollama", "ollama.exe");
        AddInstallCandidate(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Ollama", "ollama.exe");
        AddInstallCandidate(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Ollama", "ollama.exe");
        AddInstallCandidate(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Ollama", "ollama.exe");

        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var fullPath = Path.GetFullPath(candidate);
                if (File.Exists(fullPath) && string.Equals(Path.GetExtension(fullPath), ".exe", StringComparison.OrdinalIgnoreCase))
                    return fullPath;
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or NotSupportedException or UnauthorizedAccessException) { }
        }

        return null;

        void AddInstallCandidate(params string[] segments)
        {
            if (segments.Length == 0 || string.IsNullOrWhiteSpace(segments[0])) return;
            candidates.Add(Path.Combine(segments));
        }
    }

    private static bool IsValidLocalModelName(string model)
        => !string.IsNullOrWhiteSpace(model)
            && model.Length <= 120
            && !OllamaAdvisorOptions.IsCloudModelTag(model)
            && model.All(c => char.IsAsciiLetterOrDigit(c) && c <= 127 || c is ':' or '_' or '-' or '.' or '/');

    private sealed record TagsProbe(bool ApiAvailable, HashSet<string>? ModelNames, string? ReasonCode);
}
