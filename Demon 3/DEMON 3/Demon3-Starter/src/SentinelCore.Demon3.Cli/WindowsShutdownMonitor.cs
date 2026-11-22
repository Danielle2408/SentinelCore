using System.Globalization;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace SentinelCore.Demon3.Cli;

/// <summary>Receives Windows end-session broadcasts through a hidden top-level window.</summary>
internal sealed class WindowsShutdownMonitor : IDisposable
{
    private const int WmQueryEndSession = 0x0011;
    private const int WmEndSession = 0x0016;
    private readonly ManualResetEventSlim _ready = new(false);
    private readonly Thread _messageThread;
    private ShutdownWindow? _window;
    private Exception? _startupFailure;

    public WindowsShutdownMonitor(Action beforeShutdown, Action onShutdown)
    {
        ArgumentNullException.ThrowIfNull(beforeShutdown);
        ArgumentNullException.ThrowIfNull(onShutdown);

        _messageThread = new Thread(() =>
        {
            try
            {
                using var window = new ShutdownWindow(beforeShutdown, onShutdown, _ready);
                _window = window;
                Application.Run(window);
            }
            catch (Exception exception)
            {
                _startupFailure = exception;
                _ready.Set();
            }
        })
        {
            IsBackground = true,
            Name = "SentinelCore Windows shutdown monitor"
        };
        _messageThread.SetApartmentState(ApartmentState.STA);
        _messageThread.Start();

        if (!_ready.Wait(TimeSpan.FromSeconds(5)))
            throw new TimeoutException("La fenêtre interne de notification Windows n’a pas démarré.");
        if (_startupFailure is not null)
            throw new InvalidOperationException("La fenêtre interne de notification Windows n’a pas pu démarrer.", _startupFailure);
    }

    public void Dispose()
    {
        var window = _window;
        if (window is not null && !window.IsDisposed && window.IsHandleCreated)
        {
            try { window.BeginInvoke((Action)window.Close); }
            catch (InvalidOperationException) { }
        }
        _messageThread.Join(TimeSpan.FromSeconds(2));
        _ready.Dispose();
    }

    private sealed class ShutdownWindow : Form
    {
        private readonly Action _beforeShutdown;
        private readonly Action _onShutdown;
        private readonly ManualResetEventSlim _ready;
        private int _shutdownPreparationStarted;

        public ShutdownWindow(Action beforeShutdown, Action onShutdown, ManualResetEventSlim ready)
        {
            _beforeShutdown = beforeShutdown;
            _onShutdown = onShutdown;
            _ready = ready;
            Text = $"SentinelCoreShutdownMonitor:{Environment.ProcessId}";
            ShowInTaskbar = false;
            FormBorderStyle = FormBorderStyle.None;
            StartPosition = FormStartPosition.Manual;
            Location = new System.Drawing.Point(-32000, -32000);
            Size = new System.Drawing.Size(1, 1);
            WindowState = FormWindowState.Normal;
            Opacity = 0;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Hide();
            WriteIsolatedTestHandle();
            _ready.Set();
        }

        private void WriteIsolatedTestHandle()
        {
            var pipeName = Environment.GetEnvironmentVariable("SENTINELCORE_TEST_GUARD_PIPE_NAME");
            var requestedPath = Environment.GetEnvironmentVariable("SENTINELCORE_TEST_SHUTDOWN_HANDLE_PATH");
            if (string.IsNullOrWhiteSpace(pipeName) || !pipeName.StartsWith("SentinelCore.Guard.BackgroundTest.", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(requestedPath)) return;

            try
            {
                var fullPath = Path.GetFullPath(requestedPath);
                var tempPrefix = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (fullPath.StartsWith(tempPrefix, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Path.GetFileName(fullPath), "shutdown-handle.txt", StringComparison.OrdinalIgnoreCase))
                    File.WriteAllText(fullPath, Handle.ToInt64().ToString("X", CultureInfo.InvariantCulture));
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException) { }
        }

        protected override void WndProc(ref Message message)
        {
            if (message.Msg == WmQueryEndSession)
            {
                if (Interlocked.Exchange(ref _shutdownPreparationStarted, 1) == 0)
                    _beforeShutdown();
                message.Result = new IntPtr(1);
                return;
            }

            if (message.Msg == WmEndSession)
            {
                if (message.WParam != IntPtr.Zero)
                    _onShutdown();
                else
                    Interlocked.Exchange(ref _shutdownPreparationStarted, 0);
                message.Result = IntPtr.Zero;
                return;
            }

            base.WndProc(ref message);
        }
    }
}
