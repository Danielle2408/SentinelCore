using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SentinelCore.Demon2.Service;

internal static class WindowsServiceDispatcher
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceStopped = 0x00000001;
    private const uint AcceptStop = 0x00000001;
    private const uint AcceptShutdown = 0x00000004;
    private const uint ControlStop = 0x00000001;
    private const uint ControlShutdown = 0x00000005;
    private const int ErrorFailedServiceControllerConnect = 1063;
    private const string ServiceName = "SentinelCoreDemon2";

    private static ServiceMainCallback? _serviceMain;
    private static HandlerCallback? _handler;
    private static Func<CancellationToken, Task>? _worker;
    private static CancellationTokenSource? _stop;
    private static IntPtr _statusHandle;
    private static ServiceStatus _status;

    public static void Run(Func<CancellationToken, Task> worker)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Threat Monitor is a Windows service.");
        _worker = worker;
        _serviceMain = ServiceMain;
        _handler = HandleControl;
        var table = new[]
        {
            new ServiceTableEntry { ServiceName = ServiceName, ServiceProc = _serviceMain },
            new ServiceTableEntry { ServiceName = null, ServiceProc = null }
        };
        if (StartServiceCtrlDispatcher(table)) return;
        var error = Marshal.GetLastWin32Error();
        if (error != ErrorFailedServiceControllerConnect) throw new Win32Exception(error);
        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, e) => { e.Cancel = true; cts.Cancel(); };
        Console.CancelKeyPress += cancelHandler;
        try
        {
            try { worker(cts.Token).GetAwaiter().GetResult(); }
            catch (OperationCanceledException) when (cts.IsCancellationRequested) { }
        }
        finally { Console.CancelKeyPress -= cancelHandler; }
    }

    private static void ServiceMain(uint argc, IntPtr argv)
    {
        _statusHandle = RegisterServiceCtrlHandlerEx(ServiceName, _handler!, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero) return;
        _status = new ServiceStatus { ServiceType = ServiceWin32OwnProcess, CurrentState = ServiceStartPending, WaitHint = 10_000 };
        SetServiceStatus(_statusHandle, ref _status);
        _stop = new CancellationTokenSource();
        _status.CurrentState = ServiceRunning;
        _status.ControlsAccepted = AcceptStop | AcceptShutdown;
        _status.CheckPoint = 0;
        _status.WaitHint = 0;
        SetServiceStatus(_statusHandle, ref _status);
        try { _worker!(_stop.Token).GetAwaiter().GetResult(); }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (Exception ex) { Console.Error.WriteLine(ex); _status.Win32ExitCode = 1; }
        _status.CurrentState = ServiceStopped;
        _status.ControlsAccepted = 0;
        SetServiceStatus(_statusHandle, ref _status);
        _stop.Dispose();
        _stop = null;
    }

    private static uint HandleControl(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ControlStop or ControlShutdown)
        {
            _status.CurrentState = ServiceStopPending;
            _status.ControlsAccepted = 0;
            _status.WaitHint = 10_000;
            SetServiceStatus(_statusHandle, ref _status);
            _stop?.Cancel();
        }
        return 0;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry { [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName; public ServiceMainCallback? ServiceProc; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceMainCallback(uint argc, IntPtr argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint HandlerCallback(uint control, uint eventType, IntPtr eventData, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceStartTable);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerCallback callback, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus serviceStatus);
}
