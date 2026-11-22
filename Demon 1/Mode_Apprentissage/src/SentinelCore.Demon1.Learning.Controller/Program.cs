namespace SentinelCore.Demon1.Learning.Controller;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--broker") return Demon1BackgroundBrokerRuntime.Run(args.Skip(1).ToArray());
        if (args.Length > 0 && args[0] == "--worker") return global::CollectorRuntime.Run(args.Skip(1).ToArray());
        var auth = Demon1AuthenticationFacade.AuthenticateOwner();
        if (auth is null) return 0;
        var workerExecutablePath = Path.Combine(AppContext.BaseDirectory, "SentinelCore.Demon1.Learning.Controller.exe");
        Application.Run(new MainForm(auth, workerExecutablePath));
        return 0;
    }
}
