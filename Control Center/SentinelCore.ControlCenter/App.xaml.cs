using System.Net.Http;
using System.Windows;
using SentinelCore.Demon1.Learning.Controller;
using SentinelCore.Demon3.Core.Notifications;
using MessageBox = System.Windows.MessageBox;

namespace SentinelCore.ControlCenter;

public partial class App : System.Windows.Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var failedAttempts = new AuthenticationFailureAlertGate(2);
        Task? authenticationAlert = null;
        try
        {
            void OnAuthenticationFailure()
            {
                if (failedAttempts.RecordFailure()) authenticationAlert = SendAuthenticationFailureAlertAsync();
            }

            var auth = Demon1AuthenticationFacade.AuthenticateOwner(onFailedAttempt: OnAuthenticationFailure);
            if (auth is null)
            {
                if (authenticationAlert is not null) await authenticationAlert;
                Shutdown();
                return;
            }

            var startProtectionAfterAuth = e.Args.Any(arg => string.Equals(arg, "--start-protection-after-auth", StringComparison.Ordinal));
            var window = new MainWindow(auth, startProtectionAfterAuth);
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            if (authenticationAlert is not null) await authenticationAlert;
            MessageBox.Show("L’authentification de SentinelCore a échoué : " + ex.Message,
                "SentinelCore — authentification", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    private static async Task SendAuthenticationFailureAlertAsync()
    {
        try
        {
            var settings = new TelegramAlertSettingsStore().Load();
            if (settings is not { Enabled: true }) return;
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
            var result = await new TelegramBotApiClient(http).SendMessageAsync(settings,
                "SENTINELCORE — AVERTISSEMENT\nDeux tentatives d’authentification propriétaire ont échoué dans une même ouverture de session.");
            System.Diagnostics.Trace.WriteLine(result.Succeeded
                ? "Alerte d’échecs d’authentification envoyée par Telegram."
                : "Alerte Telegram d’authentification non envoyée : " + result.ReasonCode);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine("Alerte Telegram d’authentification indisponible : " + ex.GetType().Name);
        }
    }
}
