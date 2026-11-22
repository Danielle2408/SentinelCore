namespace SentinelCore.Demon1.Learning.Controller;

/// <summary>
/// Shared D1 owner-authentication entry point for the standalone controller and trusted hosts.
/// The returned AuthStore is non-null only after setup or successful face/password verification.
/// </summary>
public static class Demon1AuthenticationFacade
{
    private static readonly object InitializationLock = new();
    private static bool _formsInitialized;

    /// <summary>
    /// Shows the existing D1 first-run master-password setup, or the existing face/password
    /// sign-in dialog. Returns null when the owner closes or cancels authentication.
    /// Call before creating the D1 control or showing the host's main window.
    /// </summary>
    public static AuthStore? AuthenticateOwner(IWin32Window? dialogOwner = null, Action? onFailedAttempt = null)
    {
        EnsureWindowsFormsInitialized();
        var auth = new AuthStore();
        if (!auth.IsConfigured)
        {
            using var setup = new MasterPasswordDialog(isSetup: true);
            if (ShowDialog(setup, dialogOwner) != DialogResult.OK || string.IsNullOrEmpty(setup.Password)) return null;
            auth.SetPassword(setup.Password);
            return auth;
        }

        var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon1Learning");
        var settings = LearningSettings.Load(dataRoot);
        using var authentication = new StartupAuthDialog(auth, dataRoot, settings, onFailedAttempt);
        return ShowDialog(authentication, dialogOwner) == DialogResult.OK ? auth : null;
    }

    private static DialogResult ShowDialog(Form dialog, IWin32Window? owner)
        => owner is null ? dialog.ShowDialog() : dialog.ShowDialog(owner);

    private static void EnsureWindowsFormsInitialized()
    {
        if (_formsInitialized) return;
        lock (InitializationLock)
        {
            if (_formsInitialized) return;
            ApplicationConfiguration.Initialize();
            _formsInitialized = true;
        }
    }
}
