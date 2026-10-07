using FileEncryptionDashboard.Data;
using FileEncryptionDashboard.Forms;
using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;

namespace FileEncryptionDashboard;

/// <summary>
/// Application entry point. It wires the layers together (database, services,
/// forms) and then loops: log in, use the app, log out, log in again.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // Standard WinForms start-up (DPI settings, default font, visual styles).
        ApplicationConfiguration.Initialize();

        // Repository layer: create the database file and tables on first start.
        string connectionString = Database.BuildConnectionString(Database.DefaultPath);
        Database.Initialize(connectionString);

        // Service layer.
        var auth = new AuthService(new UserRepository(connectionString));

        while (true)
        {
            using var loginForm = new LoginForm(auth);
            if (loginForm.ShowDialog() != DialogResult.OK || loginForm.Session is null)
            {
                break; // the user closed the login window: exit the application
            }

            // The session (and its master key) is wiped when this block ends.
            using UserSession session = loginForm.Session;
            using var mainForm = new MainForm(session);
            if (mainForm.ShowDialog() != DialogResult.Retry)
            {
                break; // window closed with the X button: exit the application
            }
            // Retry means "log out": go round again to the login screen.
        }
    }
}
