using FileEncryptionDashboard.Models;

namespace FileEncryptionDashboard.Forms;

/// <summary>
/// GUI layer: the main window shown after login.
/// This is a placeholder for now: it shows who is logged in. The encrypt and
/// decrypt features are added in the next stage.
/// </summary>
public sealed class MainForm : Form
{
    public MainForm(UserSession session)
    {
        Text = "File Encryption Dashboard";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(560, 360);

        var welcomeLabel = new Label
        {
            Text = $"Logged in as {session.Username} ({(session.IsAdmin ? "Admin" : "General User")})",
            Font = new Font(Font.FontFamily, 14f, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(24, 24)
        };

        var infoLabel = new Label
        {
            Text = session.IsAdmin
                ? "Admins can encrypt and decrypt files and view the encryption log."
                : "General Users can encrypt and decrypt their own files.",
            AutoSize = true,
            Location = new Point(24, 70)
        };

        var logoutButton = new Button
        {
            Text = "Log out",
            Size = new Size(100, 32),
            Location = new Point(24, 300),
            Anchor = AnchorStyles.Left | AnchorStyles.Bottom
        };
        logoutButton.Click += (sender, e) => DialogResult = DialogResult.Retry; // closes the form

        Controls.Add(welcomeLabel);
        Controls.Add(infoLabel);
        Controls.Add(logoutButton);
    }
}
