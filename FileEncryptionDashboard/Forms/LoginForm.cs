using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;

namespace FileEncryptionDashboard.Forms;

/// <summary>
/// GUI layer: the login window. It has two modes, "log in" and "create account".
/// On the very first run only account creation is offered, and that first
/// account becomes the Admin. Later accounts are General Users.
/// The password hashing is deliberately slow, so it runs on a background task
/// (async/await) to keep the window responsive.
/// </summary>
public sealed class LoginForm : Form
{
    private readonly AuthService _auth;

    private readonly Label _titleLabel = new();
    private readonly Label _messageLabel = new();
    private readonly Label _usernameLabel = new();
    private readonly TextBox _usernameBox = new();
    private readonly Label _passwordLabel = new();
    private readonly TextBox _passwordBox = new();
    private readonly Label _confirmLabel = new();
    private readonly TextBox _confirmBox = new();
    private readonly Label _statusLabel = new();
    private readonly Button _primaryButton = new();
    private readonly Button _switchButton = new();

    private bool _isFirstRun;
    private bool _registering;

    /// <summary>The session created by a successful login (null if the user cancelled).</summary>
    public UserSession? Session { get; private set; }

    public LoginForm(AuthService auth)
    {
        _auth = auth;
        _isFirstRun = _auth.IsFirstRun;

        BuildLayout();
        SetMode(registering: _isFirstRun);
    }

    // ---------- layout ----------

    /// <summary>Creates and arranges all controls in code (no designer file is needed).</summary>
    private void BuildLayout()
    {
        Text = "File Encryption Dashboard";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(380, 460);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(24),
            ColumnCount = 1
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

        _titleLabel.Font = new Font(Font.FontFamily, 15f, FontStyle.Bold);
        _titleLabel.AutoSize = true;
        _titleLabel.Margin = new Padding(0, 0, 0, 8);

        _messageLabel.AutoSize = true;
        _messageLabel.MaximumSize = new Size(330, 0); // wrap long text
        _messageLabel.Margin = new Padding(0, 0, 0, 12);

        _usernameLabel.Text = "Username";
        _usernameLabel.AutoSize = true;
        _passwordLabel.Text = "Password";
        _passwordLabel.AutoSize = true;
        _confirmLabel.Text = "Confirm password";
        _confirmLabel.AutoSize = true;

        _passwordBox.UseSystemPasswordChar = true;
        _confirmBox.UseSystemPasswordChar = true;
        foreach (TextBox box in new[] { _usernameBox, _passwordBox, _confirmBox })
        {
            box.Dock = DockStyle.Fill;
            box.Margin = new Padding(0, 2, 0, 10);
        }

        _statusLabel.AutoSize = true;
        _statusLabel.MaximumSize = new Size(330, 0);
        _statusLabel.Margin = new Padding(0, 4, 0, 8);

        _primaryButton.Height = 34;
        _primaryButton.Dock = DockStyle.Fill;
        _primaryButton.Click += PrimaryButton_Click;

        _switchButton.Height = 30;
        _switchButton.Dock = DockStyle.Fill;
        _switchButton.Click += SwitchButton_Click;

        Control[] rows =
        {
            _titleLabel, _messageLabel,
            _usernameLabel, _usernameBox,
            _passwordLabel, _passwordBox,
            _confirmLabel, _confirmBox,
            _statusLabel, _primaryButton, _switchButton
        };
        foreach (Control row in rows)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(row);
        }

        Controls.Add(layout);
        AcceptButton = _primaryButton; // pressing Enter clicks the main button
    }

    /// <summary>Switches between "log in" and "create account" and updates the texts.</summary>
    private void SetMode(bool registering)
    {
        _registering = registering;

        _confirmLabel.Visible = registering;
        _confirmBox.Visible = registering;
        _switchButton.Visible = !_isFirstRun; // on first run there is nothing to switch to
        _statusLabel.Text = string.Empty;

        if (_isFirstRun)
        {
            _titleLabel.Text = "Create administrator";
            _messageLabel.Text = "No accounts exist yet. The first account you create becomes the Admin.";
            _primaryButton.Text = "Create account";
        }
        else if (registering)
        {
            _titleLabel.Text = "Create account";
            _messageLabel.Text = "New accounts are General Users. The password needs at least 8 characters.";
            _primaryButton.Text = "Create account";
            _switchButton.Text = "Back to log in";
        }
        else
        {
            _titleLabel.Text = "Log in";
            _messageLabel.Text = "Enter your username and password.";
            _primaryButton.Text = "Log in";
            _switchButton.Text = "Create a new account";
        }
    }

    /// <summary>Shows a message under the form fields: red for errors, green for success.</summary>
    private void ShowStatus(string message, bool isError)
    {
        _statusLabel.ForeColor = isError ? Color.Firebrick : Color.SeaGreen;
        _statusLabel.Text = message;
    }

    /// <summary>Disables the buttons and shows a wait cursor while background work runs.</summary>
    private void SetBusy(bool busy)
    {
        _primaryButton.Enabled = !busy;
        _switchButton.Enabled = !busy;
        UseWaitCursor = busy;
    }

    // ---------- event handlers ----------

    private void SwitchButton_Click(object? sender, EventArgs e)
    {
        SetMode(registering: !_registering);
    }

    /// <summary>
    /// Handles the main button. 'async void' is acceptable here because this is
    /// an event handler; exceptions are caught inside so none escape.
    /// </summary>
    private async void PrimaryButton_Click(object? sender, EventArgs e)
    {
        SetBusy(true);
        try
        {
            if (_registering)
            {
                await RegisterAsync();
            }
            else
            {
                await LogInAsync();
            }
        }
        catch (InvalidLoginException ex)
        {
            ShowStatus(ex.Message, isError: true);
            _passwordBox.Clear();
            _passwordBox.Focus();
        }
        catch (RegistrationException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (Exception ex)
        {
            // Last resort: anything unexpected (for example a database problem).
            ShowStatus("Unexpected error: " + ex.Message, isError: true);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task LogInAsync()
    {
        string username = _usernameBox.Text;
        string password = _passwordBox.Text;

        // PBKDF2 takes a noticeable fraction of a second, so run it off the UI thread.
        Session = await Task.Run(() => _auth.Login(username, password));
        DialogResult = DialogResult.OK; // closes the dialog
    }

    private async Task RegisterAsync()
    {
        string username = _usernameBox.Text;
        string password = _passwordBox.Text;

        if (password != _confirmBox.Text)
        {
            ShowStatus("The two passwords do not match.", isError: true);
            return;
        }

        Role role = _isFirstRun ? Role.Admin : Role.GeneralUser;
        await Task.Run(() => _auth.Register(username, password, role));

        // Registration done: go back to the log-in screen.
        _isFirstRun = false;
        _passwordBox.Clear();
        _confirmBox.Clear();
        SetMode(registering: false);
        ShowStatus($"Account '{username}' created. You can now log in.", isError: false);
    }
}
