using FileEncryptionDashboard.Data;
using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;

namespace FileEncryptionDashboard.Forms;

/// <summary>
/// GUI layer: the main window. Users pick a file, then encrypt or decrypt it.
/// The work runs asynchronously with a progress bar and a Cancel button, so the
/// window never freezes. Every successful encryption is recorded in the database.
/// </summary>
public sealed class MainForm : Form
{
    private readonly UserSession _session;
    private readonly EncryptionService _encryption;
    private readonly IKeyRepository _keys;

    private readonly TextBox _encryptPathBox = new();
    private readonly Button _encryptBrowseButton = new();
    private readonly Button _encryptButton = new();
    private readonly TextBox _decryptPathBox = new();
    private readonly Button _decryptBrowseButton = new();
    private readonly Button _decryptButton = new();
    private readonly Button _logoutButton = new();
    private readonly Button _cancelButton = new();
    private readonly ProgressBar _progressBar = new();
    private readonly Label _statusLabel = new();

    private CancellationTokenSource? _cts;
    private bool _busy;

    public MainForm(UserSession session, EncryptionService encryption, IKeyRepository keys)
    {
        _session = session;
        _encryption = encryption;
        _keys = keys;
        BuildLayout();
    }

    // ---------- layout ----------

    private void BuildLayout()
    {
        Text = "File Encryption Dashboard";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        ClientSize = new Size(640, 400);

        string roleName = _session.IsAdmin ? "Admin" : "General User";
        var header = new Label
        {
            Text = $"Logged in as {_session.Username} ({roleName})",
            Font = new Font(Font.FontFamily, 13f, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(24, 20)
        };

        _logoutButton.Text = "Log out";
        _logoutButton.Size = new Size(100, 30);
        _logoutButton.Location = new Point(516, 16);
        _logoutButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _logoutButton.Click += (sender, e) => DialogResult = DialogResult.Retry; // closes the form

        _encryptBrowseButton.Click += (sender, e) => Browse(_encryptPathBox, "Choose a file to encrypt", null);
        _encryptButton.Click += EncryptButton_Click;
        _decryptBrowseButton.Click += (sender, e) =>
            Browse(_decryptPathBox, "Choose an encrypted file", "Encrypted files (*.enc)|*.enc|All files (*.*)|*.*");
        _decryptButton.Click += DecryptButton_Click;

        _progressBar.Style = ProgressBarStyle.Marquee; // endless animation: we cannot know the percentage
        _progressBar.Location = new Point(24, 300);
        _progressBar.Size = new Size(480, 20);
        _progressBar.Visible = false;

        _cancelButton.Text = "Cancel";
        _cancelButton.Size = new Size(100, 30);
        _cancelButton.Location = new Point(516, 295);
        _cancelButton.Visible = false;
        _cancelButton.Click += (sender, e) => _cts?.Cancel();

        _statusLabel.AutoSize = true;
        _statusLabel.MaximumSize = new Size(592, 0);
        _statusLabel.Location = new Point(24, 336);

        Controls.Add(header);
        Controls.Add(_logoutButton);
        Controls.Add(BuildFileGroup("Encrypt a file", 64, _encryptPathBox, _encryptBrowseButton, _encryptButton,
            "Encrypt", "The encrypted copy is saved next to the original with .enc added to its name."));
        Controls.Add(BuildFileGroup("Decrypt a file", 180, _decryptPathBox, _decryptBrowseButton, _decryptButton,
            "Decrypt", "Only the account that encrypted a file can decrypt it."));
        Controls.Add(_progressBar);
        Controls.Add(_cancelButton);
        Controls.Add(_statusLabel);
    }

    /// <summary>Builds one boxed section (path box, Browse button, action button, hint text).</summary>
    private static GroupBox BuildFileGroup(string title, int top, TextBox pathBox, Button browse,
        Button action, string actionText, string hint)
    {
        pathBox.ReadOnly = true;
        pathBox.Location = new Point(16, 34);
        pathBox.Size = new Size(400, 26);

        browse.Text = "Browse...";
        browse.Location = new Point(424, 32);
        browse.Size = new Size(76, 30);

        action.Text = actionText;
        action.Location = new Point(508, 32);
        action.Size = new Size(68, 30);

        var hintLabel = new Label { Text = hint, AutoSize = true, Location = new Point(16, 70) };

        var group = new GroupBox { Text = title, Location = new Point(24, top), Size = new Size(592, 100) };
        group.Controls.Add(pathBox);
        group.Controls.Add(browse);
        group.Controls.Add(action);
        group.Controls.Add(hintLabel);
        return group;
    }

    // ---------- helpers ----------

    private void ShowStatus(string message, bool isError)
    {
        _statusLabel.ForeColor = isError ? Color.Firebrick : Color.SeaGreen;
        _statusLabel.Text = message;
    }

    /// <summary>Locks the buttons and shows the progress bar while an operation runs.</summary>
    private void SetBusy(bool busy)
    {
        _busy = busy;
        foreach (Button button in new[] { _encryptBrowseButton, _encryptButton, _decryptBrowseButton, _decryptButton, _logoutButton })
        {
            button.Enabled = !busy;
        }
        _progressBar.Visible = busy;
        _cancelButton.Visible = busy;
    }

    private void Browse(TextBox target, string title, string? filter)
    {
        using var dialog = new OpenFileDialog { Title = title, CheckFileExists = true };
        if (filter is not null)
        {
            dialog.Filter = filter;
        }

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            target.Text = dialog.FileName;
            ShowStatus(string.Empty, isError: false);
        }
    }

    /// <summary>
    /// Runs one encrypt or decrypt operation with a progress reporter and a
    /// cancellation token, and turns every kind of failure into a readable message.
    /// </summary>
    private async Task RunOperationAsync(Func<IProgress<string>, CancellationToken, Task<string>> operation)
    {
        SetBusy(true);
        _cts = new CancellationTokenSource();

        // Progress<T> delivers its messages slightly late. Without this flag, a late
        // "Unlocking..." message could overwrite the final success or error message.
        bool finished = false;
        var progress = new Progress<string>(message =>
        {
            if (!finished)
            {
                ShowStatus(message, isError: false);
            }
        });

        try
        {
            string doneMessage = await operation(progress, _cts.Token);
            ShowStatus(doneMessage, isError: false);
        }
        catch (OperationCanceledException)
        {
            ShowStatus("Cancelled. No output file was kept.", isError: true);
        }
        catch (WrongKeyException)
        {
            ShowStatus("This file was encrypted by a different account. Only that account can decrypt it.", isError: true);
        }
        catch (CorruptedFileException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (KeyNotFoundException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (UnauthorizedAccessException)
        {
            ShowStatus("Windows denied access to that file or folder.", isError: true);
        }
        catch (IOException ex)
        {
            ShowStatus("File problem: " + ex.Message, isError: true);
        }
        catch (InvalidOperationException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (ArgumentException ex)
        {
            ShowStatus(ex.Message, isError: true);
        }
        catch (Exception ex)
        {
            ShowStatus("Unexpected error: " + ex.Message, isError: true);
        }
        finally
        {
            finished = true; // from now on, ignore any progress message still on its way
            _cts?.Dispose();
            _cts = null;
            SetBusy(false);
        }
    }

    // ---------- event handlers ----------

    private async void EncryptButton_Click(object? sender, EventArgs e)
    {
        string input = _encryptPathBox.Text;
        if (string.IsNullOrWhiteSpace(input))
        {
            ShowStatus("Choose a file to encrypt first.", isError: true);
            return;
        }

        string output = input + ".enc";
        if (File.Exists(output))
        {
            DialogResult answer = MessageBox.Show(this,
                $"{Path.GetFileName(output)} already exists. Replace it?",
                "Replace existing file?", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (answer != DialogResult.Yes)
            {
                return;
            }
        }

        await RunOperationAsync(async (progress, token) =>
        {
            EncryptionResult result =
                await _encryption.EncryptFileAsync(input, _session.MasterKey, output, progress, token);

            // The file is already encrypted, so record its key even if the user cancels now.
            await Task.Run(() => _keys.Add(result, Path.GetFileName(input), _session.Username));
            return $"Encrypted: {output}";
        });
    }

    private async void DecryptButton_Click(object? sender, EventArgs e)
    {
        string input = _decryptPathBox.Text;
        if (string.IsNullOrWhiteSpace(input))
        {
            ShowStatus("Choose an encrypted file first.", isError: true);
            return;
        }

        // Ask where to save the result. The dialog warns before replacing an existing file.
        using var dialog = new SaveFileDialog
        {
            Title = "Save the decrypted file as",
            FileName = Path.GetFileNameWithoutExtension(input)
        };
        string? folder = Path.GetDirectoryName(input);
        if (folder is not null)
        {
            dialog.InitialDirectory = folder;
        }
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }
        string output = dialog.FileName;

        await RunOperationAsync(async (progress, token) =>
        {
            Guid fileId = _encryption.ReadFileId(input); // fails if this is not one of our files
            if (!_keys.TryGetWrappedKey(fileId, out WrappedKey? wrapped))
            {
                throw new KeyNotFoundException("No key was found for this file. It was not encrypted with this installation.");
            }

            await _encryption.DecryptFileAsync(input, output, wrapped, _session.MasterKey, progress, token);
            return $"Decrypted: {output}";
        });
    }

    /// <summary>
    /// Overrides the base class behaviour: the window refuses to close while an
    /// operation is running, so the user cannot lose work by accident.
    /// </summary>
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (_busy)
        {
            e.Cancel = true;
            ShowStatus("An operation is still running. Cancel it or wait for it to finish.", isError: true);
            return;
        }
        base.OnFormClosing(e);
    }
}
