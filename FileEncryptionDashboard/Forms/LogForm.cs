using FileEncryptionDashboard.Data;
using FileEncryptionDashboard.Models;

namespace FileEncryptionDashboard.Forms;

/// <summary>
/// GUI layer: the Admin-only encryption log. It lists who encrypted which file
/// and when, with a key fingerprint (the keys themselves are never shown).
/// The window listens for the repository's EntryAdded event, so a new row
/// appears by itself when a file is encrypted while the log is open.
/// </summary>
public sealed class LogForm : Form
{
    private readonly IKeyRepository _keys;
    private readonly DataGridView _grid = new();
    private readonly Label _countLabel = new();
    private readonly Button _refreshButton = new();

    public LogForm(IKeyRepository keys)
    {
        _keys = keys;
        BuildLayout();
        RefreshLog();
        _keys.EntryAdded += Keys_EntryAdded; // subscribe to the event
    }

    private void BuildLayout()
    {
        Text = "Encryption log";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(720, 420);
        MinimumSize = new Size(560, 300);

        _countLabel.AutoSize = true;
        _countLabel.Location = new Point(16, 22);

        _refreshButton.Text = "Refresh";
        _refreshButton.Size = new Size(90, 30);
        _refreshButton.Location = new Point(614, 14);
        _refreshButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _refreshButton.Click += (sender, e) => RefreshLog();

        _grid.Location = new Point(16, 56);
        _grid.Size = new Size(688, 348);
        _grid.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        _grid.ReadOnly = true;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        _grid.Columns.Add("id", "ID");
        _grid.Columns.Add("file", "File");
        _grid.Columns.Add("owner", "Owner");
        _grid.Columns.Add("when", "Encrypted at");
        _grid.Columns.Add("fingerprint", "Key fingerprint");
        _grid.Columns[0].FillWeight = 20f; // the ID column can be narrow

        Controls.Add(_countLabel);
        Controls.Add(_refreshButton);
        Controls.Add(_grid);
    }

    /// <summary>Reloads every row from the database.</summary>
    private void RefreshLog()
    {
        IReadOnlyList<EncryptedFileRecord> records = _keys.GetAll();

        _grid.Rows.Clear();
        foreach (EncryptedFileRecord record in records)
        {
            _grid.Rows.Add(
                record.Id,
                record.FileName,
                record.Owner,
                record.EncryptedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                record.KeyFingerprint);
        }

        string entries = records.Count == 1 ? "1 entry" : $"{records.Count} entries";
        _countLabel.Text = $"{entries}. Keys are never shown here.";
    }

    /// <summary>
    /// Event handler. The event is raised on the background thread that saved the
    /// record, but only the UI thread may touch controls, so the work is handed over.
    /// </summary>
    private void Keys_EntryAdded(object? sender, LogEntryAddedEventArgs e)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        if (InvokeRequired)
        {
            BeginInvoke(new Action(RefreshLog));
        }
        else
        {
            RefreshLog();
        }
    }

    /// <summary>
    /// Unsubscribes when the window closes. If this were forgotten, the repository
    /// would keep a reference to the closed form and keep calling its handler.
    /// </summary>
    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _keys.EntryAdded -= Keys_EntryAdded;
        base.OnFormClosed(e);
    }
}
