namespace FileEncryptionDashboard.Models;

/// <summary>
/// Information sent along with the KeyRepository.EntryAdded event: the log
/// entry that was just saved. Deriving from EventArgs is the standard .NET pattern.
/// </summary>
public class LogEntryAddedEventArgs : EventArgs
{
    public LogEntryAddedEventArgs(EncryptedFileRecord entry) => Entry = entry;

    /// <summary>The new log entry (fingerprint only, never the key itself).</summary>
    public EncryptedFileRecord Entry { get; }
}
