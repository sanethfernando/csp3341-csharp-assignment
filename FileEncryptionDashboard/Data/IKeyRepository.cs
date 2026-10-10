using System.Diagnostics.CodeAnalysis;
using FileEncryptionDashboard.Models;

namespace FileEncryptionDashboard.Data;

/// <summary>
/// What the rest of the application may do with stored file keys and the
/// encryption log. Depending on an interface (not the SQLite class) keeps
/// the service and GUI layers independent of the database.
/// </summary>
public interface IKeyRepository
{
    /// <summary>Raised after a new encryption record has been saved. Can be raised on a background thread.</summary>
    event EventHandler<LogEntryAddedEventArgs>? EntryAdded;

    /// <summary>Saves a new encryption record and returns its database id.</summary>
    long Add(EncryptionResult result, string fileName, string owner);

    /// <summary>Looks up the wrapped key for an encrypted file. Returns false if the file is unknown.</summary>
    bool TryGetWrappedKey(Guid fileId, [NotNullWhen(true)] out WrappedKey? wrapped);

    /// <summary>Returns the whole encryption log, newest first. Contains fingerprints, never keys.</summary>
    IReadOnlyList<EncryptedFileRecord> GetAll();
}
