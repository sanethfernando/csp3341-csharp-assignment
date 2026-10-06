using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using FileEncryptionDashboard.Models;
using Microsoft.Data.Sqlite;

namespace FileEncryptionDashboard.Data;

/// <summary>
/// Repository layer: stores wrapped file keys and the encryption log in SQLite.
/// Each method opens its own short-lived connection and disposes it with
/// <c>using</c>, because SQLite connections hold unmanaged resources.
/// </summary>
public sealed class KeyRepository : IKeyRepository
{
    private readonly string _connectionString;

    public KeyRepository(string connectionString) => _connectionString = connectionString;

    /// <inheritdoc />
    public long Add(EncryptionResult result, string fileName, string owner)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO EncryptedFiles
                (FileId, FileName, Owner, EncryptedAtUtc, KeyFingerprint, WrapNonce, WrapTag, WrappedKey)
            VALUES
                ($fileId, $fileName, $owner, $encryptedAt, $fingerprint, $nonce, $tag, $cipher)
            RETURNING Id;
            """;

        // Parameters (not string concatenation) prevent SQL injection.
        command.Parameters.AddWithValue("$fileId", result.FileId.ToString());
        command.Parameters.AddWithValue("$fileName", fileName);
        command.Parameters.AddWithValue("$owner", owner);
        command.Parameters.AddWithValue("$encryptedAt", DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$fingerprint", result.KeyFingerprint);
        command.Parameters.AddWithValue("$nonce", result.Wrapped.Nonce);
        command.Parameters.AddWithValue("$tag", result.Wrapped.Tag);
        command.Parameters.AddWithValue("$cipher", result.Wrapped.CipherKey);

        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <inheritdoc />
    public bool TryGetWrappedKey(Guid fileId, [NotNullWhen(true)] out WrappedKey? wrapped)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT WrapNonce, WrapTag, WrappedKey FROM EncryptedFiles WHERE FileId = $fileId;";
        command.Parameters.AddWithValue("$fileId", fileId.ToString());

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            wrapped = new WrappedKey(
                reader.GetFieldValue<byte[]>(0),
                reader.GetFieldValue<byte[]>(1),
                reader.GetFieldValue<byte[]>(2));
            return true;
        }

        wrapped = null;
        return false;
    }

    /// <inheritdoc />
    public IReadOnlyList<EncryptedFileRecord> GetAll()
    {
        var records = new List<EncryptedFileRecord>();

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, FileName, Owner, EncryptedAtUtc, KeyFingerprint
            FROM EncryptedFiles
            ORDER BY Id DESC;
            """;

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            records.Add(new EncryptedFileRecord(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetString(2),
                DateTime.Parse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                reader.GetString(4)));
        }
        return records;
    }
}
