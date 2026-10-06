using Microsoft.Data.Sqlite;

namespace FileEncryptionDashboard.Data;

/// <summary>
/// Repository layer helper: knows where the database file lives and creates
/// its tables. Every other class in this layer receives a connection string.
/// </summary>
public static class Database
{
    /// <summary>Default database location: the current user's local application data folder.</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "FileEncryptionDashboard",
        "app.db");

    /// <summary>Builds a SQLite connection string for the given file, creating its folder if needed.</summary>
    public static string BuildConnectionString(string path)
    {
        string? folder = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(folder))
        {
            Directory.CreateDirectory(folder);
        }
        return new SqliteConnectionStringBuilder { DataSource = path }.ToString();
    }

    /// <summary>Creates the tables if they do not exist yet. Safe to call every time the app starts.</summary>
    public static void Initialize(string connectionString)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                Id          INTEGER PRIMARY KEY AUTOINCREMENT,
                Username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                AuthSalt    BLOB    NOT NULL,
                AuthHash    BLOB    NOT NULL,
                KeySalt     BLOB    NOT NULL,
                Role        INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS EncryptedFiles (
                Id             INTEGER PRIMARY KEY AUTOINCREMENT,
                FileId         TEXT NOT NULL UNIQUE,
                FileName       TEXT NOT NULL,
                Owner          TEXT NOT NULL,
                EncryptedAtUtc TEXT NOT NULL,
                KeyFingerprint TEXT NOT NULL,
                WrapNonce      BLOB NOT NULL,
                WrapTag        BLOB NOT NULL,
                WrappedKey     BLOB NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }
}
