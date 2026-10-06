using System.Globalization;
using FileEncryptionDashboard.Models;
using Microsoft.Data.Sqlite;

namespace FileEncryptionDashboard.Data;

/// <summary>Repository layer: stores user accounts in SQLite.</summary>
public sealed class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString) => _connectionString = connectionString;

    /// <inheritdoc />
    public long Add(UserAccount user)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO Users (Username, AuthSalt, AuthHash, KeySalt, Role)
            VALUES ($username, $authSalt, $authHash, $keySalt, $role)
            RETURNING Id;
            """;
        command.Parameters.AddWithValue("$username", user.Username);
        command.Parameters.AddWithValue("$authSalt", user.AuthSalt);
        command.Parameters.AddWithValue("$authHash", user.AuthHash);
        command.Parameters.AddWithValue("$keySalt", user.KeySalt);
        command.Parameters.AddWithValue("$role", (int)user.Role);

        return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    /// <inheritdoc />
    public UserAccount? FindByUsername(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Username, AuthSalt, AuthHash, KeySalt, Role
            FROM Users
            WHERE Username = $username;
            """;
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        return new UserAccount(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetFieldValue<byte[]>(2),
            reader.GetFieldValue<byte[]>(3),
            reader.GetFieldValue<byte[]>(4),
            (Role)reader.GetInt32(5));
    }

    /// <inheritdoc />
    public int Count()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Users;";
        return Convert.ToInt32(command.ExecuteScalar(), CultureInfo.InvariantCulture);
    }
}
