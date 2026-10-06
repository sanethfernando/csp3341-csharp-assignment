using FileEncryptionDashboard.Models;

namespace FileEncryptionDashboard.Data;

/// <summary>What the rest of the application may do with stored user accounts.</summary>
public interface IUserRepository
{
    /// <summary>Saves a new user and returns the new database id. Throws if the username already exists.</summary>
    long Add(UserAccount user);

    /// <summary>Finds a user by username (not case-sensitive), or returns null.</summary>
    UserAccount? FindByUsername(string username);

    /// <summary>Returns how many users exist (used to detect first run).</summary>
    int Count();
}
