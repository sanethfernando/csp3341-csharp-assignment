namespace FileEncryptionDashboard.Models;

/// <summary>
/// A registered user. The password itself is never stored: only a salted
/// PBKDF2 hash (<see cref="AuthHash"/>) used to check logins. A second,
/// separate salt (<see cref="KeySalt"/>) is used to derive the master key
/// that protects this user's file keys.
/// </summary>
/// <param name="Id">Database row id (0 before the user has been saved).</param>
/// <param name="Username">Unique login name (not case-sensitive).</param>
/// <param name="AuthSalt">Random salt for the login hash.</param>
/// <param name="AuthHash">PBKDF2 hash of the password.</param>
/// <param name="KeySalt">Random salt for deriving the master key.</param>
/// <param name="Role">Whether the user is a General User or an Admin.</param>
public record UserAccount(
    long Id,
    string Username,
    byte[] AuthSalt,
    byte[] AuthHash,
    byte[] KeySalt,
    Role Role);
