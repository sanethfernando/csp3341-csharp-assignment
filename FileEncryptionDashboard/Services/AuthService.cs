using System.Security.Cryptography;
using FileEncryptionDashboard.Data;
using FileEncryptionDashboard.Models;

namespace FileEncryptionDashboard.Services;

/// <summary>
/// Service layer: registration and login.
/// Passwords are never stored. At registration two random salts are created:
/// one is used to hash the password for login checks, the other to derive the
/// master key that protects the user's file keys. Using different salts means
/// the login hash cannot be turned into the master key.
/// </summary>
public sealed class AuthService
{
    private const int SaltSize = 16;
    private const int MinPasswordLength = 8;

    // Used to spend the same time on "unknown user" as on a real login attempt.
    private static readonly byte[] DummySalt = RandomNumberGenerator.GetBytes(SaltSize);

    private readonly IUserRepository _users;

    public AuthService(IUserRepository users) => _users = users;

    /// <summary>True when no accounts exist yet (the first account created becomes the Admin).</summary>
    public bool IsFirstRun => _users.Count() == 0;

    /// <summary>Creates a new account and returns it (with its database id filled in).</summary>
    public UserAccount Register(string username, string password, Role role)
    {
        ValidateUsername(username);
        ValidatePassword(password);

        if (_users.FindByUsername(username) is not null)
        {
            throw new RegistrationException("That username is already taken.");
        }

        byte[] authSalt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] keySalt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] authHash = EncryptionService.DeriveKey(password, authSalt);

        var account = new UserAccount(0, username, authSalt, authHash, keySalt, role);
        long id = _users.Add(account);
        return account with { Id = id }; // 'with' copies the record, changing only Id
    }

    /// <summary>
    /// Checks the credentials and, if correct, returns a session holding the
    /// user's master key. Throws <see cref="InvalidLoginException"/> otherwise.
    /// </summary>
    public UserSession Login(string username, string password)
    {
        UserAccount? account = string.IsNullOrWhiteSpace(username)
            ? null
            : _users.FindByUsername(username.Trim());

        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidLoginException();
        }

        if (account is null)
        {
            EncryptionService.DeriveKey(password, DummySalt); // keep timing similar to a real attempt
            throw new InvalidLoginException();
        }

        byte[] attempt = EncryptionService.DeriveKey(password, account.AuthSalt);
        if (!CryptographicOperations.FixedTimeEquals(attempt, account.AuthHash))
        {
            throw new InvalidLoginException();
        }

        byte[] masterKey = EncryptionService.DeriveKey(password, account.KeySalt);
        return new UserSession(account.Username, account.Role, masterKey);
    }

    private static void ValidateUsername(string username)
    {
        bool valid = !string.IsNullOrEmpty(username)
            && username.Length is >= 3 and <= 20
            && username.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

        if (!valid)
        {
            throw new RegistrationException("Username must be 3-20 characters: letters, digits or underscore.");
        }
    }

    private static void ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
        {
            throw new RegistrationException($"Password must be at least {MinPasswordLength} characters.");
        }
    }
}
