using System.Security.Cryptography;

namespace FileEncryptionDashboard.Models;

/// <summary>
/// Represents a logged-in user. It holds the master key in memory only for
/// the length of the session; <see cref="Dispose"/> wipes it (called on logout).
/// This is an abstract data type: the key is a private field that can only be
/// read through a property that refuses to work after the session ends.
/// </summary>
public sealed class UserSession : IDisposable
{
    private byte[]? _masterKey;

    public UserSession(string username, Role role, byte[] masterKey)
    {
        Username = username;
        Role = role;
        _masterKey = masterKey;
    }

    /// <summary>The logged-in user's name.</summary>
    public string Username { get; }

    /// <summary>The logged-in user's access level.</summary>
    public Role Role { get; }

    /// <summary>True when the user is an Admin.</summary>
    public bool IsAdmin => Role == Role.Admin;

    /// <summary>The key that protects this user's file keys. Not available after logout.</summary>
    public byte[] MasterKey => _masterKey ?? throw new ObjectDisposedException(nameof(UserSession));

    /// <summary>Wipes the master key from memory.</summary>
    public void Dispose()
    {
        if (_masterKey is not null)
        {
            CryptographicOperations.ZeroMemory(_masterKey);
            _masterKey = null;
        }
    }
}
