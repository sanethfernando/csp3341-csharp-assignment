namespace FileEncryptionDashboard.Services;

/// <summary>
/// Thrown when a file key cannot be unwrapped, for example when a user tries
/// to decrypt a file that belongs to someone else.
/// </summary>
public class WrongKeyException : Exception
{
    public WrongKeyException(string message) : base(message) { }
    public WrongKeyException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Thrown when a file is not a valid encrypted file or has been tampered with.
/// </summary>
public class CorruptedFileException : Exception
{
    public CorruptedFileException(string message) : base(message) { }
    public CorruptedFileException(string message, Exception inner) : base(message, inner) { }
}
