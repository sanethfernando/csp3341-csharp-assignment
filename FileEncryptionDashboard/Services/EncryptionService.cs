using System.Security.Cryptography;
using FileEncryptionDashboard.Models;

namespace FileEncryptionDashboard.Services;

/// <summary>
/// Service layer: all AES-256-GCM logic for the application.
/// Each file gets its own random key. That key is wrapped (encrypted) with the
/// user's master key before it is stored, and the master key is derived from
/// the user's password with PBKDF2.
///
/// Encrypted file layout:
///   "FED1" (4 bytes) | file id (16) | nonce (12) | tag (16) | ciphertext
/// The first 20 bytes (the header) are authenticated but not encrypted.
/// </summary>
public sealed class EncryptionService
{
    private const int KeySize = 32;            // 256-bit AES key
    private const int NonceSize = 12;          // standard GCM nonce size
    private const int TagSize = 16;            // 128-bit authentication tag
    private const int GuidSize = 16;
    private const int Pbkdf2Iterations = 600_000;

    private static readonly byte[] Magic = "FED1"u8.ToArray();
    private static readonly int HeaderSize = Magic.Length + GuidSize;

    /// <summary>Largest file accepted, because AES-GCM here works on the whole file in memory.</summary>
    public const long MaxFileSizeBytes = 100L * 1024 * 1024;

    // ---------- key helpers ----------

    /// <summary>Creates cryptographically secure random bytes (used for salts and keys).</summary>
    public static byte[] GenerateRandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    /// <summary>Derives a 256-bit key from a password and salt using PBKDF2-HMAC-SHA256.</summary>
    public static byte[] DeriveKey(string password, byte[] salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(salt);
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeySize);
    }

    /// <summary>Returns the first 16 hex characters of the key's SHA-256 hash; safe to show in the log.</summary>
    public static string Fingerprint(byte[] key) => Convert.ToHexString(SHA256.HashData(key))[..16];

    // ---------- key wrapping ----------

    /// <summary>Encrypts a file key with the user's master key so it can be stored safely.</summary>
    public WrappedKey WrapKey(byte[] fileKey, byte[] masterKey)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] cipher = new byte[fileKey.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(masterKey, TagSize);
        aes.Encrypt(nonce, fileKey, cipher, tag);
        return new WrappedKey(nonce, tag, cipher);
    }

    /// <summary>Recovers a file key. Fails with <see cref="WrongKeyException"/> if the master key is wrong.</summary>
    public byte[] UnwrapKey(WrappedKey wrapped, byte[] masterKey)
    {
        byte[] fileKey = new byte[wrapped.CipherKey.Length];
        try
        {
            using var aes = new AesGcm(masterKey, TagSize);
            aes.Decrypt(wrapped.Nonce, wrapped.CipherKey, wrapped.Tag, fileKey);
        }
        catch (CryptographicException ex)
        {
            throw new WrongKeyException("This file was not encrypted with your account's key.", ex);
        }
        return fileKey;
    }

    // ---------- byte-level encryption ----------

    /// <summary>Encrypts data and returns the full encrypted-file container.</summary>
    public byte[] EncryptBytes(byte[] plaintext, byte[] fileKey, Guid fileId)
    {
        byte[] container = new byte[HeaderSize + NonceSize + TagSize + plaintext.Length];
        Span<byte> span = container;

        Magic.CopyTo(container, 0);
        fileId.TryWriteBytes(span.Slice(Magic.Length, GuidSize));

        Span<byte> nonce = span.Slice(HeaderSize, NonceSize);
        Span<byte> tag = span.Slice(HeaderSize + NonceSize, TagSize);
        Span<byte> cipher = span[(HeaderSize + NonceSize + TagSize)..];
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(fileKey, TagSize);
        // The header is passed as associated data, so changing it breaks decryption.
        aes.Encrypt(nonce, plaintext, cipher, tag, span[..HeaderSize]);
        return container;
    }

    /// <summary>Decrypts an encrypted-file container with the file key.</summary>
    public byte[] DecryptBytes(byte[] container, byte[] fileKey)
    {
        ReadFileId(container); // validates the header

        ReadOnlySpan<byte> all = container;
        ReadOnlySpan<byte> header = all[..HeaderSize];
        ReadOnlySpan<byte> nonce = all.Slice(HeaderSize, NonceSize);
        ReadOnlySpan<byte> tag = all.Slice(HeaderSize + NonceSize, TagSize);
        ReadOnlySpan<byte> cipher = all[(HeaderSize + NonceSize + TagSize)..];
        byte[] plaintext = new byte[cipher.Length];

        try
        {
            using var aes = new AesGcm(fileKey, TagSize);
            aes.Decrypt(nonce, cipher, tag, plaintext, header);
        }
        catch (CryptographicException ex)
        {
            throw new CorruptedFileException("The file is damaged or has been modified.", ex);
        }
        return plaintext;
    }

    // ---------- file id (overloaded: bytes or path) ----------

    /// <summary>Reads the file id from an in-memory encrypted container.</summary>
    public Guid ReadFileId(byte[] container)
    {
        if (container.Length < HeaderSize + NonceSize + TagSize ||
            !container.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new CorruptedFileException("This is not a valid encrypted file.");
        }
        return new Guid(container.AsSpan(Magic.Length, GuidSize));
    }

    /// <summary>Reads the file id from an encrypted file on disk (reads only the header).</summary>
    public Guid ReadFileId(string path)
    {
        byte[] header = new byte[HeaderSize + NonceSize + TagSize];
        using FileStream stream = File.OpenRead(path);
        int read = stream.ReadAtLeast(header, header.Length, throwOnEndOfStream: false);
        if (read < header.Length)
        {
            throw new CorruptedFileException("This is not a valid encrypted file.");
        }
        return ReadFileId(header);
    }

    // ---------- file-level operations ----------

    /// <summary>
    /// Encrypts a file. The output file is written to <paramref name="outputPath"/>
    /// (default: the input path plus ".enc").
    /// </summary>
    public EncryptionResult EncryptFile(string inputPath, byte[] masterKey, string? outputPath = null)
    {
        var info = new FileInfo(inputPath);
        if (!info.Exists)
        {
            throw new FileNotFoundException("The file to encrypt was not found.", inputPath);
        }
        if (info.Length > MaxFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"File is larger than the {MaxFileSizeBytes / (1024 * 1024)} MB limit.");
        }

        outputPath ??= inputPath + ".enc";
        byte[] plaintext = File.ReadAllBytes(inputPath);
        byte[] fileKey = RandomNumberGenerator.GetBytes(KeySize);
        Guid fileId = Guid.NewGuid();

        try
        {
            File.WriteAllBytes(outputPath, EncryptBytes(plaintext, fileKey, fileId));
            return new EncryptionResult(fileId, WrapKey(fileKey, masterKey), Fingerprint(fileKey));
        }
        finally
        {
            // Wipe the plaintext key from memory whether or not encryption succeeded.
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>Decrypts an encrypted file using its stored wrapped key.</summary>
    public void DecryptFile(string inputPath, string outputPath, WrappedKey wrapped, byte[] masterKey)
    {
        byte[] container = File.ReadAllBytes(inputPath);
        byte[] fileKey = UnwrapKey(wrapped, masterKey);

        try
        {
            File.WriteAllBytes(outputPath, DecryptBytes(container, fileKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }
}
