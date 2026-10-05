namespace FileEncryptionDashboard.Models;

/// <summary>
/// What the encryption service hands back after encrypting a file, so the
/// caller can record it in the database.
/// </summary>
/// <param name="FileId">Identifier stored in the encrypted file's header.</param>
/// <param name="Wrapped">The file key, protected by the user's master key.</param>
/// <param name="KeyFingerprint">Short SHA-256 fingerprint identifying the key (safe to display).</param>
public record EncryptionResult(Guid FileId, WrappedKey Wrapped, string KeyFingerprint);
