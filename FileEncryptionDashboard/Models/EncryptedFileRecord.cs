namespace FileEncryptionDashboard.Models;

/// <summary>
/// One row of the encryption log. A record gives immutability and
/// value-based equality from a single declaration.
/// </summary>
/// <param name="Id">Database row id.</param>
/// <param name="FileName">Name of the file that was encrypted.</param>
/// <param name="Owner">Username of the person who encrypted it.</param>
/// <param name="EncryptedAtUtc">When the file was encrypted (UTC).</param>
/// <param name="KeyFingerprint">Short SHA-256 fingerprint identifying the key; the key itself is never shown.</param>
public record EncryptedFileRecord(
    long Id,
    string FileName,
    string Owner,
    DateTime EncryptedAtUtc,
    string KeyFingerprint);