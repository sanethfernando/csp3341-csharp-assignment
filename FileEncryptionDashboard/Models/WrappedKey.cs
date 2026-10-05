namespace FileEncryptionDashboard.Models;

/// <summary>
/// A per-file AES key that has itself been encrypted ("wrapped") with the
/// user's master key. This is what gets stored in the database, so the
/// database alone is never enough to decrypt a file.
/// </summary>
/// <param name="Nonce">Unique 12-byte value used for the wrapping operation.</param>
/// <param name="Tag">16-byte authentication tag proving the wrapped key was not altered.</param>
/// <param name="CipherKey">The encrypted file key.</param>
public record WrappedKey(byte[] Nonce, byte[] Tag, byte[] CipherKey);
