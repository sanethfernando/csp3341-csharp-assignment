using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;
using Xunit;

namespace FileEncryptionDashboard.Tests;

/// <summary>
/// Unit tests for EncryptionService. xUnit creates a fresh instance of this
/// class for every test, so each test gets its own keys and temp folder.
/// </summary>
public class EncryptionServiceTests : IDisposable
{
    private readonly EncryptionService _service = new();
    private readonly byte[] _masterKey = EncryptionService.GenerateRandomBytes(32);
    private readonly byte[] _fileKey = EncryptionService.GenerateRandomBytes(32);
    private readonly byte[] _sample = "Hello, secret world!"u8.ToArray();
    private readonly string _tempDir;

    public EncryptionServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "fed_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    /// <summary>Runs after each test to remove the temp folder.</summary>
    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

    // ---------- byte-level encryption ----------

    [Fact]
    public void EncryptBytes_ThenDecryptBytes_ReturnsOriginal()
    {
        byte[] container = _service.EncryptBytes(_sample, _fileKey, Guid.NewGuid());
        Assert.Equal(_sample, _service.DecryptBytes(container, _fileKey));
    }

    [Fact]
    public void EncryptBytes_EmptyInput_RoundTrips()
    {
        byte[] container = _service.EncryptBytes(Array.Empty<byte>(), _fileKey, Guid.NewGuid());
        Assert.Empty(_service.DecryptBytes(container, _fileKey));
    }

    [Fact]
    public void EncryptBytes_OutputDoesNotContainPlaintext()
    {
        byte[] container = _service.EncryptBytes(_sample, _fileKey, Guid.NewGuid());
        Assert.True(container.AsSpan().IndexOf(_sample) < 0);
    }

    [Fact]
    public void EncryptBytes_SameInputTwice_GivesDifferentOutput()
    {
        Guid id = Guid.NewGuid();
        byte[] first = _service.EncryptBytes(_sample, _fileKey, id);
        byte[] second = _service.EncryptBytes(_sample, _fileKey, id);
        Assert.NotEqual(first, second); // random nonce each time
    }

    [Fact]
    public void DecryptBytes_ModifiedCiphertext_ThrowsCorruptedFile()
    {
        byte[] container = _service.EncryptBytes(_sample, _fileKey, Guid.NewGuid());
        container[^1] ^= 1; // flip one bit in the last byte
        Assert.Throws<CorruptedFileException>(() => _service.DecryptBytes(container, _fileKey));
    }

    [Fact]
    public void DecryptBytes_ModifiedHeader_ThrowsCorruptedFile()
    {
        byte[] container = _service.EncryptBytes(_sample, _fileKey, Guid.NewGuid());
        container[5] ^= 1; // flip one bit inside the file id in the header
        Assert.Throws<CorruptedFileException>(() => _service.DecryptBytes(container, _fileKey));
    }

    [Fact]
    public void ReadFileId_NotAnEncryptedFile_ThrowsCorruptedFile()
    {
        Assert.Throws<CorruptedFileException>(() => _service.ReadFileId(new byte[100]));
    }

    // ---------- key handling ----------

    [Fact]
    public void WrapKey_ThenUnwrapKey_ReturnsOriginalKey()
    {
        WrappedKey wrapped = _service.WrapKey(_fileKey, _masterKey);
        Assert.Equal(_fileKey, _service.UnwrapKey(wrapped, _masterKey));
    }

    [Fact]
    public void UnwrapKey_WrongMasterKey_ThrowsWrongKey()
    {
        WrappedKey wrapped = _service.WrapKey(_fileKey, _masterKey);
        byte[] otherKey = EncryptionService.GenerateRandomBytes(32);
        Assert.Throws<WrongKeyException>(() => _service.UnwrapKey(wrapped, otherKey));
    }

    [Fact]
    public void Fingerprint_IsSixteenHexCharacters()
    {
        string fingerprint = EncryptionService.Fingerprint(_fileKey);
        Assert.Equal(16, fingerprint.Length);
        Assert.True(fingerprint.All(Uri.IsHexDigit));
    }

    [Fact]
    public void DeriveKey_SameInputsSameKey_DifferentPasswordDifferentKey()
    {
        byte[] salt = EncryptionService.GenerateRandomBytes(16);
        byte[] a = EncryptionService.DeriveKey("password-one", salt);
        byte[] b = EncryptionService.DeriveKey("password-one", salt);
        byte[] c = EncryptionService.DeriveKey("password-two", salt);
        Assert.Equal(a, b);
        Assert.NotEqual(a, c);
    }

    // ---------- file-level operations ----------

    [Fact]
    public void EncryptFile_ThenDecryptFile_RestoresContent()
    {
        string source = Path.Combine(_tempDir, "note.txt");
        File.WriteAllBytes(source, _sample);

        EncryptionResult result = _service.EncryptFile(source, _masterKey);
        string encrypted = source + ".enc";
        string restored = Path.Combine(_tempDir, "restored.txt");
        _service.DecryptFile(encrypted, restored, result.Wrapped, _masterKey);

        Assert.Equal(_sample, File.ReadAllBytes(restored));
        Assert.Equal(result.FileId, _service.ReadFileId(encrypted));
    }

    [Fact]
    public void DecryptFile_WrongMasterKey_ThrowsWrongKey()
    {
        string source = Path.Combine(_tempDir, "note.txt");
        File.WriteAllBytes(source, _sample);
        EncryptionResult result = _service.EncryptFile(source, _masterKey);

        byte[] otherKey = EncryptionService.GenerateRandomBytes(32);
        Assert.Throws<WrongKeyException>(() =>
            _service.DecryptFile(source + ".enc", Path.Combine(_tempDir, "out.txt"), result.Wrapped, otherKey));
    }

    [Fact]
    public void EncryptFile_MissingFile_ThrowsFileNotFound()
    {
        string missing = Path.Combine(_tempDir, "does-not-exist.txt");
        Assert.Throws<FileNotFoundException>(() => _service.EncryptFile(missing, _masterKey));
    }
}
