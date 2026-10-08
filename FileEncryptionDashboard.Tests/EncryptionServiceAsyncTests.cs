using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;
using Xunit;

namespace FileEncryptionDashboard.Tests;

/// <summary>
/// A progress reporter that records messages immediately. (The built-in
/// Progress&lt;T&gt; delivers messages asynchronously, which makes ordering hard to test.)
/// </summary>
public class ListProgress : IProgress<string>
{
    public List<string> Messages { get; } = new();
    public void Report(string value) => Messages.Add(value);
}

/// <summary>Tests for the asynchronous encrypt and decrypt methods.</summary>
public class EncryptionServiceAsyncTests : IDisposable
{
    private readonly EncryptionService _service = new();
    private readonly byte[] _masterKey = EncryptionService.GenerateRandomBytes(32);
    private readonly byte[] _sample = "Async hello!"u8.ToArray();
    private readonly string _tempDir;
    private readonly string _source;

    public EncryptionServiceAsyncTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "fed_async_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _source = Path.Combine(_tempDir, "note.txt");
        File.WriteAllBytes(_source, _sample);
    }

    public void Dispose() => Directory.Delete(_tempDir, recursive: true);

    [Fact]
    public async Task EncryptFileAsync_ThenDecryptFileAsync_RestoresContent()
    {
        EncryptionResult result = await _service.EncryptFileAsync(_source, _masterKey);
        string restored = Path.Combine(_tempDir, "restored.txt");

        await _service.DecryptFileAsync(_source + ".enc", restored, result.Wrapped, _masterKey);

        Assert.Equal(_sample, await File.ReadAllBytesAsync(restored));
    }

    [Fact]
    public async Task EncryptFileAsync_ReportsProgressInOrder()
    {
        var progress = new ListProgress();

        await _service.EncryptFileAsync(_source, _masterKey, progress: progress);

        Assert.Equal(
            new[] { "Reading file...", "Encrypting...", "Saving encrypted file..." },
            progress.Messages.ToArray());
    }

    [Fact]
    public async Task EncryptFileAsync_AlreadyCancelled_ThrowsAndLeavesNoOutput()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _service.EncryptFileAsync(_source, _masterKey, cancellationToken: cts.Token));

        Assert.False(File.Exists(_source + ".enc"));
        Assert.False(File.Exists(_source + ".enc.tmp"));
    }

    [Fact]
    public async Task DecryptFileAsync_WrongMasterKey_ThrowsAndLeavesNoOutput()
    {
        EncryptionResult result = await _service.EncryptFileAsync(_source, _masterKey);
        string output = Path.Combine(_tempDir, "out.txt");
        byte[] otherKey = EncryptionService.GenerateRandomBytes(32);

        await Assert.ThrowsAsync<WrongKeyException>(
            () => _service.DecryptFileAsync(_source + ".enc", output, result.Wrapped, otherKey));

        Assert.False(File.Exists(output));
    }

    [Fact]
    public async Task DecryptFileAsync_OutputSameAsInput_Throws()
    {
        EncryptionResult result = await _service.EncryptFileAsync(_source, _masterKey);
        string encrypted = _source + ".enc";

        await Assert.ThrowsAsync<ArgumentException>(
            () => _service.DecryptFileAsync(encrypted, encrypted, result.Wrapped, _masterKey));
    }

    [Fact]
    public async Task EncryptFileAsync_MissingFile_ThrowsFileNotFound()
    {
        string missing = Path.Combine(_tempDir, "missing.txt");
        await Assert.ThrowsAsync<FileNotFoundException>(
            () => _service.EncryptFileAsync(missing, _masterKey));
    }
}
