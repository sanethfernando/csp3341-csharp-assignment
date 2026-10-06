using FileEncryptionDashboard.Data;
using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;
using Microsoft.Data.Sqlite;
using Xunit;

namespace FileEncryptionDashboard.Tests;

/// <summary>
/// Tests for the repository layer. Each test gets its own temporary database
/// file, which is deleted afterwards.
/// </summary>
public class RepositoryTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _connectionString;
    private readonly KeyRepository _keys;
    private readonly UserRepository _users;
    private readonly EncryptionService _service = new();

    public RepositoryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "fed_db_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _connectionString = Database.BuildConnectionString(Path.Combine(_tempDir, "test.db"));
        Database.Initialize(_connectionString);
        _keys = new KeyRepository(_connectionString);
        _users = new UserRepository(_connectionString);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools(); // release the pooled file handle so the file can be deleted
        Directory.Delete(_tempDir, recursive: true);
    }

    private static UserAccount NewUser(string name, Role role = Role.GeneralUser) =>
        new(0, name,
            EncryptionService.GenerateRandomBytes(16),
            EncryptionService.GenerateRandomBytes(32),
            EncryptionService.GenerateRandomBytes(16),
            role);

    private EncryptionResult NewEncryptionResult()
    {
        byte[] fileKey = EncryptionService.GenerateRandomBytes(32);
        byte[] masterKey = EncryptionService.GenerateRandomBytes(32);
        return new EncryptionResult(Guid.NewGuid(), _service.WrapKey(fileKey, masterKey), EncryptionService.Fingerprint(fileKey));
    }

    // ---------- Database ----------

    [Fact]
    public void Initialize_CalledTwice_DoesNotThrow()
    {
        Database.Initialize(_connectionString);
        Database.Initialize(_connectionString);
    }

    // ---------- KeyRepository ----------

    [Fact]
    public void KeyRepository_AddThenTryGet_ReturnsSameWrappedKey()
    {
        EncryptionResult result = NewEncryptionResult();
        long id = _keys.Add(result, "report.docx", "alice");

        Assert.True(id > 0);
        bool found = _keys.TryGetWrappedKey(result.FileId, out WrappedKey? stored);
        Assert.True(found);

        // IsType fails the test if 'stored' is null, and gives us a non-null variable to use.
        WrappedKey storedKey = Assert.IsType<WrappedKey>(stored);
        Assert.Equal(result.Wrapped.Nonce, storedKey.Nonce);
        Assert.Equal(result.Wrapped.Tag, storedKey.Tag);
        Assert.Equal(result.Wrapped.CipherKey, storedKey.CipherKey);
    }

    [Fact]
    public void KeyRepository_TryGet_UnknownFile_ReturnsFalse()
    {
        Assert.False(_keys.TryGetWrappedKey(Guid.NewGuid(), out WrappedKey? stored));
        Assert.Null(stored);
    }

    [Fact]
    public void KeyRepository_GetAll_ReturnsNewestFirstWithFingerprints()
    {
        EncryptionResult first = NewEncryptionResult();
        EncryptionResult second = NewEncryptionResult();
        _keys.Add(first, "first.txt", "alice");
        _keys.Add(second, "second.txt", "bob");

        IReadOnlyList<EncryptedFileRecord> log = _keys.GetAll();

        Assert.Equal(2, log.Count);
        Assert.Equal("second.txt", log[0].FileName);
        Assert.Equal("bob", log[0].Owner);
        Assert.Equal(second.KeyFingerprint, log[0].KeyFingerprint);
        Assert.Equal("first.txt", log[1].FileName);
        Assert.Equal(DateTimeKind.Utc, log[0].EncryptedAtUtc.Kind);
    }

    // ---------- UserRepository ----------

    [Fact]
    public void UserRepository_AddThenFind_ReturnsUser()
    {
        UserAccount user = NewUser("Alice", Role.Admin);
        long id = _users.Add(user);

        UserAccount found = Assert.IsType<UserAccount>(_users.FindByUsername("Alice"));

        Assert.Equal(id, found.Id);
        Assert.Equal(Role.Admin, found.Role);
        Assert.Equal(user.AuthHash, found.AuthHash);
        Assert.Equal(user.KeySalt, found.KeySalt);
    }

    [Fact]
    public void UserRepository_Find_IsNotCaseSensitive()
    {
        _users.Add(NewUser("Alice"));
        Assert.NotNull(_users.FindByUsername("ALICE"));
    }

    [Fact]
    public void UserRepository_Find_UnknownUser_ReturnsNull()
    {
        Assert.Null(_users.FindByUsername("nobody"));
    }

    [Fact]
    public void UserRepository_AddDuplicateUsername_Throws()
    {
        _users.Add(NewUser("alice"));
        Assert.Throws<SqliteException>(() => _users.Add(NewUser("ALICE")));
    }

    [Fact]
    public void UserRepository_Count_ReflectsNumberOfUsers()
    {
        Assert.Equal(0, _users.Count());
        _users.Add(NewUser("alice"));
        _users.Add(NewUser("bob"));
        Assert.Equal(2, _users.Count());
    }
}
