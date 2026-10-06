using FileEncryptionDashboard.Data;
using FileEncryptionDashboard.Models;
using FileEncryptionDashboard.Services;
using Xunit;

namespace FileEncryptionDashboard.Tests;

/// <summary>
/// A fake repository that keeps users in memory. Because AuthService depends on
/// the IUserRepository interface, it can be tested with no database at all.
/// </summary>
public class FakeUserRepository : IUserRepository
{
    private readonly Dictionary<string, UserAccount> _users = new(StringComparer.OrdinalIgnoreCase);

    public long Add(UserAccount user)
    {
        long id = _users.Count + 1;
        _users[user.Username] = user with { Id = id };
        return id;
    }

    public UserAccount? FindByUsername(string username) =>
        _users.TryGetValue(username, out UserAccount? user) ? user : null;

    public int Count() => _users.Count;
}

public class AuthServiceTests
{
    private readonly FakeUserRepository _repo = new();
    private readonly AuthService _auth;

    public AuthServiceTests() => _auth = new AuthService(_repo);

    [Fact]
    public void IsFirstRun_TrueUntilAnAccountExists()
    {
        Assert.True(_auth.IsFirstRun);
        _auth.Register("admin", "correct-horse", Role.Admin);
        Assert.False(_auth.IsFirstRun);
    }

    [Fact]
    public void Register_ThenLogin_ReturnsSessionWithCorrectRole()
    {
        _auth.Register("alice", "correct-horse", Role.Admin);

        using UserSession session = _auth.Login("alice", "correct-horse");

        Assert.Equal("alice", session.Username);
        Assert.Equal(Role.Admin, session.Role);
        Assert.True(session.IsAdmin);
    }

    [Fact]
    public void Login_UsernameIsNotCaseSensitive()
    {
        _auth.Register("Alice", "correct-horse", Role.GeneralUser);
        using UserSession session = _auth.Login("ALICE", "correct-horse");
        Assert.False(session.IsAdmin);
    }

    [Fact]
    public void Login_WrongPassword_Throws()
    {
        _auth.Register("alice", "correct-horse", Role.GeneralUser);
        Assert.Throws<InvalidLoginException>(() => _auth.Login("alice", "wrong-password"));
    }

    [Fact]
    public void Login_UnknownUser_ThrowsSameException()
    {
        Assert.Throws<InvalidLoginException>(() => _auth.Login("nobody", "correct-horse"));
    }

    [Fact]
    public void Login_EmptyPassword_Throws()
    {
        _auth.Register("alice", "correct-horse", Role.GeneralUser);
        Assert.Throws<InvalidLoginException>(() => _auth.Login("alice", ""));
    }

    [Fact]
    public void Register_DuplicateUsername_Throws()
    {
        _auth.Register("alice", "correct-horse", Role.GeneralUser);
        Assert.Throws<RegistrationException>(() => _auth.Register("ALICE", "another-password", Role.GeneralUser));
    }

    [Fact]
    public void Register_ShortPassword_Throws()
    {
        Assert.Throws<RegistrationException>(() => _auth.Register("alice", "short", Role.GeneralUser));
    }

    [Theory]
    [InlineData("")]
    [InlineData("ab")]
    [InlineData("has space")]
    [InlineData("bad;name")]
    [InlineData("this_name_is_far_too_long")]
    public void Register_InvalidUsername_Throws(string username)
    {
        Assert.Throws<RegistrationException>(() => _auth.Register(username, "correct-horse", Role.GeneralUser));
    }

    [Fact]
    public void StoredAccount_DoesNotContainThePassword()
    {
        UserAccount account = _auth.Register("alice", "correct-horse", Role.GeneralUser);

        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes("correct-horse");
        Assert.NotEqual(passwordBytes, account.AuthHash);
        Assert.NotEqual(account.AuthSalt, account.KeySalt);
        Assert.True(account.Id > 0);
    }

    [Fact]
    public void SamePassword_TwoUsers_GetDifferentHashes()
    {
        UserAccount a = _auth.Register("alice", "correct-horse", Role.GeneralUser);
        UserAccount b = _auth.Register("bob", "correct-horse", Role.GeneralUser);
        Assert.NotEqual(a.AuthHash, b.AuthHash);
    }

    [Fact]
    public void Login_SamePasswordTwice_GivesSameMasterKey()
    {
        _auth.Register("alice", "correct-horse", Role.GeneralUser);

        using UserSession first = _auth.Login("alice", "correct-horse");
        using UserSession second = _auth.Login("alice", "correct-horse");

        Assert.Equal(first.MasterKey, second.MasterKey);
    }

    [Fact]
    public void UserSession_AfterDispose_RefusesToGiveTheKey()
    {
        _auth.Register("alice", "correct-horse", Role.GeneralUser);
        UserSession session = _auth.Login("alice", "correct-horse");

        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() => { _ = session.MasterKey; });
    }

    [Fact]
    public void EndToEnd_KeyWrappedInOneSession_CanBeUnwrappedInTheNext()
    {
        var encryption = new EncryptionService();
        byte[] fileKey = EncryptionService.GenerateRandomBytes(32);
        _auth.Register("alice", "correct-horse", Role.GeneralUser);

        WrappedKey wrapped;
        using (UserSession first = _auth.Login("alice", "correct-horse"))
        {
            wrapped = encryption.WrapKey(fileKey, first.MasterKey);
        }

        using UserSession second = _auth.Login("alice", "correct-horse");
        Assert.Equal(fileKey, encryption.UnwrapKey(wrapped, second.MasterKey));
    }

    [Fact]
    public void EndToEnd_AnotherUser_CannotUnwrapTheKey()
    {
        var encryption = new EncryptionService();
        byte[] fileKey = EncryptionService.GenerateRandomBytes(32);
        _auth.Register("alice", "correct-horse", Role.GeneralUser);
        _auth.Register("bob", "battery-staple", Role.GeneralUser);

        using UserSession alice = _auth.Login("alice", "correct-horse");
        using UserSession bob = _auth.Login("bob", "battery-staple");
        WrappedKey wrapped = encryption.WrapKey(fileKey, alice.MasterKey);

        Assert.Throws<WrongKeyException>(() => encryption.UnwrapKey(wrapped, bob.MasterKey));
    }
}