namespace FileEncryptionDashboard.Services;

/// <summary>
/// Thrown when a login fails. The message is deliberately the same for an
/// unknown user and a wrong password, so attackers cannot tell which usernames exist.
/// </summary>
public class InvalidLoginException : Exception
{
    public InvalidLoginException() : base("Incorrect username or password.") { }
}

/// <summary>Thrown when a new account cannot be created (bad username, weak password, name taken).</summary>
public class RegistrationException : Exception
{
    public RegistrationException(string message) : base(message) { }
}
