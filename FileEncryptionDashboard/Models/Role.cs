namespace FileEncryptionDashboard.Models;

/// <summary>
/// The access levels in the application.
/// An enum is a user-defined data type with a fixed set of named values.
/// </summary>
public enum Role
{
    /// <summary>Can encrypt and decrypt files only.</summary>
    GeneralUser = 0,

    /// <summary>Can also view the encryption log.</summary>
    Admin = 1
}