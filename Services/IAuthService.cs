using TWR.Shared.Auth.Models;

namespace TWR.Shared.Auth.Services;

public interface IAuthService
{
    AuthUiState State { get; }

    /// <summary>Restores a session from a stored refresh token. Call once at startup.</summary>
    Task InitializeAsync();

    Task<AuthResult> LoginAsync(string email, string password, bool rememberMe = false);
    Task<AuthResult> VerifyTwoFactorAsync(string challengeToken, string otpCode, bool trustDevice);

    /// <summary>Runs the full WebAuthn assertion ceremony (options -> browser prompt -> complete) and logs in on success.</summary>
    Task<AuthResult> LoginWithPasskeyAsync(string email);

    /// <summary>Registers a new passkey for the currently authenticated user. For an already-signed-in Settings page, not the login flow.</summary>
    Task<bool> RegisterPasskeyAsync(string? deviceLabel = null);

    /// <summary>Silently exchanges the stored refresh token for a new access token. Used by RefreshTokenHandler on a 401.</summary>
    Task<bool> TryRefreshAsync();

    Task LogoutAsync();

    Task<bool> ForgotPasswordAsync(string email);
    Task<bool> ResetPasswordAsync(string code, string newPassword);

    /// <summary>For an already-signed-in Settings/Profile page. Returns null on success, or an error message.</summary>
    Task<string?> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);

    string? GetToken();

    /// <summary>Human-readable reason the most recent call failed. Null after a successful call.</summary>
    string? LastError { get; }
}
