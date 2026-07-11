namespace TWR.Shared.Auth.Services;

/// <summary>
/// Singleton shared between <see cref="AuthService"/> and <see cref="RefreshTokenHandler"/>.
/// AuthService writes tokens and wires the callbacks on login; RefreshTokenHandler reads the
/// token on every request and invokes TryRefreshAsync when a 401 is received. The callbacks are
/// wired after the host is built (see each app's Program.cs) to break what would otherwise be a
/// circular dependency: RefreshTokenHandler wraps the HttpClient that AuthService itself needs.
/// </summary>
public class AuthTokenStore
{
    public string? AccessToken  { get; set; }
    public string? RefreshToken { get; set; }

    public Func<Task<bool>>? TryRefreshAsync { get; set; }
    public Func<Task>?       LogoutAsync     { get; set; }
}
