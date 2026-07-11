namespace TWR.Shared.Auth.Models;

/// <summary>
/// Per-app configuration for <see cref="Services.AuthService"/>. Everything else
/// (HTTP calls, token storage, WebAuthn ceremony) is identical across apps.
/// </summary>
public sealed class AuthServiceOptions
{
    /// <summary>The MyFamilyAuth ClientId this app is registered under, e.g. "myfinances".</summary>
    public required string AppClientId { get; init; }

    /// <summary>
    /// MyFamilyAuth's own public base URL (e.g. https://myfamilyauth-api.fly.dev). Used ONLY for
    /// the WebAuthn endpoints, which must be called directly from the browser (cross-origin) rather
    /// than through this app's own API proxy — WebAuthn resolves the credential's RP from the real
    /// browser Origin header, which a server-to-server proxy call doesn't carry.
    /// </summary>
    public required string MyFamilyAuthPublicBaseUrl { get; init; }
}
