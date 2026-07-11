namespace TWR.Shared.Auth.Services;

/// <summary>
/// Thin wrapper so <see cref="AuthService"/> can take two distinct <see cref="HttpClient"/>s via
/// plain constructor injection (no named/keyed DI) — this one points at the app's own API, which
/// proxies login/2FA/refresh/forgot-password/reset-password to MyFamilyAuth server-to-server.
/// </summary>
public class AppApiHttpClient(HttpClient client)
{
    public HttpClient Client { get; } = client;
}
