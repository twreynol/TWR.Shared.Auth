namespace TWR.Shared.Auth.Services;

/// <summary>
/// Points directly at MyFamilyAuth's own public base URL, bypassing this app's API proxy —
/// used only for the WebAuthn endpoints, which need the browser's real Origin header to resolve
/// the correct RP (a server-to-server proxy call carries no meaningful Origin).
/// </summary>
public class MyFamilyAuthHttpClient(HttpClient client)
{
    public HttpClient Client { get; } = client;
}
