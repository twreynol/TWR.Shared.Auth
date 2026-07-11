using Microsoft.Extensions.DependencyInjection;

namespace TWR.Shared.Auth.Services;

public static class AuthServiceProviderExtensions
{
    /// <summary>
    /// Call once on <c>host.Services</c> right after <c>builder.Build()</c> (before
    /// <c>host.RunAsync()</c>): wires AuthTokenStore's refresh/logout callbacks to the
    /// built AuthService instance (can't be done at registration time — RefreshTokenHandler
    /// needs the callbacks before AuthService itself can be constructed), then restores any
    /// session from a stored refresh token before the app renders.
    /// </summary>
    public static async Task InitializeTwrSharedAuthAsync(this IServiceProvider services)
    {
        var store = services.GetRequiredService<AuthTokenStore>();
        var auth  = services.GetRequiredService<AuthService>();

        store.TryRefreshAsync = () => auth.TryRefreshAsync();
        store.LogoutAsync     = () => auth.LogoutAsync();

        await auth.InitializeAsync();
    }
}
