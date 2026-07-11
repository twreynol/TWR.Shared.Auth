using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace TWR.Shared.Auth.Services;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the entire shared auth subsystem — token store, both HttpClients (this app's own
    /// API proxy, plus a direct-to-MyFamilyAuth client for WebAuthn), AuthService, and the
    /// AuthenticationStateProvider/IAuthService wiring <c>[Authorize]</c>/<c>AuthorizeRouteView</c>
    /// need. This is everything a consuming app's Program.cs previously hand-wrote itself.
    ///
    /// Call <see cref="AuthServiceProviderExtensions.InitializeTwrSharedAuthAsync"/> on
    /// <c>host.Services</c> after <c>builder.Build()</c> to finish wiring (session restore).
    /// </summary>
    public static IServiceCollection AddTwrSharedAuth(
        this IServiceCollection services, string appClientId, string appApiBaseUrl, string myFamilyAuthPublicBaseUrl)
    {
        services.AddSingleton<AuthTokenStore>();

        services.AddSingleton(new Models.AuthServiceOptions
        {
            AppClientId               = appClientId,
            MyFamilyAuthPublicBaseUrl = myFamilyAuthPublicBaseUrl
        });

        // Registered as a plain HttpClient too (not just wrapped in AppApiHttpClient) — every other
        // service in the app (BuildInfoService, domain services, etc.) already injects a bare
        // HttpClient expecting exactly this one: the app's own API, refresh-token-aware.
        services.AddScoped(sp =>
        {
            var store   = sp.GetRequiredService<AuthTokenStore>();
            var handler = new RefreshTokenHandler(store) { InnerHandler = new HttpClientHandler() };
            return new HttpClient(handler) { BaseAddress = new Uri(appApiBaseUrl) };
        });
        services.AddScoped(sp => new AppApiHttpClient(sp.GetRequiredService<HttpClient>()));

        services.AddScoped(_ =>
            new MyFamilyAuthHttpClient(new HttpClient { BaseAddress = new Uri(myFamilyAuthPublicBaseUrl) }));

        services.AddAuthorizationCore();
        services.AddCascadingAuthenticationState();
        services.AddScoped<AuthService>();
        services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<AuthService>());
        services.AddScoped<IAuthService>(sp => sp.GetRequiredService<AuthService>());

        return services;
    }
}
