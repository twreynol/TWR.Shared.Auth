using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using TWR.MyFamilyAuth.Contracts.DTOs.Auth;
using TWR.Shared.Auth.Models;

namespace TWR.Shared.Auth.Services;

/// <summary>
/// The one IAuthService implementation every adopting app registers as-is. Login/2FA/refresh/
/// forgot-password/reset-password go through the app's own API (a server-to-server proxy to
/// MyFamilyAuth) via <see cref="AppApiHttpClient"/>. WebAuthn calls (see the sibling
/// AuthService.WebAuthn.cs file) go directly to MyFamilyAuth via <see cref="MyFamilyAuthHttpClient"/>.
/// </summary>
public partial class AuthService : AuthenticationStateProvider, IAuthService
{
    private const string RefreshTokenKeySuffix = "_refresh_token";
    private const string DeviceTrustKeySuffix  = "_device_trust_token";

    private readonly HttpClient _http;
    private readonly HttpClient _mfaHttp;
    private readonly IJSRuntime _js;
    private readonly AuthTokenStore _store;
    private readonly AuthServiceOptions _options;
    private ClaimsPrincipal _currentUser = new(new ClaimsIdentity());
    private string? _pendingChallengeToken;

    public AuthService(AppApiHttpClient appApi, MyFamilyAuthHttpClient mfa, IJSRuntime js,
        AuthTokenStore store, AuthServiceOptions options)
    {
        _http    = appApi.Client;
        _mfaHttp = mfa.Client;
        _js      = js;
        _store   = store;
        _options = options;
    }

    private string RefreshTokenKey => _options.AppClientId + RefreshTokenKeySuffix;
    private string DeviceTrustKey  => _options.AppClientId + DeviceTrustKeySuffix;

    public AuthUiState State     { get; private set; } = AuthUiState.Empty;
    public string?     LastError { get; private set; }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
        => Task.FromResult(new AuthenticationState(_currentUser));

    /// <summary>
    /// Restores a session from a refresh token left in localStorage (e.g. after a page reload),
    /// by exchanging it for a fresh access token — never trusts a locally-cached access token itself.
    /// </summary>
    public async Task InitializeAsync()
    {
        string? storedRefreshToken;
        try
        {
            storedRefreshToken = await _js.InvokeAsync<string?>("localStorage.getItem", RefreshTokenKey);
        }
        catch { return; } // JS interop not ready (prerender) — nothing to restore yet.

        if (string.IsNullOrEmpty(storedRefreshToken))
            return;

        _store.RefreshToken = storedRefreshToken;
        if (!await TryRefreshAsync())
            await ClearStoredRefreshTokenAsync();
    }

    public async Task<AuthResult> LoginAsync(string email, string password, bool rememberMe = false)
    {
        LastError = null;
        _pendingChallengeToken = null;
        try
        {
            string? deviceTrustToken = null;
            try { deviceTrustToken = await _js.InvokeAsync<string?>("localStorage.getItem", DeviceTrustKey); }
            catch { /* prerender — no device trust to send yet */ }

            var response = await _http.PostAsJsonAsync("api/auth/login", new
            {
                email,
                password,
                appClientId = _options.AppClientId,
                rememberMe,
                deviceTrustToken
            });

            if (!response.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(response);
                return AuthResult.Failure(LastError);
            }

            var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
            if (result is null) return AuthResult.Failure("Empty response from server.");

            if (result.RequiresTwoFactor)
            {
                _pendingChallengeToken = result.TwoFactorChallengeToken;
                return AuthResult.NeedsTwoFactor(result.TwoFactorChallengeToken!);
            }

            await CompleteLoginAsync(result);
            return AuthResult.Succeeded(result.MustChangePassword);
        }
        catch (Exception ex) { LastError = ex.Message; return AuthResult.Failure(LastError); }
    }

    public async Task<AuthResult> VerifyTwoFactorAsync(string challengeToken, string otpCode, bool trustDevice)
    {
        LastError = null;
        try
        {
            var response = await _http.PostAsJsonAsync("api/auth/verify-2fa",
                new { challengeToken, otpCode, trustDevice });

            if (!response.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(response);
                return AuthResult.Failure(LastError);
            }

            var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
            if (result is null) return AuthResult.Failure("Empty response from server.");

            if (!string.IsNullOrEmpty(result.DeviceTrustToken))
            {
                try { await _js.InvokeVoidAsync("localStorage.setItem", DeviceTrustKey, result.DeviceTrustToken); }
                catch { /* best effort */ }
            }

            _pendingChallengeToken = null;
            await CompleteLoginAsync(result);
            return AuthResult.Succeeded(result.MustChangePassword);
        }
        catch (Exception ex) { LastError = ex.Message; return AuthResult.Failure(LastError); }
    }

    /// <summary>
    /// Silently exchanges the current refresh token for a new access/refresh pair.
    /// Called by RefreshTokenHandler on a 401, and by InitializeAsync on startup.
    /// </summary>
    public async Task<bool> TryRefreshAsync()
    {
        if (string.IsNullOrEmpty(_store.RefreshToken))
            return false;

        try
        {
            var response = await _http.PostAsJsonAsync("api/auth/refresh", new { refreshToken = _store.RefreshToken });
            if (!response.IsSuccessStatusCode)
                return false;

            var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
            if (result is null) return false;

            await CompleteLoginAsync(result);
            return true;
        }
        catch { return false; }
    }

    private async Task CompleteLoginAsync(LoginResponse result)
    {
        _store.AccessToken  = result.Token;
        _store.RefreshToken = result.RefreshToken;
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _store.AccessToken);

        if (!string.IsNullOrEmpty(result.RefreshToken))
        {
            try { await _js.InvokeVoidAsync("localStorage.setItem", RefreshTokenKey, result.RefreshToken); }
            catch { /* best effort — in-memory session still works this page load */ }
        }

        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, result.UserId.ToString()),
            new Claim(ClaimTypes.Name,           result.FullName),
            new Claim(ClaimTypes.Email,          result.Email),
            new Claim(ClaimTypes.Role,           result.Role)
        }, "jwt");

        _currentUser = new ClaimsPrincipal(identity);
        State = new AuthUiState(true, result.FullName, result.MustChangePassword);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task LogoutAsync()
    {
        if (!string.IsNullOrEmpty(_store.RefreshToken))
        {
            try { await _http.PostAsJsonAsync("api/auth/logout", new { refreshToken = _store.RefreshToken }); }
            catch { /* best effort */ }
        }
        _store.AccessToken  = null;
        _store.RefreshToken = null;
        _http.DefaultRequestHeaders.Authorization = null;
        _currentUser = new ClaimsPrincipal(new ClaimsIdentity());
        State = AuthUiState.Empty;
        await ClearStoredRefreshTokenAsync();
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    private async Task ClearStoredRefreshTokenAsync()
    {
        try { await _js.InvokeVoidAsync("localStorage.removeItem", RefreshTokenKey); }
        catch { /* best effort */ }
    }

    public string? GetToken() => _store.AccessToken;

    public async Task<bool> ForgotPasswordAsync(string email)
    {
        LastError = null;
        try
        {
            var response = await _http.PostAsJsonAsync("api/auth/forgot-password", new { email });
            if (!response.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(response);
                return false;
            }
            return true;
        }
        catch (Exception ex) { LastError = ex.Message; return false; }
    }

    public async Task<bool> ResetPasswordAsync(string code, string newPassword)
    {
        LastError = null;
        try
        {
            var response = await _http.PostAsJsonAsync("api/auth/reset-password", new { token = code, newPassword });
            if (!response.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(response);
                return false;
            }
            return true;
        }
        catch (Exception ex) { LastError = ex.Message; return false; }
    }

    private static async Task<string> ReadErrorAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        return string.IsNullOrWhiteSpace(body) ? $"HTTP {(int)response.StatusCode}" : body;
    }
}
