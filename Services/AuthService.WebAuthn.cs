using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.JSInterop;
using TWR.MyFamilyAuth.Contracts.DTOs.Auth;
using TWR.MyFamilyAuth.Contracts.DTOs.WebAuthn;
using TWR.Shared.Auth.Models;

namespace TWR.Shared.Auth.Services;

/// <summary>
/// WebAuthn (passkey) ceremonies — the only auth methods that call MyFamilyAuth directly
/// (<see cref="_mfaHttp"/>) instead of going through this app's own API proxy. See
/// AuthServiceOptions.MyFamilyAuthPublicBaseUrl for why.
/// </summary>
public partial class AuthService
{
    public async Task<AuthResult> LoginWithPasskeyAsync(string email)
    {
        LastError = null;
        try
        {
            var optionsResponse = await _mfaHttp.PostAsJsonAsync("api/auth/webauthn/login-options",
                new WebAuthnLoginOptionsRequest(email, _options.AppClientId));

            if (!optionsResponse.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(optionsResponse);
                return AuthResult.Failure(LastError);
            }

            var options = await optionsResponse.Content.ReadFromJsonAsync<WebAuthnLoginOptionsResponse>();
            if (options is null) return AuthResult.Failure("Empty response from server.");

            string assertionJson;
            try
            {
                assertionJson = await _js.InvokeAsync<string>("twrAuth.getAssertion", options.OptionsJson);
            }
            catch (Exception ex)
            {
                // User cancelled the browser prompt, or no matching authenticator — not a server error.
                LastError = ex.Message;
                return AuthResult.Failure(LastError);
            }

            var completeResponse = await _mfaHttp.PostAsJsonAsync("api/auth/webauthn/login-complete",
                new WebAuthnLoginCompleteRequest(options.ChallengeToken, assertionJson, RememberMe: true));

            if (!completeResponse.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(completeResponse);
                return AuthResult.Failure(LastError);
            }

            var result = await completeResponse.Content.ReadFromJsonAsync<LoginResponse>();
            if (result is null) return AuthResult.Failure("Empty response from server.");

            await CompleteLoginAsync(result);
            return AuthResult.Succeeded(result.MustChangePassword);
        }
        catch (Exception ex) { LastError = ex.Message; return AuthResult.Failure(LastError); }
    }

    public async Task<bool> RegisterPasskeyAsync(string? deviceLabel = null)
    {
        LastError = null;
        try
        {
            var optionsResponse = await SendAuthenticatedAsync(HttpMethod.Post, "api/auth/webauthn/register-options");
            if (!optionsResponse.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(optionsResponse);
                return false;
            }

            var options = await optionsResponse.Content.ReadFromJsonAsync<RegisterOptionsResponse>();
            if (options is null) return false;

            string attestationJson;
            try
            {
                attestationJson = await _js.InvokeAsync<string>("twrAuth.createCredential", options.OptionsJson);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                return false;
            }

            var completeResponse = await SendAuthenticatedAsync(HttpMethod.Post, "api/auth/webauthn/register-complete",
                new RegisterCompleteRequest(options.ChallengeToken, attestationJson, deviceLabel));

            if (!completeResponse.IsSuccessStatusCode)
            {
                LastError = await ReadErrorAsync(completeResponse);
                return false;
            }

            return true;
        }
        catch (Exception ex) { LastError = ex.Message; return false; }
    }

    // register-options/register-complete are [Authorize] on MyFamilyAuth's side — _mfaHttp has no
    // RefreshTokenHandler attaching a token automatically (unlike _http), so it's attached here.
    private async Task<HttpResponseMessage> SendAuthenticatedAsync(HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _store.AccessToken);
        return await _mfaHttp.SendAsync(request);
    }
}
