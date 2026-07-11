using System.Net;
using System.Net.Http.Json;
using TWR.MyFamilyAuth.Contracts.DTOs.Auth;
using TWR.MyFamilyAuth.Contracts.DTOs.WebAuthn;
using TWR.Shared.Auth.Models;
using TWR.Shared.Auth.Services;

namespace TWR.Shared.Auth.Tests;

/// <summary>
/// Unit tests for AuthService's proxy-path logic (login/2FA/refresh/forgot-password/reset-password),
/// which every adopting app's own API forwards server-to-server to MyFamilyAuth. A fake
/// HttpMessageHandler stands in for that app API — no real server involved.
/// </summary>
public class AuthServiceTests
{
    private static readonly Guid UserId = Guid.NewGuid();

    private static LoginResponse SuccessResponse(bool mustChangePassword = false) => new(
        Token: "jwt-token", RefreshToken: "raw-refresh", ExpiresAt: DateTime.UtcNow.AddHours(1),
        UserId: UserId, FullName: "Jane Doe", Email: "jane@example.com", Role: "User",
        MustChangePassword: mustChangePassword);

    private static LoginResponse TwoFactorResponse() => new(
        Token: null, RefreshToken: null, ExpiresAt: DateTime.UtcNow,
        UserId: UserId, FullName: "Jane Doe", Email: "jane@example.com", Role: "User",
        MustChangePassword: false, RequiresTwoFactor: true, TwoFactorChallengeToken: "challenge-abc");

    private static (AuthService svc, FakeHttpMessageHandler handler, AuthTokenStore store) Build(
        Func<HttpRequestMessage, HttpResponseMessage>? responder = null)
    {
        var handler = new FakeHttpMessageHandler(responder ?? (_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(SuccessResponse()) }));

        var appApi = new AppApiHttpClient(new HttpClient(handler) { BaseAddress = new Uri("https://app.example/") });
        var mfa    = new MyFamilyAuthHttpClient(new HttpClient(handler) { BaseAddress = new Uri("https://mfa.example/") });
        var store  = new AuthTokenStore();
        var options = new AuthServiceOptions { AppClientId = "testapp", MyFamilyAuthPublicBaseUrl = "https://mfa.example/" };

        var svc = new AuthService(appApi, mfa, new FakeJSRuntime(), store, options);
        return (svc, handler, store);
    }

    [Fact]
    public async Task LoginAsync_Success_ReturnsSucceededAndUpdatesState()
    {
        var (svc, _, store) = Build();

        var result = await svc.LoginAsync("jane@example.com", "password", rememberMe: true);

        Assert.Equal(AuthOutcome.Success, result.Outcome);
        Assert.True(svc.State.IsAuthenticated);
        Assert.Equal("Jane Doe", svc.State.DisplayName);
        Assert.Equal("jwt-token", store.AccessToken);
        Assert.Equal("raw-refresh", store.RefreshToken);
    }

    [Fact]
    public async Task LoginAsync_PostsToAppsOwnApiNotMyFamilyAuthDirectly()
    {
        var (svc, handler, _) = Build();

        await svc.LoginAsync("jane@example.com", "password");

        var request = Assert.Single(handler.Requests);
        Assert.Equal("app.example", request.RequestUri!.Host);
        Assert.Equal("/api/auth/login", request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task LoginAsync_RequiresTwoFactor_ReturnsChallengeTokenWithoutSettingState()
    {
        var (svc, _, store) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(TwoFactorResponse()) });

        var result = await svc.LoginAsync("jane@example.com", "password");

        Assert.Equal(AuthOutcome.RequiresTwoFactor, result.Outcome);
        Assert.Equal("challenge-abc", result.ChallengeToken);
        Assert.False(svc.State.IsAuthenticated);
        Assert.Null(store.AccessToken);
    }

    [Fact]
    public async Task LoginAsync_HttpFailure_ReturnsFailureWithServerMessage()
    {
        var (svc, _, _) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("Invalid email or password.") });

        var result = await svc.LoginAsync("jane@example.com", "wrong-password");

        Assert.Equal(AuthOutcome.Failed, result.Outcome);
        Assert.Contains("Invalid email or password.", result.ErrorMessage);
    }

    [Fact]
    public async Task VerifyTwoFactorAsync_Success_CompletesLoginAndUpdatesState()
    {
        var (svc, handler, store) = Build();

        var result = await svc.VerifyTwoFactorAsync("challenge-abc", "123456", trustDevice: true);

        Assert.Equal(AuthOutcome.Success, result.Outcome);
        Assert.True(svc.State.IsAuthenticated);
        Assert.Equal("jwt-token", store.AccessToken);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("/api/auth/verify-2fa", request.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task VerifyTwoFactorAsync_Failure_ReturnsFailureAndDoesNotAuthenticate()
    {
        var (svc, _, _) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("Invalid or expired verification code.") });

        var result = await svc.VerifyTwoFactorAsync("challenge-abc", "000000", trustDevice: false);

        Assert.Equal(AuthOutcome.Failed, result.Outcome);
        Assert.False(svc.State.IsAuthenticated);
    }

    [Fact]
    public async Task TryRefreshAsync_NoStoredRefreshToken_ReturnsFalseWithoutCallingApi()
    {
        var (svc, handler, _) = Build();

        var refreshed = await svc.TryRefreshAsync();

        Assert.False(refreshed);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task TryRefreshAsync_Success_UpdatesStoredTokens()
    {
        var (svc, _, store) = Build();
        store.RefreshToken = "old-refresh";

        var refreshed = await svc.TryRefreshAsync();

        Assert.True(refreshed);
        Assert.Equal("jwt-token", store.AccessToken);
        Assert.Equal("raw-refresh", store.RefreshToken);
    }

    [Fact]
    public async Task TryRefreshAsync_HttpFailure_ReturnsFalse()
    {
        var (svc, _, store) = Build(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized));
        store.RefreshToken = "old-refresh";

        var refreshed = await svc.TryRefreshAsync();

        Assert.False(refreshed);
    }

    [Fact]
    public async Task LogoutAsync_ClearsTokensAndState()
    {
        var (svc, _, store) = Build();
        await svc.LoginAsync("jane@example.com", "password");

        await svc.LogoutAsync();

        Assert.Null(store.AccessToken);
        Assert.Null(store.RefreshToken);
        Assert.False(svc.State.IsAuthenticated);
    }

    [Fact]
    public async Task ForgotPasswordAsync_Success_ReturnsTrue()
    {
        var (svc, handler, _) = Build(_ => new HttpResponseMessage(HttpStatusCode.OK));

        var ok = await svc.ForgotPasswordAsync("jane@example.com");

        Assert.True(ok);
        Assert.Equal("/api/auth/forgot-password", handler.Requests[0].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ForgotPasswordAsync_Failure_SetsLastError()
    {
        var (svc, _, _) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("Failed to send reset code.") });

        var ok = await svc.ForgotPasswordAsync("jane@example.com");

        Assert.False(ok);
        Assert.Contains("Failed to send reset code.", svc.LastError);
    }

    [Fact]
    public async Task ResetPasswordAsync_Success_ReturnsTrue()
    {
        var (svc, handler, _) = Build(_ => new HttpResponseMessage(HttpStatusCode.OK));

        var ok = await svc.ResetPasswordAsync("123456", "NewP@ssw0rd!");

        Assert.True(ok);
        Assert.Equal("/api/auth/reset-password", handler.Requests[0].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ChangePasswordAsync_Success_ReturnsNull()
    {
        var (svc, handler, _) = Build(_ => new HttpResponseMessage(HttpStatusCode.OK));

        var error = await svc.ChangePasswordAsync(UserId, "OldP@ss1!", "NewP@ss1!");

        Assert.Null(error);
        Assert.Equal("/api/auth/change-password", handler.Requests[0].RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task ChangePasswordAsync_Failure_ReturnsErrorMessage()
    {
        var (svc, _, _) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("Current password is incorrect.") });

        var error = await svc.ChangePasswordAsync(UserId, "wrong-current", "NewP@ss1!");

        Assert.Contains("Current password is incorrect.", error);
    }

    [Fact]
    public async Task GetPasskeysAsync_Success_ReturnsListFromMyFamilyAuthDirectly()
    {
        var passkeys = new List<PasskeyDto> { new(Guid.NewGuid(), "My Laptop", DateTime.UtcNow, DateTime.UtcNow) };
        var (svc, handler, store) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(passkeys) });
        store.AccessToken = "token";

        var result = await svc.GetPasskeysAsync();

        Assert.NotNull(result);
        Assert.Single(result);
        Assert.Equal("My Laptop", result[0].DeviceLabel);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("mfa.example", request.RequestUri!.Host);
        Assert.Equal("/api/auth/webauthn/credentials", request.RequestUri!.AbsolutePath);
        Assert.Equal(HttpMethod.Get, request.Method);
    }

    [Fact]
    public async Task GetPasskeysAsync_Failure_ReturnsNullAndSetsLastError()
    {
        var (svc, _, store) = Build(_ =>
            new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("Unable to list passkeys.") });
        store.AccessToken = "token";

        var result = await svc.GetPasskeysAsync();

        Assert.Null(result);
        Assert.Contains("Unable to list passkeys.", svc.LastError);
    }

    [Fact]
    public async Task DeletePasskeyAsync_Success_ReturnsTrue()
    {
        var credId = Guid.NewGuid();
        var (svc, handler, store) = Build(_ => new HttpResponseMessage(HttpStatusCode.OK));
        store.AccessToken = "token";

        var ok = await svc.DeletePasskeyAsync(credId);

        Assert.True(ok);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"/api/auth/webauthn/credentials/{credId}", request.RequestUri!.AbsolutePath);
        Assert.Equal(HttpMethod.Delete, request.Method);
    }

    [Fact]
    public async Task DeletePasskeyAsync_Failure_ReturnsFalseAndSetsLastError()
    {
        var (svc, _, store) = Build(_ => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("Not found.") });
        store.AccessToken = "token";

        var ok = await svc.DeletePasskeyAsync(Guid.NewGuid());

        Assert.False(ok);
        Assert.Contains("Not found.", svc.LastError);
    }

    [Fact]
    public async Task GetToken_ReturnsCurrentlyStoredAccessToken()
    {
        var (svc, _, store) = Build();
        store.AccessToken = "some-token";

        Assert.Equal("some-token", svc.GetToken());
    }
}
