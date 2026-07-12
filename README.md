# TWR.Shared.Auth

Shared MyFamilyAuth login experience for the TWR MyApps suite. One package supplies:

- `IAuthService` / `AuthService` — login, 2FA, refresh, logout, forgot/reset/change password, passkeys.
- `LoginForm.razor`, `ForgotPasswordForm.razor` — drop-in login/reset UI (no outer card — each app supplies its own branding).
- `PasskeyManager.razor` — list/register/revoke passkeys (WebAuthn), wording configurable via `Term`.
- `twr-auth.js` — the browser-side WebAuthn ceremony (uses `PublicKeyCredential.parseCreationOptionsFromJSON`/`parseRequestOptionsFromJSON`, no hand-rolled base64url conversion).

**Why this exists:** every app used to hand-build its own login page, and they drifted (some had 2FA, some didn't; only one had Forgot Password; none had passkeys until this package). The goal is consistent behavior, consistent look and feel, and near-zero code in each consuming app.

---

## Two different backends — read this before wiring anything up

Almost everything (login, 2FA, refresh, forgot/reset/change password) goes through **the consuming app's own API as a server-to-server proxy** to MyFamilyAuth.API. This is same-origin from the browser's perspective — no CORS needed — and it means MyFamilyAuth's client secret never has to reach the browser.

**Passkeys (WebAuthn) are the one exception.** WebAuthn's whole security model keys off the browser's real `Origin` header to resolve which app/RP a credential belongs to — a server-to-server proxy call has no meaningful Origin header, so it would always be rejected. Passkey calls go **directly from the browser to MyFamilyAuth.API**, cross-origin, relying on MyFamilyAuth's own CORS allowlist plus a second origin check against that app's `RegisteredApp.AllowedOrigins`.

Practical consequence: `AuthService` needs **two `HttpClient`s** — the app's own API (proxy path) and a second one pointed at MyFamilyAuth's public base URL (passkeys only). `AddTwrSharedAuth` sets both up; you just supply both base URLs.

---

## Prerequisites before you start

1. **The app must already have its own working MyFamilyAuth V2 JWT validation on the server side** — i.e. its API validates tokens issued by MyFamilyAuth (`ValidIssuer`/`ValidAudience`/shared signing key), the way `TWR.MyFinances.API`/`TWR.MyMessages.API` do today. If the app currently issues its own separate JWT (like MyMedical does), that's a bigger migration — see "Apps with their own existing auth" below.
2. **The app must be registered in MyFamilyAuth** as a `RegisteredApp` (`ClientId`, `AllowedOrigins` containing every real origin — dev and prod — the app will be reached from). Use the Admin UI in MyFamilyAuth.Web (Apps admin page) — don't hand-edit seed code or the database directly.
3. **A shared JWT signing secret** between the app's API and MyFamilyAuth (same convention as MyFinances/MyMessages/TheFamilyInfo today) so the app's API can validate tokens MyFamilyAuth issued.

---

## Step-by-step: wiring a new Blazor WASM app

### 1. Add the package reference

```xml
<PackageReference Include="TWR.Shared.Auth" Version="1.2.2" />
```
(Check the latest published version in GitHub Packages before pinning.)

### 2. Server-side: add a thin auth-proxy controller to the app's own API

Copy the pattern from `TWR.MyFinances.API/Controllers/AuthController.cs` or `TWR.MyMessages.API/Controllers/AuthController.cs`. It's a `[ApiController]` with `login`, `verify-2fa`, `refresh`, `forgot-password`, `reset-password`, `change-password` actions, each forwarding to `{MyFamilyAuthBaseUrl}/api/auth/...` via a named `HttpClient("MyFamilyAuth")`, and a private `ProxyAsync` helper that copies status code + body back. `change-password` forwards the caller's `Authorization` header (`forwardBearer: true`); the others don't need it.

Register the named client in `Program.cs`:
```csharp
builder.Services.AddHttpClient("MyFamilyAuth", c => c.BaseAddress = new Uri(mfaSettings.BaseUrl));
```

### 3. Client-side: wire `Program.cs`

```csharp
using TWR.Shared.Auth.Services;

var apiBaseUrl = builder.Configuration["ApiSettings:BaseUrl"] ?? builder.HostEnvironment.BaseAddress;
var mfaBaseUrl = (builder.Configuration["MyFamilyAuthSettings:BaseUrl"] ?? "http://localhost:5100").TrimEnd('/') + "/";

builder.Services.AddTwrSharedAuth(
    appClientId: "yourappclientid",     // must match the RegisteredApp's ClientId in MyFamilyAuth
    appApiBaseUrl: apiBaseUrl,          // the app's own API (proxy path)
    myFamilyAuthPublicBaseUrl: mfaBaseUrl); // MyFamilyAuth.API's public URL (passkeys only)

var host = builder.Build();

// Restores a session from a stored refresh token before the app renders. Must run after
// builder.Build(), before host.RunAsync().
await host.Services.InitializeTwrSharedAuthAsync();

await host.RunAsync();
```

`AddTwrSharedAuth` registers everything: `AuthTokenStore`, a plain `HttpClient` pointed at the app's own API (with `RefreshTokenHandler` wired in — every other service that injects a bare `HttpClient` gets this same refresh-aware one for free), `AppApiHttpClient`/`MyFamilyAuthHttpClient` wrapper types, `AuthService`, and the `AuthenticationStateProvider`/`IAuthService` registrations `[Authorize]`/`AuthorizeRouteView` need.

### 4. `appsettings*.json` — add `MyFamilyAuthSettings:BaseUrl`

Add to each environment's config (Development, Docker, Production, etc. — see any existing app's `wwwroot/appsettings.*.json` for the exact per-environment values already in use):
```json
{
  "ApiSettings": { "BaseUrl": "https://localhost:XXXX" },
  "MyFamilyAuthSettings": { "BaseUrl": "http://localhost:5100" }
}
```

### 5. `_Imports.razor` — add the shared usings

```razor
@using TWR.Shared.Auth.Components
@using TWR.Shared.Auth.Services
@using TWR.Shared.Auth.Models
```

### 6. `wwwroot/index.html` — add the WebAuthn script

```html
<script src="_content/TWR.Shared.Auth/twr-auth.js"></script>
```

### 7. Login page

```razor
@page "/login"
@layout LoginLayout
@attribute [AllowAnonymous]

<div class="your-branded-login-card">
    <!-- your logo/heading -->
    <LoginForm AppDisplayName="Your App Name" />
</div>
```
`LoginForm` handles email/password, an in-component 2FA step (no separate `/login/verify-2fa` route needed), Remember Me, a "Forgot password?" link, and a "Use a passkey instead" option (auto-detected once an email is typed, if the browser supports `PublicKeyCredential`).

### 8. Forgot-password page (separate route, per-app)

```razor
@page "/forgot-password"
@layout LoginLayout
@attribute [AllowAnonymous]

<div class="your-branded-login-card">
    <ForgotPasswordForm BackToLoginUrl="/login" />
</div>
```

### 9. Settings/Profile page — passkeys

```razor
<PasskeyManager />
```
Or, for a mobile app where "fingerprint" is the term users recognize:
```razor
<PasskeyManager Term="Fingerprint" />
```
That's the whole passkey UI — list with device labels + created/last-used dates, revoke button, register-new with a device-name field. No other wiring needed; it calls `IAuthService.GetPasskeysAsync`/`RegisterPasskeyAsync`/`DeletePasskeyAsync` under the hood.

### 10. Change-password (if the app has its own Settings/Profile page for it)

```csharp
var error = await AuthService.ChangePasswordAsync(userId, currentPassword, newPassword);
// null on success, error message string on failure
```

---

## Apps with their own existing auth (e.g. MyMedical, TheFamilyInfo)

If the app currently issues its **own** JWT (self-signed, own `AuthUser` table, own login endpoint) rather than validating MyFamilyAuth's, adopting this package is a bigger job than steps 1–10 above. You need, roughly, in this order:

1. **Dual-auth on the server**: keep the existing scheme working (`AddAuthentication().AddJwtBearer("Legacy", ...)`) and add a second scheme validating MyFamilyAuth-issued tokens (`.AddJwtBearer("MyFamilyAuth", ...)`), per the Config Switch Pattern documented in the suite root `CLAUDE.md`.
2. **Identity alignment**: the app's local user table's primary key must adopt MyFamilyAuth's `UserId` verbatim, not auto-generate its own (mismatched keys have caused real bugs elsewhere in this suite). This usually means a migration mapping existing local users to their MyFamilyAuth `UserId`.
3. **Register the app** in MyFamilyAuth as a `RegisteredApp` if it isn't already, with real `AllowedOrigins`.
4. **Add the proxy controller** (step 2 above) to forward login/2FA/refresh/etc. to MyFamilyAuth.
5. **Once V2 auth is live and stable**, follow steps 1, 3–10 above to swap the client-side login/Settings UI over to this package, retiring the app's hand-built login page.
6. **Retire the legacy scheme** once nothing depends on it.

This is materially more work than a fresh integration — budget for it as its own project phase, not a drop-in.

---

## Testing

`TWR.Shared.Auth.Tests` uses a fake `HttpMessageHandler` to unit-test `AuthService`'s request/response mapping and state transitions without a real server. If you add new methods to `IAuthService`, add matching tests there following the existing pattern in `AuthServiceTests.cs`.

## Publishing

This repo auto-publishes to GitHub Packages on every push to `master` (version-diff check in `.github/workflows/publish-package.yml`) — bump `<Version>` in `TWR.Shared.Auth.csproj` before merging, or nothing new gets published. It depends on `TWR.MyFamilyAuth.Contracts`, which publishes on its own **tag-triggered** workflow (`contracts-vX.Y.Z` tag) in the `TWR.MyFamilyAuth` repo — if you bump the Contracts dependency version here, make sure that tag's been pushed and published *first*, or this repo's own restore will fail.
