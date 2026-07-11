using System.Security.Claims;
using System.Text.Json;

namespace TWR.Shared.Auth.Services;

/// <summary>
/// Decodes the claims out of a JWT payload — the single source of truth for a signed-in
/// user's identity in every adopting app, rather than trusting a login response body's own
/// UserId/FullName/Email/Role fields (which can only ever restate what the token already
/// says, and could drift out of sync with it). Every app in the suite that issues its own
/// JWT (self-issued or otherwise) is expected to mint "sub"/"email"/"given_name"/"family_name"
/// claims matching MyFamilyAuth's own convention — this is the one mapping every client needs.
/// </summary>
public static class JwtClaimsParser
{
    public static List<Claim> Parse(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2) return [];

        var bytes = Convert.FromBase64String(PadBase64Url(parts[1]));
        var doc   = JsonDocument.Parse(bytes);

        var claims = new List<Claim>();
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            var type = prop.Name switch
            {
                "sub"         => ClaimTypes.NameIdentifier,
                "email"       => ClaimTypes.Email,
                "given_name"  => ClaimTypes.GivenName,
                "family_name" => ClaimTypes.Surname,
                "name"        => ClaimTypes.Name,
                "role"        => ClaimTypes.Role,
                _             => prop.Name
            };

            if (prop.Value.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in prop.Value.EnumerateArray())
                    claims.Add(new Claim(type, item.ToString()));
            }
            else
            {
                var value = prop.Value.ValueKind == JsonValueKind.String ? prop.Value.GetString() ?? "" : prop.Value.ToString();
                claims.Add(new Claim(type, value));
            }
        }

        // Synthesise ClaimTypes.Name from given_name + family_name when the token has no
        // single "name" claim of its own (MyFamilyAuth's tokens split first/last; a self-issued
        // token like MyMessages' may carry either shape).
        if (!claims.Any(c => c.Type == ClaimTypes.Name))
        {
            var given  = claims.FirstOrDefault(c => c.Type == ClaimTypes.GivenName)?.Value ?? "";
            var family = claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value ?? "";
            var full   = $"{given} {family}".Trim();
            if (!string.IsNullOrEmpty(full))
                claims.Add(new Claim(ClaimTypes.Name, full));
        }

        return claims;
    }

    public static string? DisplayName(IReadOnlyCollection<Claim> claims)
        => claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;

    private static string PadBase64Url(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            _ => s
        };
    }
}
