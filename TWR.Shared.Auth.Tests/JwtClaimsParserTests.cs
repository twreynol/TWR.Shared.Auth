using System.Security.Claims;
using System.Text;
using System.Text.Json;
using TWR.Shared.Auth.Services;

namespace TWR.Shared.Auth.Tests;

public class JwtClaimsParserTests
{
    private static string FakeJwt(object payload)
    {
        var json = JsonSerializer.Serialize(payload);
        var b64  = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return $"header.{b64}.signature";
    }

    [Fact]
    public void Parse_MyFamilyAuthShapedToken_MapsGivenNameAndFamilyNameAndSynthesizesFullName()
    {
        var jwt = FakeJwt(new { sub = "11111111-1111-1111-1111-111111111111", email = "jane@example.com", given_name = "Jane", family_name = "Doe", role = "User" });

        var claims = JwtClaimsParser.Parse(jwt);

        Assert.Equal("11111111-1111-1111-1111-111111111111", claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value);
        Assert.Equal("jane@example.com", claims.First(c => c.Type == ClaimTypes.Email).Value);
        Assert.Equal("Jane", claims.First(c => c.Type == ClaimTypes.GivenName).Value);
        Assert.Equal("Doe", claims.First(c => c.Type == ClaimTypes.Surname).Value);
        Assert.Equal("User", claims.First(c => c.Type == ClaimTypes.Role).Value);
        Assert.Equal("Jane Doe", JwtClaimsParser.DisplayName(claims));
    }

    [Fact]
    public void Parse_SelfIssuedTokenShapedLikeMyMessages_MapsPlainNameClaimDirectly()
    {
        var jwt = FakeJwt(new { sub = "22222222-2222-2222-2222-222222222222", name = "Jeff Reger", role = "User" });

        var claims = JwtClaimsParser.Parse(jwt);

        Assert.Equal("Jeff Reger", JwtClaimsParser.DisplayName(claims));
    }

    [Fact]
    public void Parse_MalformedToken_ReturnsEmptyRatherThanThrowing()
    {
        var claims = JwtClaimsParser.Parse("not-a-jwt");

        Assert.Empty(claims);
    }
}
