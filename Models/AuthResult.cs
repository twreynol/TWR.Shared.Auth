namespace TWR.Shared.Auth.Models;

public enum AuthOutcome { Success, RequiresTwoFactor, Failed }

public record AuthResult(
    AuthOutcome Outcome,
    string? ChallengeToken     = null,
    string? ErrorMessage       = null,
    bool    MustChangePassword = false)
{
    public static AuthResult Succeeded(bool mustChangePassword = false)
        => new(AuthOutcome.Success, MustChangePassword: mustChangePassword);

    public static AuthResult NeedsTwoFactor(string challengeToken)
        => new(AuthOutcome.RequiresTwoFactor, ChallengeToken: challengeToken);

    public static AuthResult Failure(string errorMessage)
        => new(AuthOutcome.Failed, ErrorMessage: errorMessage);
}
