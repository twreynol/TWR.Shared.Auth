namespace TWR.Shared.Auth.Models;

public record AuthUiState(bool IsAuthenticated, string? DisplayName, bool MustChangePassword)
{
    public static readonly AuthUiState Empty = new(false, null, false);
}
