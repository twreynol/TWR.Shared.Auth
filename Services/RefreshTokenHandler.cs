using System.Net;
using System.Net.Http.Headers;

namespace TWR.Shared.Auth.Services;

/// <summary>
/// DelegatingHandler that:
///   1. Attaches the current Bearer token to every non-auth request.
///   2. On 401, attempts a silent token refresh via AuthTokenStore.TryRefreshAsync.
///   3. On successful refresh, retries the original request once with the new token.
///   4. On failed refresh, calls AuthTokenStore.LogoutAsync to clear auth state.
///
/// Requests to /api/auth/* are passed through unchanged — they don't carry a token
/// and must never trigger a refresh attempt (would cause an infinite loop).
/// </summary>
public class RefreshTokenHandler(AuthTokenStore store) : DelegatingHandler
{
    private bool _isRefreshing;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri?.PathAndQuery.StartsWith("/api/auth/", StringComparison.OrdinalIgnoreCase) == true)
            return await base.SendAsync(request, cancellationToken);

        if (!string.IsNullOrEmpty(store.AccessToken))
            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", store.AccessToken);

        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized
            && !_isRefreshing
            && store.TryRefreshAsync is not null)
        {
            _isRefreshing = true;
            try
            {
                var refreshed = await store.TryRefreshAsync();
                if (refreshed && !string.IsNullOrEmpty(store.AccessToken))
                {
                    var retry = await CloneRequestAsync(request);
                    retry.Headers.Authorization =
                        new AuthenticationHeaderValue("Bearer", store.AccessToken);
                    response = await base.SendAsync(retry, cancellationToken);
                }
                else if (store.LogoutAsync is not null)
                {
                    await store.LogoutAsync();
                }
            }
            finally
            {
                _isRefreshing = false;
            }
        }

        return response;
    }

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage original)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri);

        foreach (var header in original.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        if (original.Content is not null)
        {
            var body = await original.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(body);
            foreach (var header in original.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }
}
