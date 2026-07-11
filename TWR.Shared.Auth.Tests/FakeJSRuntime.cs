using Microsoft.JSInterop;

namespace TWR.Shared.Auth.Tests;

/// <summary>No-op IJSRuntime — these tests exercise AuthService's HTTP/state logic, not localStorage.</summary>
public class FakeJSRuntime : IJSRuntime
{
    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
        => ValueTask.FromResult(default(TValue)!);

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        => ValueTask.FromResult(default(TValue)!);

    public ValueTask<TValue> InvokeConstructorAsync<TValue>(string identifier, object?[]? args) where TValue : IJSObjectReference
        => throw new NotSupportedException("Not used by these tests.");

    public ValueTask<TValue> InvokeConstructorAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args) where TValue : IJSObjectReference
        => throw new NotSupportedException("Not used by these tests.");

    public ValueTask<TValue> GetValueAsync<TValue>(string identifier)
        => ValueTask.FromResult(default(TValue)!);

    public ValueTask<TValue> GetValueAsync<TValue>(string identifier, CancellationToken cancellationToken)
        => ValueTask.FromResult(default(TValue)!);

    public ValueTask SetValueAsync<TValue>(string identifier, TValue value)
        => ValueTask.CompletedTask;

    public ValueTask SetValueAsync<TValue>(string identifier, TValue value, CancellationToken cancellationToken)
        => ValueTask.CompletedTask;
}
