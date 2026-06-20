namespace FluxForm.Core.Dependencies;

public interface IDependencyManager
{
    string ToolsDirectory { get; }
    Task<string?> EnsureAvailableAsync(string dependencyName, CancellationToken cancellationToken = default);
    bool IsAvailable(string dependencyName);
    string? GetExecutablePath(string dependencyName);
}
