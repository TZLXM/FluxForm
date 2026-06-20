namespace FluxForm.Core.Dependencies;

public class DependencyConfig
{
    public string Name { get; set; } = string.Empty;
    public string WindowsUrl { get; set; } = string.Empty;
    public string RelativeExecutablePath { get; set; } = string.Empty;
    public string? ArchiveType { get; set; }
    public string? Checksum { get; set; }
}
