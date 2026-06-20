namespace FluxForm.Core.Models;

public enum ConversionCategory
{
    Video,
    Audio,
    Image,
    Document
}

public class ConversionTask
{
    public Guid Id { get; } = Guid.NewGuid();
    public string InputPath { get; set; } = string.Empty;
    public string OutputPath { get; set; } = string.Empty;
    public string InputFormat { get; set; } = string.Empty;
    public string OutputFormat { get; set; } = string.Empty;
    public ConversionCategory Category { get; set; }
    public Dictionary<string, string> Options { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
