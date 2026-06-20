namespace FluxForm.Core.Models;

public class FormatInfo
{
    public string Extension { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public ConversionCategory Category { get; set; }
    public string[] CommonExtensions { get; set; } = Array.Empty<string>();
}
