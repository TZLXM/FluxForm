using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public class FormatPreset
{
    public string Extension { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public ConversionCategory Category { get; set; }
}
