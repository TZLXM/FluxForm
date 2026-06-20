using FluxForm.Core.Models;

namespace FluxForm.Core.Converters;

public interface IConverter
{
    ConversionCategory Category { get; }
    IReadOnlyCollection<string> SupportedInputFormats { get; }
    IReadOnlyCollection<string> SupportedOutputFormats { get; }
    bool CanConvert(string inputExtension, string outputExtension);
    Task<ConversionResult> ConvertAsync(ConversionTask task, IProgress<ProgressInfo> progress, CancellationToken cancellationToken = default);
}
