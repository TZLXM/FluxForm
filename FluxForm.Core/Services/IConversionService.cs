using FluxForm.Core.Models;

namespace FluxForm.Core.Services;

public interface IConversionService
{
    Task<ConversionResult> ConvertAsync(ConversionTask task, IProgress<ProgressInfo>? progress = null, CancellationToken cancellationToken = default);
    IReadOnlyList<FormatInfo> GetFormats(ConversionCategory? category = null);
}
