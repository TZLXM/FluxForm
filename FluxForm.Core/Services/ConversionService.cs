using FluxForm.Core.Converters;
using FluxForm.Core.Dependencies;
using FluxForm.Core.Models;

namespace FluxForm.Core.Services;

public class ConversionService : IConversionService
{
    private readonly ConverterRegistry _registry;

    public ConversionService(IDependencyManager dependencyManager)
    {
        _registry = new ConverterRegistry();
        var videoFormats = new[] { "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg" };
        var audioFormats = new[] { "mp3", "aac", "flac", "wav", "ogg", "m4a", "wma", "opus" };
        var imageFormats = new[] { "jpg", "jpeg", "png", "webp", "bmp", "gif", "tiff", "tif" };

        _registry.Register(new FFmpegConverter(dependencyManager, ConversionCategory.Video, videoFormats));
        _registry.Register(new FFmpegConverter(dependencyManager, ConversionCategory.Audio, audioFormats));
        _registry.Register(new FFmpegConverter(dependencyManager, ConversionCategory.Image, imageFormats));
        _registry.Register(new LibreOfficeConverter(dependencyManager));
    }

    public async Task<ConversionResult> ConvertAsync(ConversionTask task, IProgress<ProgressInfo>? progress = null, CancellationToken cancellationToken = default)
    {
        var converter = _registry.FindConverter(task.InputFormat, task.OutputFormat);
        if (converter == null)
            return ConversionResult.Failure(task.Id, $"不支持的转换：{task.InputFormat} -> {task.OutputFormat}", TimeSpan.Zero);

        task.Category = converter.Category;
        var actualProgress = progress ?? new Progress<ProgressInfo>(_ => { });
        return await converter.ConvertAsync(task, actualProgress, cancellationToken);
    }

    public IReadOnlyList<FormatInfo> GetFormats(ConversionCategory? category = null)
    {
        return _registry.GetSupportedFormats(category);
    }
}
