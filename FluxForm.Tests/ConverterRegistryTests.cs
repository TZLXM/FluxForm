using FluxForm.Core.Converters;
using FluxForm.Core.Dependencies;
using FluxForm.Core.Models;
using FluxForm.Core.Services;

namespace FluxForm.Tests;

public class ConverterRegistryTests
{
    [Fact]
    public void ConversionService_Should_Find_Video_Converter()
    {
        var dep = new DependencyManager(Path.Combine(Path.GetTempPath(), "fluxform-test-tools"));
        var service = new ConversionService(dep);

        var converter = ((dynamic)service).GetType()
            .GetField("_registry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(service);

        Assert.NotNull(converter);
    }

    [Fact]
    public void FFmpegConverter_Should_Report_CanConvert_For_Video()
    {
        var dep = new DependencyManager(Path.Combine(Path.GetTempPath(), "fluxform-test-tools"));
        var converter = new FFmpegConverter(dep, ConversionCategory.Video, new[] { "mp4", "mkv", "avi" });

        Assert.True(converter.CanConvert("mp4", "mkv"));
        Assert.False(converter.CanConvert("mp4", "mp3"));
    }

    [Fact]
    public void ConversionService_Should_Return_Formats()
    {
        var dep = new DependencyManager(Path.Combine(Path.GetTempPath(), "fluxform-test-tools"));
        var service = new ConversionService(dep);

        var formats = service.GetFormats();
        Assert.NotEmpty(formats);
        Assert.Contains(formats, f => f.Category == ConversionCategory.Video && f.Extension == "mp4");
        Assert.Contains(formats, f => f.Category == ConversionCategory.Audio && f.Extension == "mp3");
    }
}
