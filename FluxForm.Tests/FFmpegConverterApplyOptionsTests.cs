using System.Reflection;
using FluxForm.Core.Converters;
using FluxForm.Core.Models;

namespace FluxForm.Tests;

public class FFmpegConverterApplyOptionsTests
{
    [Fact]
    public void ApplyOptions_adds_frame_rate_argument_when_frameRate_option_present()
    {
        var args = BuildArgs(new Dictionary<string, string> { ["frameRate"] = "30" });

        Assert.Contains("-r", args);
        var index = args.IndexOf("-r");
        Assert.Equal("30", args[index + 1]);
    }

    [Fact]
    public void ApplyOptions_adds_aspect_ratio_argument_when_aspectRatio_option_present()
    {
        var args = BuildArgs(new Dictionary<string, string> { ["aspectRatio"] = "16:9" });

        Assert.Contains("-aspect", args);
        var index = args.IndexOf("-aspect");
        Assert.Equal("16:9", args[index + 1]);
    }

    private static List<string> BuildArgs(Dictionary<string, string> options)
    {
        var task = new ConversionTask
        {
            Category = ConversionCategory.Video,
            InputPath = "input.mp4",
            OutputPath = "output.mp4",
            Options = new Dictionary<string, string>(options, StringComparer.OrdinalIgnoreCase)
        };

        var args = new List<string>();
        var method = typeof(FFmpegConverter).GetMethod("ApplyOptions", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        method.Invoke(null, new object[] { args, task });
        return args;
    }
}
