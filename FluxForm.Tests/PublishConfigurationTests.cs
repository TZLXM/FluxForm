using System.IO;
using System.Reflection;

namespace FluxForm.Tests;

public class PublishConfigurationTests
{
    [Fact]
    public void FFmpeg_publish_target_is_cache_aware_and_does_not_download_by_default()
    {
        var targets = File.ReadAllText(GetProjectFile("build", "FFmpeg.targets"));

        Assert.Contains("<BundleFFmpeg Condition=\"'$(BundleFFmpeg)' == '' and Exists('$(FFmpegCachePath)')\">true</BundleFFmpeg>", targets);
        Assert.Contains("<BundleFFmpeg Condition=\"'$(BundleFFmpeg)' == ''\">false</BundleFFmpeg>", targets);
        Assert.Contains("<DownloadFFmpegDuringPublish Condition=\"'$(DownloadFFmpegDuringPublish)' == ''\">false</DownloadFFmpegDuringPublish>", targets);
        Assert.Contains("BundleFfmpegForPublish.ps1", targets);
        Assert.DoesNotContain("<DownloadFile", targets);
        Assert.DoesNotContain("<Unzip", targets);
    }

    [Theory]
    [InlineData("publish-cli.ps1")]
    [InlineData("publish-wpf.ps1")]
    public void Publish_scripts_make_ffmpeg_bundling_explicit(string scriptName)
    {
        var script = File.ReadAllText(GetProjectFile("scripts", scriptName));

        Assert.Contains("[switch]$BundleFFmpeg", script);
        Assert.Contains("[switch]$DownloadFFmpeg", script);
        Assert.Contains("-p:DownloadFFmpegDuringPublish=$downloadFFmpegValue", script);
        Assert.Contains("-p:BundleFFmpeg=$bundleFFmpegValue", script);
    }

    [Fact]
    public void FFmpeg_bundle_script_uses_temporary_download_before_updating_cache()
    {
        var script = File.ReadAllText(GetProjectFile("build", "BundleFfmpegForPublish.ps1"));

        Assert.Contains("$tempDownloadPath", script);
        Assert.Contains("Move-Item -LiteralPath $tempDownloadPath -Destination $CachePath -Force", script);
        Assert.Contains("Test-ZipArchive", script);
    }

    [Fact]
    public void Wpf_single_file_publish_extracts_content_before_startup()
    {
        var project = File.ReadAllText(GetProjectFile("FluxForm.WPF", "FluxForm.WPF.csproj"));

        Assert.Contains("<IncludeAllContentForSelfExtract Condition=\"'$(PublishSingleFile)' == 'true'\">true</IncludeAllContentForSelfExtract>", project);
    }

    [Fact]
    public void Wpf_publish_script_does_not_require_existing_publish_directory()
    {
        var script = File.ReadAllText(GetProjectFile("scripts", "publish-wpf.ps1"));

        Assert.DoesNotContain("Resolve-Path '.\\\\publish\\\\wpf'", script);
        Assert.Contains("[System.IO.Path]::GetFullPath((Join-Path (Get-Location) 'publish\\wpf'))", script);
    }

    private static string GetProjectFile(params string[] parts)
    {
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        var root = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
        return Path.Combine(new[] { root }.Concat(parts).ToArray());
    }
}
