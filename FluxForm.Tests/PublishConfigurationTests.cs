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
    public void FFmpeg_bundle_script_extracts_outside_target_directory_before_replacing_files()
    {
        var script = File.ReadAllText(GetProjectFile("build", "BundleFfmpegForPublish.ps1"));

        Assert.Contains("[System.IO.Path]::GetTempPath()", script);
        Assert.DoesNotContain("[System.IO.Path]::Combine($ffmpegDir, \"_extract_\"", script);
        Assert.Contains("Get-ChildItem -LiteralPath $binDir -File", script);
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

    [Fact]
    public void Installer_definition_targets_per_user_wpf_install_with_languages()
    {
        var installer = File.ReadAllText(GetProjectFile("installer", "FluxForm.iss"));

        Assert.Contains("#define MyAppVersion \"0.1.1\"", installer);
        Assert.Contains("OutputBaseFilename=FluxFormSetup-0.1.1", installer);
        Assert.Contains("DefaultDirName={localappdata}\\Programs\\FluxForm", installer);
        Assert.Contains("PrivilegesRequired=lowest", installer);
        Assert.Contains("DisableDirPage=no", installer);
        Assert.Contains("Name: \"english\"; MessagesFile: \"compiler:Default.isl\"", installer);
        Assert.Contains("Name: \"chinesesimp\"; MessagesFile: \".\\Languages\\ChineseSimplified.isl\"", installer);
        Assert.True(File.Exists(GetProjectFile("installer", "Languages", "ChineseSimplified.isl")));
        Assert.Contains("Source: \"..\\publish\\wpf\\FluxForm.WPF.exe\"; DestDir: \"{app}\"", installer);
        Assert.Contains("Source: \"..\\publish\\wpf\\tools\\ffmpeg\\*\"; DestDir: \"{app}\\tools\\ffmpeg\"", installer);
        Assert.Contains("Name: \"{group}\\FluxForm\"; Filename: \"{app}\\FluxForm.WPF.exe\"", installer);
        Assert.Contains("Name: \"{userdesktop}\\FluxForm\"; Filename: \"{app}\\FluxForm.WPF.exe\"; Tasks: desktopicon", installer);
    }

    [Fact]
    public void Installer_publish_script_builds_wpf_with_ffmpeg_and_finds_inno_compiler()
    {
        var script = File.ReadAllText(GetProjectFile("scripts", "publish-installer.ps1"));

        Assert.Contains("[string]$InnoSetupCompilerPath", script);
        Assert.Contains("[switch]$DownloadFFmpeg", script);
        Assert.Contains(".\\scripts\\publish-wpf.ps1", script);
        Assert.Contains("-BundleFFmpeg", script);
        Assert.Contains("-DownloadFFmpeg", script);
        Assert.Contains("ISCC.exe", script);
        Assert.Contains("FluxForm.iss", script);
        Assert.Contains("Inno Setup compiler was not found", script);
        Assert.Contains("Test-Path -LiteralPath $_", script);
    }

    [Fact]
    public void Installer_publish_script_logs_failures_and_has_double_click_wrapper()
    {
        var script = File.ReadAllText(GetProjectFile("scripts", "publish-installer.ps1"));
        var wrapper = File.ReadAllText(GetProjectFile("scripts", "publish-installer.cmd"));

        Assert.Contains("[switch]$PauseOnError", script);
        Assert.Contains("publish\\installer", script);
        Assert.Contains("publish-installer.log", script);
        Assert.Contains("Start-Transcript -LiteralPath $logPath", script);
        Assert.Contains("Press Enter to close", script);

        Assert.Contains("powershell.exe", wrapper);
        Assert.Contains("-PauseOnError", wrapper);
        Assert.Contains("publish-installer.ps1", wrapper);
    }

    [Fact]
    public void Release_check_builds_installer_only_when_requested()
    {
        var script = File.ReadAllText(GetProjectFile("scripts", "release-check.ps1"));

        Assert.Contains("[switch]$BuildInstaller", script);
        Assert.Contains("[switch]$DownloadFFmpeg", script);
        Assert.Contains("if ($BuildInstaller)", script);
        Assert.Contains("-DownloadFFmpeg:$DownloadFFmpeg", script);
    }

    private static string GetProjectFile(params string[] parts)
    {
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        var root = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
        return Path.Combine(new[] { root }.Concat(parts).ToArray());
    }
}
