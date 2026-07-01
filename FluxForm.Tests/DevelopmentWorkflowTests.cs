using System.IO;
using System.Reflection;

namespace FluxForm.Tests;

public class DevelopmentWorkflowTests
{
    [Fact]
    public void Repository_pins_sdk_and_enables_locked_package_restore()
    {
        var globalJson = File.ReadAllText(GetProjectFile("global.json"));
        var directoryProps = File.ReadAllText(GetProjectFile("Directory.Build.props"));

        Assert.Contains("\"version\": \"9.0.305\"", globalJson);
        Assert.Contains("\"rollForward\": \"latestFeature\"", globalJson);
        Assert.Contains("<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>", directoryProps);
        Assert.Contains("<ContinuousIntegrationBuild Condition=\"'$(CI)' == 'true'\">true</ContinuousIntegrationBuild>", directoryProps);
    }

    [Fact]
    public void Repository_declares_initial_application_version()
    {
        var directoryProps = File.ReadAllText(GetProjectFile("Directory.Build.props"));

        Assert.Contains("<VersionPrefix>0.1.1</VersionPrefix>", directoryProps);
        Assert.Contains("<AssemblyVersion>0.1.1.0</AssemblyVersion>", directoryProps);
        Assert.Contains("<FileVersion>0.1.1.0</FileVersion>", directoryProps);
        Assert.Contains("<InformationalVersion>0.1.1</InformationalVersion>", directoryProps);
        Assert.Contains("<IncludeSourceRevisionInInformationalVersion>false</IncludeSourceRevisionInInformationalVersion>", directoryProps);
    }

    [Fact]
    public void Repository_defines_encoding_and_line_ending_policy()
    {
        var editorConfig = File.ReadAllText(GetProjectFile(".editorconfig"));
        var gitAttributes = File.ReadAllText(GetProjectFile(".gitattributes"));

        Assert.Contains("charset = utf-8", editorConfig);
        Assert.Contains("end_of_line = crlf", editorConfig);
        Assert.Contains("*.cs text eol=crlf", gitAttributes);
        Assert.Contains("*.ps1 text eol=crlf", gitAttributes);
        Assert.Contains("*.zip binary", gitAttributes);
    }

    [Fact]
    public void Ci_runs_release_check_instead_of_only_build_and_test()
    {
        var workflow = File.ReadAllText(GetProjectFile(".github", "workflows", "ci.yml"));

        Assert.Contains("permissions:", workflow);
        Assert.Contains("contents: read", workflow);
        Assert.Contains("concurrency:", workflow);
        Assert.Contains("Release check", workflow);
        Assert.Contains(@".\scripts\release-check.ps1", workflow);
        Assert.DoesNotContain("dotnet build .\\FluxForm.sln --configuration Release --no-restore", workflow);
        Assert.DoesNotContain("dotnet test .\\FluxForm.sln --configuration Release --no-build", workflow);
    }

    [Fact]
    public void Release_check_can_optionally_run_wpf_smoke_test()
    {
        var releaseCheck = File.ReadAllText(GetProjectFile("scripts", "release-check.ps1"));
        var smoke = File.ReadAllText(GetProjectFile("scripts", "smoke-wpf.ps1"));
        var publishCli = File.ReadAllText(GetProjectFile("scripts", "publish-cli.ps1"));
        var publishWpf = File.ReadAllText(GetProjectFile("scripts", "publish-wpf.ps1"));

        Assert.Contains("[switch]$RunWpfSmoke", releaseCheck);
        Assert.Contains("smoke-wpf.ps1", releaseCheck);
        Assert.Contains("-p:RestorePackagesWithLockFile=false", publishCli);
        Assert.Contains("-p:RestorePackagesWithLockFile=false", publishWpf);
        Assert.Contains("-p:NuGetLockFilePath=.\\FluxForm.CLI\\obj\\publish.packages.lock.json", publishCli);
        Assert.Contains("-p:NuGetLockFilePath=.\\FluxForm.WPF\\obj\\publish.packages.lock.json", publishWpf);
        Assert.Contains("[switch]$BuildInstaller", releaseCheck);
        Assert.Contains("publish-installer.ps1", releaseCheck);
        Assert.Contains("MainWindowHandle", smoke);
        Assert.Contains("Start-Process", smoke);
        Assert.Contains("Stop-Process", smoke);
    }

    [Fact]
    public void GitHub_pull_request_template_requires_scope_and_verification_notes()
    {
        var template = File.ReadAllText(GetProjectFile(".github", "pull_request_template.md"));

        Assert.Contains("Summary", template);
        Assert.Contains("Test Plan", template);
        Assert.Contains("WPF", template);
        Assert.Contains("publish", template);
        Assert.Contains("FFmpeg", template);
        Assert.Contains("LibreOffice", template);
    }

    [Fact]
    public void Documentation_describes_installer_distribution()
    {
        var readme = File.ReadAllText(GetProjectFile("README.md"));
        var agents = File.ReadAllText(GetProjectFile("AGENTS.md"));

        Assert.Contains("FluxFormSetup-0.1.1.exe", readme);
        Assert.Contains("scripts/publish-installer.ps1", readme);
        Assert.Contains("SmartScreen", readme);
        Assert.Contains("LibreOffice", readme);

        Assert.Contains("scripts/publish-installer.ps1", agents);
        Assert.Contains("FluxFormSetup-0.1.1.exe", agents);
        Assert.Contains("Inno Setup", agents);
    }

    [Fact]
    public void GitHub_issue_templates_collect_reproduction_environment_and_acceptance_details()
    {
        var bugReport = File.ReadAllText(GetProjectFile(".github", "ISSUE_TEMPLATE", "bug_report.yml"));
        var featureRequest = File.ReadAllText(GetProjectFile(".github", "ISSUE_TEMPLATE", "feature_request.yml"));

        Assert.Contains("FluxForm bug report", bugReport);
        Assert.Contains("Windows version", bugReport);
        Assert.Contains("Input format", bugReport);
        Assert.Contains("Output format", bugReport);
        Assert.Contains("FFmpeg", bugReport);
        Assert.Contains("LibreOffice", bugReport);
        Assert.Contains("Logs", bugReport);

        Assert.Contains("FluxForm feature request", featureRequest);
        Assert.Contains("User workflow", featureRequest);
        Assert.Contains("Acceptance criteria", featureRequest);
    }

    [Fact]
    public void GitHub_dependabot_tracks_actions_and_nuget_manifests()
    {
        var dependabot = File.ReadAllText(GetProjectFile(".github", "dependabot.yml"));

        Assert.Contains("package-ecosystem: \"github-actions\"", dependabot);
        Assert.Contains("package-ecosystem: \"nuget\"", dependabot);
        Assert.Contains("directory: \"/FluxForm.Core\"", dependabot);
        Assert.Contains("directory: \"/FluxForm.CLI\"", dependabot);
        Assert.Contains("directory: \"/FluxForm.WPF\"", dependabot);
        Assert.Contains("directory: \"/FluxForm.Tests\"", dependabot);
    }

    [Fact]
    public void GitHub_release_workflow_builds_release_and_uploads_cli_wpf_and_installer_artifacts()
    {
        var releaseWorkflow = File.ReadAllText(GetProjectFile(".github", "workflows", "release.yml"));

        Assert.Contains("workflow_dispatch:", releaseWorkflow);
        Assert.Contains("release_tag:", releaseWorkflow);
        Assert.Contains("tags:", releaseWorkflow);
        Assert.Contains("contents: write", releaseWorkflow);
        Assert.Contains("Install Inno Setup", releaseWorkflow);
        Assert.Contains("JRSoftware.InnoSetup", releaseWorkflow);
        Assert.Contains(@".\scripts\release-check.ps1 -Runtime $env:RUNTIME -BuildInstaller -DownloadFFmpeg", releaseWorkflow);
        Assert.Contains("Compress-Archive -Path publish/cli/*", releaseWorkflow);
        Assert.Contains("Compress-Archive -Path publish/wpf/*", releaseWorkflow);
        Assert.Contains("FluxFormSetup-0.1.1.exe", releaseWorkflow);
        Assert.Contains("if: startsWith(github.ref, 'refs/tags/') || inputs.release_tag != ''", releaseWorkflow);
        Assert.Contains("GH_TOKEN: ${{ github.token }}", releaseWorkflow);
        Assert.Contains("RELEASE_TAG: ${{ inputs.release_tag || github.ref_name }}", releaseWorkflow);
        Assert.Contains("gh release create $env:RELEASE_TAG", releaseWorkflow);
        Assert.Contains("--verify-tag", releaseWorkflow);
        Assert.Contains("--generate-notes", releaseWorkflow);
        Assert.Contains("actions/upload-artifact@v4", releaseWorkflow);
        Assert.Contains("publish/cli", releaseWorkflow);
        Assert.Contains("publish/wpf", releaseWorkflow);
        Assert.Contains("publish/installer/FluxFormSetup-0.1.1.exe", releaseWorkflow);
    }

    private static string GetProjectFile(params string[] parts)
    {
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        var root = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
        return Path.Combine(new[] { root }.Concat(parts).ToArray());
    }
}
