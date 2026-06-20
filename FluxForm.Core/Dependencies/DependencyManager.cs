using System.IO.Compression;
using System.Security.Cryptography;

namespace FluxForm.Core.Dependencies;

public class DependencyManager : IDependencyManager
{
    private readonly Dictionary<string, DependencyConfig> _configs;
    private readonly HttpClient _httpClient;
    private readonly IProgress<string>? _progress;

    public string ToolsDirectory { get; }

    public DependencyManager(string toolsDirectory, IProgress<string>? progress = null)
    {
        ToolsDirectory = Path.GetFullPath(toolsDirectory);
        _httpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
        _progress = progress;

        _configs = new Dictionary<string, DependencyConfig>(StringComparer.OrdinalIgnoreCase)
        {
            ["ffmpeg"] = new()
            {
                Name = "ffmpeg",
                WindowsUrl = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip",
                RelativeExecutablePath = "ffmpeg.exe",
                ArchiveType = "zip"
            },
            ["libreoffice"] = new()
            {
                Name = "libreoffice",
                WindowsUrl = "https://download.documentfoundation.org/libreoffice/stable/25.2.3/win/x86_64/LibreOffice_25.2.3_Win_x86-64.msi",
                RelativeExecutablePath = "program/soffice.exe",
                ArchiveType = null // MSI is installed separately; auto-download is disabled by default
            }
        };
    }

    public bool IsAvailable(string dependencyName)
    {
        return !string.IsNullOrEmpty(GetExecutablePath(dependencyName));
    }

    public string? GetExecutablePath(string dependencyName)
    {
        if (!_configs.TryGetValue(dependencyName, out var config))
            return null;

        var path = Path.Combine(ToolsDirectory, dependencyName, config.RelativeExecutablePath);
        if (File.Exists(path))
            return path;

        var direct = Path.Combine(ToolsDirectory, dependencyName + ".exe");
        if (File.Exists(direct))
            return direct;

        return null;
    }

    public async Task<string?> EnsureAvailableAsync(string dependencyName, CancellationToken cancellationToken = default)
    {
        if (!_configs.TryGetValue(dependencyName, out var config))
            return null;

        var existing = GetExecutablePath(dependencyName);
        if (!string.IsNullOrEmpty(existing))
            return existing;

        if (config.ArchiveType == null)
        {
            _progress?.Report($"{dependencyName} 未配置自动下载，请手动安装。");
            return null;
        }

        _progress?.Report($"正在下载 {dependencyName}...");

        var depDir = Path.Combine(ToolsDirectory, dependencyName);
        Directory.CreateDirectory(depDir);

        var archivePath = Path.Combine(depDir, $"{dependencyName}-download.{config.ArchiveType ?? "zip"}");

        using (var response = await _httpClient.GetAsync(config.WindowsUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken))
        {
            response.EnsureSuccessStatusCode();
            await using var fs = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None);
            await response.Content.CopyToAsync(fs, cancellationToken);
        }

        _progress?.Report($"正在解压 {dependencyName}...");

        if (config.ArchiveType == "zip")
        {
            ZipFile.ExtractToDirectory(archivePath, depDir, true);
        }

        File.Delete(archivePath);

        // gyan.dev zip contains a versioned folder; search for the executable
        var exeName = config.RelativeExecutablePath;
        var found = Directory.EnumerateFiles(depDir, exeName, SearchOption.AllDirectories).FirstOrDefault();
        if (found != null)
        {
            var targetDir = Path.GetDirectoryName(found)!;
            // Move files up if nested (simplify path)
            if (!targetDir.Equals(depDir, StringComparison.OrdinalIgnoreCase))
            {
                foreach (var file in Directory.EnumerateFiles(targetDir, "*", SearchOption.AllDirectories))
                {
                    var relative = Path.GetRelativePath(targetDir, file);
                    var dest = Path.Combine(depDir, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                    if (!File.Exists(dest))
                        File.Move(file, dest);
                }
                Directory.Delete(targetDir, true);
            }
        }

        return GetExecutablePath(dependencyName);
    }
}
