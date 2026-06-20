using System.Diagnostics;
using CliWrap;
using CliWrap.Buffered;
using FluxForm.Core.Dependencies;
using FluxForm.Core.Models;

namespace FluxForm.Core.Converters;

public class LibreOfficeConverter : IConverter
{
    private readonly IDependencyManager _dependencyManager;

    public ConversionCategory Category => ConversionCategory.Document;

    public IReadOnlyCollection<string> SupportedInputFormats { get; }
    public IReadOnlyCollection<string> SupportedOutputFormats { get; }

    public LibreOfficeConverter(IDependencyManager dependencyManager)
    {
        _dependencyManager = dependencyManager;
        var formats = new[] { "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "html", "htm", "odt", "ods", "odp" };
        SupportedInputFormats = formats;
        SupportedOutputFormats = formats;
    }

    public bool CanConvert(string inputExtension, string outputExtension)
    {
        var inExt = Normalize(inputExtension);
        var outExt = Normalize(outputExtension);
        return SupportedInputFormats.Contains(inExt, StringComparer.OrdinalIgnoreCase)
            && SupportedOutputFormats.Contains(outExt, StringComparer.OrdinalIgnoreCase);
    }

    public async Task<ConversionResult> ConvertAsync(ConversionTask task, IProgress<ProgressInfo> progress, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var sofficePath = await _dependencyManager.EnsureAvailableAsync("libreoffice", cancellationToken);
            if (string.IsNullOrEmpty(sofficePath) || !File.Exists(sofficePath))
            {
                // Fallback: try common installation directories
                sofficePath = FindInstalledLibreOffice();
                if (string.IsNullOrEmpty(sofficePath))
                    return ConversionResult.Failure(task.Id, "未找到 LibreOffice。请安装 LibreOffice 或将其路径加入系统 PATH。", sw.Elapsed);
            }

            var outputDir = Path.GetDirectoryName(Path.GetFullPath(task.OutputPath))!;
            Directory.CreateDirectory(outputDir);

            progress.Report(new ProgressInfo { TaskId = task.Id, Status = ConversionStatus.Running, Percent = 10, Message = "LibreOffice 转换中..." });

            var cmd = Cli.Wrap(sofficePath)
                .WithArguments(new[] { "--headless", "--convert-to", task.OutputFormat, "--outdir", outputDir, task.InputPath })
                .WithValidation(CommandResultValidation.None);

            var result = await cmd.ExecuteBufferedAsync(cancellationToken);
            sw.Stop();

            if (result.ExitCode != 0)
            {
                var error = string.IsNullOrWhiteSpace(result.StandardError)
                    ? $"LibreOffice 退出码 {result.ExitCode}"
                    : result.StandardError;
                return ConversionResult.Failure(task.Id, error, sw.Elapsed);
            }

            // LibreOffice uses input file name + target extension in output dir
            var expectedOutput = Path.Combine(outputDir, Path.GetFileNameWithoutExtension(task.InputPath) + "." + task.OutputFormat);
            if (!File.Exists(expectedOutput))
            {
                return ConversionResult.Failure(task.Id, "LibreOffice 未生成预期输出文件。", sw.Elapsed);
            }

            // Move to requested output path if different
            if (!expectedOutput.Equals(Path.GetFullPath(task.OutputPath), StringComparison.OrdinalIgnoreCase))
            {
                if (File.Exists(task.OutputPath))
                    File.Delete(task.OutputPath);
                File.Move(expectedOutput, task.OutputPath);
            }

            progress.Report(new ProgressInfo { TaskId = task.Id, Status = ConversionStatus.Succeeded, Percent = 100, Message = "完成" });
            return ConversionResult.Success(task.Id, task.OutputPath, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            progress.Report(new ProgressInfo { TaskId = task.Id, Status = ConversionStatus.Cancelled, Percent = 0, Message = "已取消" });
            return ConversionResult.Cancelled(task.Id);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return ConversionResult.Failure(task.Id, ex.Message, sw.Elapsed);
        }
    }

    private static string? FindInstalledLibreOffice()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "LibreOffice", "program", "soffice.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "LibreOffice", "program", "soffice.exe"),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static string Normalize(string extension)
    {
        return extension.TrimStart('.').ToLowerInvariant();
    }
}
