using System.Diagnostics;
using System.Text.RegularExpressions;
using CliWrap;
using CliWrap.Buffered;
using FluxForm.Core.Dependencies;
using FluxForm.Core.Models;

namespace FluxForm.Core.Converters;

public class FFmpegConverter : IConverter
{
    private static readonly Regex DurationRegex = new(@"Duration: (\d{2}):(\d{2}):(\d{2}\.\d{2})", RegexOptions.Compiled);
    private static readonly Regex ProgressRegex = new(@"time=(\d{2}):(\d{2}):(\d{2}\.\d{2})", RegexOptions.Compiled);

    private readonly IDependencyManager _dependencyManager;

    public ConversionCategory Category { get; }

    public IReadOnlyCollection<string> SupportedInputFormats { get; }
    public IReadOnlyCollection<string> SupportedOutputFormats { get; }

    public FFmpegConverter(IDependencyManager dependencyManager, ConversionCategory category, IEnumerable<string> formats)
    {
        _dependencyManager = dependencyManager;
        Category = category;
        var list = formats.ToList().AsReadOnly();
        SupportedInputFormats = list;
        SupportedOutputFormats = list;
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
            var ffmpegPath = await _dependencyManager.EnsureAvailableAsync("ffmpeg", cancellationToken);
            if (string.IsNullOrEmpty(ffmpegPath) || !File.Exists(ffmpegPath))
                return ConversionResult.Failure(task.Id, "FFmpeg 不可用，请检查依赖设置。", sw.Elapsed);

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(task.OutputPath))!);

            var args = new List<string> { "-y", "-i", task.InputPath };
            ApplyOptions(args, task);
            args.Add(task.OutputPath);

            double? totalSeconds = null;

            var cmd = Cli.Wrap(ffmpegPath)
                .WithArguments(args)
                .WithValidation(CommandResultValidation.None)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(new System.Text.StringBuilder()))
                .WithStandardErrorPipe(PipeTarget.ToDelegate(line =>
                {
                    if (!totalSeconds.HasValue)
                    {
                        var durMatch = DurationRegex.Match(line);
                        if (durMatch.Success)
                        {
                            totalSeconds = ParseTime(durMatch);
                        }
                    }

                    var progMatch = ProgressRegex.Match(line);
                    if (progMatch.Success && totalSeconds.HasValue && totalSeconds.Value > 0)
                    {
                        var current = ParseTime(progMatch);
                        var percent = Math.Min(100, current / totalSeconds.Value * 100);
                        progress.Report(new ProgressInfo
                        {
                            TaskId = task.Id,
                            Status = ConversionStatus.Running,
                            Percent = percent,
                            Message = $"转换中 {percent:F1}%"
                        });
                    }
                }));

            var result = await cmd.ExecuteBufferedAsync(cancellationToken);
            sw.Stop();

            if (result.ExitCode != 0)
            {
                var error = string.IsNullOrWhiteSpace(result.StandardError)
                    ? $"FFmpeg 退出码 {result.ExitCode}"
                    : result.StandardError;
                return ConversionResult.Failure(task.Id, error, sw.Elapsed);
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

    private static void ApplyOptions(List<string> args, ConversionTask task)
    {
        if (task.Options.TryGetValue("resolution", out var resolution) && !string.IsNullOrWhiteSpace(resolution))
        {
            args.Add("-s");
            args.Add(resolution);
        }

        if (task.Options.TryGetValue("videoBitrate", out var vbr) && !string.IsNullOrWhiteSpace(vbr))
        {
            args.Add("-b:v");
            args.Add(vbr);
        }

        if (task.Options.TryGetValue("audioBitrate", out var abr) && !string.IsNullOrWhiteSpace(abr))
        {
            args.Add("-b:a");
            args.Add(abr);
        }

        if (task.Options.TryGetValue("audioCodec", out var acodec) && !string.IsNullOrWhiteSpace(acodec))
        {
            args.Add("-c:a");
            args.Add(acodec);
        }

        if (task.Options.TryGetValue("videoCodec", out var vcodec) && !string.IsNullOrWhiteSpace(vcodec))
        {
            args.Add("-c:v");
            args.Add(vcodec);
        }

        if (task.Options.TryGetValue("frameRate", out var frameRate) && !string.IsNullOrWhiteSpace(frameRate))
        {
            args.Add("-r");
            args.Add(frameRate);
        }

        if (task.Options.TryGetValue("aspectRatio", out var aspectRatio) && !string.IsNullOrWhiteSpace(aspectRatio))
        {
            args.Add("-aspect");
            args.Add(aspectRatio);
        }

        if (task.Options.TryGetValue("quality", out var q) && int.TryParse(q, out var crf))
        {
            args.Add("-crf");
            args.Add(crf.ToString());
        }

        if (task.Category == ConversionCategory.Image)
        {
            args.Add("-q:v");
            args.Add(task.Options.TryGetValue("quality", out var iq) && int.TryParse(iq, out _) ? iq : "2");
        }
    }

    private static double ParseTime(Match match)
    {
        var hours = double.Parse(match.Groups[1].Value);
        var minutes = double.Parse(match.Groups[2].Value);
        var seconds = double.Parse(match.Groups[3].Value);
        return hours * 3600 + minutes * 60 + seconds;
    }

    private static string Normalize(string extension)
    {
        return extension.TrimStart('.').ToLowerInvariant();
    }
}
