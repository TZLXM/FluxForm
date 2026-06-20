using FluxForm.Core.Dependencies;
using FluxForm.Core.Models;
using FluxForm.Core.Services;

namespace FluxForm.CLI;

class Program
{
    static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        return args[0].ToLowerInvariant() switch
        {
            "convert" => await RunConvertAsync(args[1..]),
            "batch" => await RunBatchAsync(args[1..]),
            "formats" => await RunFormatsAsync(args[1..]),
            "--help" or "-h" or "help" => PrintUsage(),
            _ => UnknownCommand(args[0])
        };
    }

    static int PrintUsage()
    {
        Console.WriteLine("FluxForm 格式转换工具 CLI");
        Console.WriteLine();
        Console.WriteLine("用法:");
        Console.WriteLine("  FluxForm.CLI convert <input> <output> [options]");
        Console.WriteLine("  FluxForm.CLI batch --input-dir <dir> --output-dir <dir> --to <ext> [options]");
        Console.WriteLine("  FluxForm.CLI formats [video|audio|image|document]");
        Console.WriteLine();
        Console.WriteLine("转换选项:");
        Console.WriteLine("  --quality <value>        质量/CRF 值");
        Console.WriteLine("  --resolution <WxH>       视频分辨率，例如 1920x1080");
        Console.WriteLine("  --video-bitrate <value>  视频码率");
        Console.WriteLine("  --audio-bitrate <value>  音频码率");
        Console.WriteLine("  --no-overwrite           不覆盖已存在文件");
        Console.WriteLine();
        Console.WriteLine("批量选项:");
        Console.WriteLine("  --recursive              递归子目录");
        return 0;
    }

    static int UnknownCommand(string cmd)
    {
        Console.Error.WriteLine($"未知命令：{cmd}");
        PrintUsage();
        return 1;
    }

    static async Task<int> RunConvertAsync(string[] args)
    {
        if (args.Length < 2)
        {
            Console.Error.WriteLine("convert 命令需要输入和输出文件路径。");
            return 1;
        }

        var input = args[0];
        var output = args[1];
        var options = ParseOptions(args[2..], out var overwrite);

        if (!File.Exists(input))
        {
            Console.Error.WriteLine($"输入文件不存在：{input}");
            return 1;
        }

        if (!overwrite && File.Exists(output))
        {
            Console.Error.WriteLine("输出文件已存在，使用 --no-overwrite 取消覆盖（默认覆盖）。");
            return 1;
        }

        var service = CreateService();
        var task = new ConversionTask
        {
            InputPath = Path.GetFullPath(input),
            OutputPath = Path.GetFullPath(output),
            InputFormat = Path.GetExtension(input).TrimStart('.'),
            OutputFormat = Path.GetExtension(output).TrimStart('.'),
            Options = options
        };

        var progress = new Progress<ProgressInfo>(p =>
        {
            if (p.Status == ConversionStatus.Running)
                Console.WriteLine($"[{p.Percent:F1}%] {p.Message}");
            else
                Console.WriteLine($"[{p.Status}] {p.Message}");
        });

        var result = await service.ConvertAsync(task, progress);
        if (result.Status == ConversionStatus.Succeeded)
        {
            Console.WriteLine($"转换成功：{result.OutputPath}，耗时 {result.Duration.TotalSeconds:F2}s");
            return 0;
        }

        Console.Error.WriteLine($"转换失败：{result.ErrorMessage}");
        return 1;
    }

    static async Task<int> RunBatchAsync(string[] args)
    {
        var inputDir = ParseValue(args, "--input-dir");
        var outputDir = ParseValue(args, "--output-dir");
        var to = ParseValue(args, "--to");
        var recursive = args.Contains("--recursive");

        if (string.IsNullOrWhiteSpace(inputDir) || string.IsNullOrWhiteSpace(outputDir) || string.IsNullOrWhiteSpace(to))
        {
            Console.Error.WriteLine("batch 命令需要 --input-dir、--output-dir 和 --to 参数。");
            return 1;
        }

        if (!Directory.Exists(inputDir))
        {
            Console.Error.WriteLine($"输入目录不存在：{inputDir}");
            return 1;
        }

        Directory.CreateDirectory(outputDir);
        var service = CreateService();
        var search = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var files = new DirectoryInfo(inputDir).GetFiles("*.*", search);

        int success = 0, failed = 0;
        foreach (var file in files)
        {
            var outPath = Path.Combine(outputDir, Path.GetFileNameWithoutExtension(file.Name) + "." + to.TrimStart('.'));
            var task = new ConversionTask
            {
                InputPath = file.FullName,
                OutputPath = outPath,
                InputFormat = file.Extension.TrimStart('.'),
                OutputFormat = to.TrimStart('.')
            };

            Console.WriteLine($"正在处理：{file.Name}");
            var result = await service.ConvertAsync(task);
            if (result.Status == ConversionStatus.Succeeded)
            {
                success++;
                Console.WriteLine($"  成功 -> {outPath}");
            }
            else
            {
                failed++;
                Console.Error.WriteLine($"  失败：{result.ErrorMessage}");
            }
        }

        Console.WriteLine($"批量转换完成：成功 {success}，失败 {failed}");
        return failed > 0 ? 1 : 0;
    }

    static Task<int> RunFormatsAsync(string[] args)
    {
        var service = CreateService();
        var category = args.FirstOrDefault() switch
        {
            "video" => ConversionCategory.Video,
            "audio" => ConversionCategory.Audio,
            "image" => ConversionCategory.Image,
            "document" => ConversionCategory.Document,
            _ => (ConversionCategory?)null
        };

        var formats = service.GetFormats(category);
        foreach (var group in formats.GroupBy(f => f.Category).OrderBy(g => g.Key))
        {
            Console.WriteLine($"[{group.Key}]");
            foreach (var f in group)
                Console.WriteLine($"  .{f.Extension}");
        }

        return Task.FromResult(0);
    }

    static IConversionService CreateService()
    {
        var toolsDir = Path.Combine(AppContext.BaseDirectory, "tools");
        var depManager = new DependencyManager(toolsDir, new Progress<string>(Console.WriteLine));
        return new ConversionService(depManager);
    }

    static Dictionary<string, string> ParseOptions(string[] args, out bool overwrite)
    {
        overwrite = !args.Contains("--no-overwrite");
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string? TakeNext(ref int i)
        {
            if (i + 1 >= args.Length) return null;
            return args[++i];
        }

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--quality": dict["quality"] = TakeNext(ref i) ?? ""; break;
                case "--resolution": dict["resolution"] = TakeNext(ref i) ?? ""; break;
                case "--video-bitrate": dict["videoBitrate"] = TakeNext(ref i) ?? ""; break;
                case "--audio-bitrate": dict["audioBitrate"] = TakeNext(ref i) ?? ""; break;
            }
        }

        return dict;
    }

    static string? ParseValue(string[] args, string key)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(key, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return null;
    }
}
