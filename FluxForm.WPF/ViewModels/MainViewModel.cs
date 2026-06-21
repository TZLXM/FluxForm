using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using FluxForm.Core.Dependencies;
using FluxForm.Core.Models;
using FluxForm.Core.Services;
using Microsoft.Win32;

namespace FluxForm.WPF.ViewModels;

public class MainViewModel : ObservableObject
{
    private readonly IConversionService _conversionService;
    private readonly DependencyManager _dependencyManager;

    private string _selectedCategory = "全部";
    private string _logText = string.Empty;
    private string _outputDirectory = string.Empty;
    private string _statusText = "就绪";
    private double _totalProgress;
    private bool _isBusy;
    private CancellationTokenSource? _cts;

    private readonly Dictionary<ConversionCategory, string> _defaultFormats = new()
    {
        [ConversionCategory.Video] = "mp4",
        [ConversionCategory.Audio] = "mp3",
        [ConversionCategory.Image] = "png",
        [ConversionCategory.Document] = "pdf"
    };

    public ObservableCollection<TaskItemViewModel> Tasks { get; } = new();
    public ObservableCollection<string> Categories { get; } = new() { "全部", "视频", "音频", "图片", "文档" };
    public ObservableCollection<FormatPreset> FormatPresets { get; } = new();
    public ICollectionView TasksView { get; }

    public string SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (SetProperty(ref _selectedCategory, value))
            {
                RefreshFormats();
                UpdateStatus();
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string OutputDirectory
    {
        get => _outputDirectory;
        set
        {
            if (SetProperty(ref _outputDirectory, value))
            {
                foreach (var task in Tasks)
                    task.OutputPath = GenerateOutputPath(task.InputPath, task.OutputFormat);
                UpdateStatus();
            }
        }
    }

    public string StatusText
    {
        get => _statusText;
        private set => SetProperty(ref _statusText, value);
    }

    public double TotalProgress
    {
        get => _totalProgress;
        private set => SetProperty(ref _totalProgress, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                UpdateStatus();
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool HasTasks => Tasks.Count > 0;
    public bool IsEmpty => Tasks.Count == 0;
    public bool NoFormatPresets => FormatPresets.Count == 0;

    public RelayCommand AddFilesCommand { get; }
    public RelayCommand ClearCommand { get; }
    public RelayCommand StartCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand SetOutputDirectoryCommand { get; }
    public RelayCommand<TaskItemViewModel> RemoveTaskCommand { get; }
    public RelayCommand<string> ApplyFormatCommand { get; }
    public RelayCommand OpenOutputCommand { get; }

    public string LogText
    {
        get => _logText;
        set => SetProperty(ref _logText, value);
    }

    public MainViewModel()
    {
        var toolsDir = Path.Combine(AppContext.BaseDirectory, "tools");
        _dependencyManager = new DependencyManager(toolsDir, new Progress<string>(msg => AppendLog(msg)));
        _conversionService = new ConversionService(_dependencyManager);

        Tasks.CollectionChanged += OnTasksCollectionChanged;

        TasksView = CollectionViewSource.GetDefaultView(Tasks);

        AddFilesCommand = new RelayCommand(_ => AddFiles());
        ClearCommand = new RelayCommand(_ => ClearTasks(), _ => Tasks.Count > 0 && !IsBusy);
        StartCommand = new RelayCommand(_ => StartConversion(), _ => Tasks.Count > 0 && !IsBusy);
        CancelCommand = new RelayCommand(_ => CancelConversion(), _ => IsBusy);
        SetOutputDirectoryCommand = new RelayCommand(_ => SetOutputDirectory());
        RemoveTaskCommand = new RelayCommand<TaskItemViewModel>(t => RemoveTask(t), _ => !IsBusy);
        ApplyFormatCommand = new RelayCommand<string>(fmt => ApplyFormat(fmt));
        OpenOutputCommand = new RelayCommand(p => OpenOutput(p?.ToString()));
        RefreshFormats();
        UpdateStatus();
    }

    private void RefreshFormats()
    {
        FormatPresets.Clear();
        var category = StringToCategory(SelectedCategory);
        if (category == null) return;

        foreach (var format in _conversionService.GetFormats(category.Value)
                     .Select(f => f.Extension)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .OrderBy(x => x))
        {
            FormatPresets.Add(new FormatPreset
            {
                Extension = format,
                DisplayName = format.ToUpperInvariant(),
                Category = category.Value
            });
        }

        OnPropertyChanged(nameof(NoFormatPresets));
    }

    private void ApplyFormat(string? format)
    {
        if (string.IsNullOrWhiteSpace(format)) return;

        var category = StringToCategory(SelectedCategory);
        var targets = category == null
            ? Tasks.ToList()
            : Tasks.Where(t => t.Category == category.Value).ToList();

        foreach (var task in targets)
        {
            if (task.Status == ConversionStatus.Running) continue;
            task.OutputFormat = format;
            task.OutputPath = GenerateOutputPath(task.InputPath, format);
        }

        if (category != null)
            _defaultFormats[category.Value] = format;

        AppendLog($"已将 {(category == null ? "全部" : CategoryToString(category.Value))} 目标格式设为 {format.ToUpperInvariant()}");
    }

    public void AddFiles(IEnumerable<string> files)
    {
        foreach (var file in files)
        {
            if (!File.Exists(file)) continue;

            var ext = Path.GetExtension(file).TrimStart('.').ToLowerInvariant();
            var category = GuessCategory(ext);
            var outputFormat = _defaultFormats.GetValueOrDefault(category, ext);
            var outputPath = GenerateOutputPath(file, outputFormat);

            var task = new TaskItemViewModel
            {
                FileName = Path.GetFileName(file),
                InputPath = file,
                InputFormat = ext,
                OutputFormat = outputFormat,
                OutputPath = outputPath,
                Category = category,
                Status = ConversionStatus.Pending,
                Message = "等待中"
            };

            task.PropertyChanged += OnTaskPropertyChanged;
            Tasks.Add(task);
        }

        CommandManager.InvalidateRequerySuggested();
        TasksView.Refresh();
        UpdateStatus();
    }

    private void AddFiles()
    {
        var dialog = new OpenFileDialog
        {
            Multiselect = true,
            Title = "选择要转换的文件"
        };
        if (dialog.ShowDialog() == true)
            AddFiles(dialog.FileNames);
    }

    private void SetOutputDirectory()
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择输出目录",
            Multiselect = false
        };
        if (dialog.ShowDialog() == true)
            OutputDirectory = dialog.FolderName;
    }

    private string GenerateOutputPath(string inputPath, string outputFormat)
    {
        var dir = !string.IsNullOrWhiteSpace(OutputDirectory)
            ? OutputDirectory
            : Path.GetDirectoryName(inputPath)!;
        var fileName = Path.GetFileNameWithoutExtension(inputPath) + "_converted." + outputFormat;
        return Path.Combine(dir, fileName);
    }

    private void RemoveTask(TaskItemViewModel? task)
    {
        if (task == null) return;
        task.PropertyChanged -= OnTaskPropertyChanged;
        Tasks.Remove(task);
        TasksView.Refresh();
        UpdateStatus();
        CommandManager.InvalidateRequerySuggested();
    }

    private void ClearTasks()
    {
        foreach (var task in Tasks)
            task.PropertyChanged -= OnTaskPropertyChanged;
        Tasks.Clear();
        TasksView.Refresh();
        UpdateStatus();
        CommandManager.InvalidateRequerySuggested();
    }

    private async void StartConversion()
    {
        IsBusy = true;
        _cts = new CancellationTokenSource();
        CommandManager.InvalidateRequerySuggested();
        AppendLog("开始转换任务...");

        var pending = Tasks.Where(t => t.Status == ConversionStatus.Pending).ToList();
        var stopwatch = Stopwatch.StartNew();

        foreach (var task in pending)
        {
            if (_cts.IsCancellationRequested)
            {
                AppendLog("转换已取消，停止后续任务。");
                break;
            }

            var supportedFormats = _conversionService.GetFormats(task.Category)
                .Select(f => f.Extension)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (!supportedFormats.Contains(task.OutputFormat))
            {
                task.Status = ConversionStatus.Failed;
                task.Message = $"不支持的输出格式：{task.OutputFormat}";
                AppendLog($"{task.FileName}: {task.Message}");
                continue;
            }

            task.Status = ConversionStatus.Running;
            task.Message = "转换中...";

            var progress = new Progress<ProgressInfo>(p =>
            {
                task.Progress = p.Percent;
                task.Message = p.Message;
                task.Status = p.Status;
                UpdateTotalProgress();
            });

            try
            {
                var result = await _conversionService.ConvertAsync(task.ToModel(), progress, _cts.Token);
                task.Status = result.Status;
                task.Message = result.Status == ConversionStatus.Succeeded
                    ? $"完成 ({result.Duration.TotalSeconds:F1}s)"
                    : result.Status == ConversionStatus.Cancelled
                        ? "已取消"
                        : $"失败：{result.ErrorMessage}";
                AppendLog($"{task.FileName}: {task.Message}");
            }
            catch (Exception ex)
            {
                task.Status = ConversionStatus.Failed;
                task.Message = $"异常：{ex.Message}";
                AppendLog($"{task.FileName}: {ex.Message}");
            }
        }

        stopwatch.Stop();
        _cts.Dispose();
        _cts = null;
        IsBusy = false;
        UpdateTotalProgress();
        CommandManager.InvalidateRequerySuggested();
        AppendLog($"所有任务处理完毕。总耗时：{stopwatch.Elapsed.TotalSeconds:F1}s");
        UpdateStatus();
    }

    private void CancelConversion()
    {
        _cts?.Cancel();
        AppendLog("用户请求取消转换...");
    }

    private void OpenOutput(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        Process.Start("explorer.exe", $"/select,\"{path}\"");
    }

    private void AppendLog(string message)
    {
        LogText += $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
    }

    private void UpdateTotalProgress()
    {
        TotalProgress = Tasks.Count > 0 ? Tasks.Average(t => t.Progress) : 0;
    }

    private void UpdateStatus()
    {
        var total = Tasks.Count;
        var pending = Tasks.Count(t => t.Status == ConversionStatus.Pending);
        var succeeded = Tasks.Count(t => t.Status == ConversionStatus.Succeeded);
        var failed = Tasks.Count(t => t.Status == ConversionStatus.Failed);
        var dir = string.IsNullOrWhiteSpace(OutputDirectory) ? "与源文件相同" : OutputDirectory;

        if (IsBusy)
            StatusText = $"转换中 · 待处理 {pending} · 完成 {succeeded} · 失败 {failed}";
        else if (total == 0)
            StatusText = "就绪 · 点击“添加文件”或拖拽文件到此处";
        else
            StatusText = $"共 {total} 个任务 · 待处理 {pending} · 完成 {succeeded} · 失败 {failed} · 输出目录：{dir}";
    }

    private void OnTasksCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems != null)
        {
            foreach (TaskItemViewModel task in e.NewItems)
                task.PropertyChanged += OnTaskPropertyChanged;
        }

        if (e.OldItems != null)
        {
            foreach (TaskItemViewModel task in e.OldItems)
                task.PropertyChanged -= OnTaskPropertyChanged;
        }

        OnPropertyChanged(nameof(HasTasks));
        OnPropertyChanged(nameof(IsEmpty));
        UpdateTotalProgress();
        UpdateStatus();
        CommandManager.InvalidateRequerySuggested();
    }

    private void OnTaskPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(TaskItemViewModel.Progress))
            UpdateTotalProgress();
    }

    private static ConversionCategory GuessCategory(string extension)
    {
        var video = new[] { "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg" };
        var audio = new[] { "mp3", "aac", "flac", "wav", "ogg", "m4a", "wma", "opus" };
        var image = new[] { "jpg", "jpeg", "png", "webp", "bmp", "gif", "tiff", "tif" };
        var doc = new[] { "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "html", "htm" };

        if (video.Contains(extension)) return ConversionCategory.Video;
        if (audio.Contains(extension)) return ConversionCategory.Audio;
        if (image.Contains(extension)) return ConversionCategory.Image;
        if (doc.Contains(extension)) return ConversionCategory.Document;
        return ConversionCategory.Video;
    }

    private static string CategoryToString(ConversionCategory category) => category switch
    {
        ConversionCategory.Video => "视频",
        ConversionCategory.Audio => "音频",
        ConversionCategory.Image => "图片",
        ConversionCategory.Document => "文档",
        _ => "其他"
    };

    private static ConversionCategory? StringToCategory(string name) => name switch
    {
        "视频" => ConversionCategory.Video,
        "音频" => ConversionCategory.Audio,
        "图片" => ConversionCategory.Image,
        "文档" => ConversionCategory.Document,
        _ => null
    };
}
