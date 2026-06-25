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
    private string _statusText = "就绪";
    private string _logText = string.Empty;
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

    public PendingBatchViewModel PendingBatch { get; } = new();
    public ObservableCollection<BatchItemViewModel> Batches { get; } = new();
    public ObservableCollection<string> Categories { get; } = new() { "全部", "视频", "音频", "图片", "文档" };
    public ObservableCollection<FormatPreset> FormatPresets { get; } = new();
    public ICollectionView TasksView { get; }

    public bool CanAddNewTasks => !IsBusy && Batches.Count == 0;
    public int TotalTaskCount => Batches.Sum(b => b.Tasks.Count);
    public bool HasTasks => TotalTaskCount > 0;
    public bool IsEmpty => TotalTaskCount == 0;
    public bool NoFormatPresets => FormatPresets.Count == 0;

    public RelayCommand AddFilesCommand { get; }
    public RelayCommand AddFolderCommand { get; }
    public RelayCommand EnqueuePendingBatchCommand { get; }
    public RelayCommand RetryFailedTasksCommand { get; }
    public RelayCommand ClearCommand { get; }
    public RelayCommand StartCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand SetOutputDirectoryCommand { get; }
    public RelayCommand<TaskItemViewModel> RemoveTaskCommand { get; }
    public RelayCommand<string> ApplyFormatCommand { get; }
    public RelayCommand OpenOutputCommand { get; }

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
        get => PendingBatch.OutputDirectory;
        set
        {
            if (PendingBatch.OutputDirectory == value)
                return;

            PendingBatch.OutputDirectory = value;
            OnPropertyChanged();
            UpdateStatus();
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
                OnPropertyChanged(nameof(CanAddNewTasks));
                UpdateStatus();
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string LogText
    {
        get => _logText;
        set => SetProperty(ref _logText, value);
    }

    public MainViewModel()
    {
        var toolsDir = Path.Combine(AppContext.BaseDirectory, "tools");
        _dependencyManager = new DependencyManager(toolsDir, new Progress<string>(AppendLog));
        _conversionService = new ConversionService(_dependencyManager);

        Batches.CollectionChanged += OnBatchesCollectionChanged;
        PendingBatch.PropertyChanged += OnPendingBatchPropertyChanged;

        TasksView = CollectionViewSource.GetDefaultView(new ObservableCollection<TaskItemViewModel>());

        AddFilesCommand = new RelayCommand(_ => AddFiles());
        AddFolderCommand = new RelayCommand(_ => AddFolder());
        EnqueuePendingBatchCommand = new RelayCommand(_ => EnqueuePendingBatch(), _ => !IsBusy);
        RetryFailedTasksCommand = new RelayCommand(_ => RetryFailedTasks(), _ => !IsBusy && Batches.SelectMany(b => b.Tasks).Any(t => t.Status == ConversionStatus.Failed));
        ClearCommand = new RelayCommand(_ => ClearTasks(), _ => HasTasks && !IsBusy);
        StartCommand = new RelayCommand(_ => StartConversion(), _ => HasTasks && !IsBusy);
        CancelCommand = new RelayCommand(_ => CancelConversion(), _ => IsBusy);
        SetOutputDirectoryCommand = new RelayCommand(_ => SetOutputDirectory());
        RemoveTaskCommand = new RelayCommand<TaskItemViewModel>(task => RemoveTask(task), _ => !IsBusy);
        ApplyFormatCommand = new RelayCommand<string>(format => ApplyFormat(format));
        OpenOutputCommand = new RelayCommand(path => OpenOutput(path?.ToString()));

        RefreshFormats();
        UpdateStatus();
    }

    public void AddFiles(IEnumerable<string> files)
    {
        foreach (var file in files)
        {
            if (!File.Exists(file))
                continue;

            var ext = Path.GetExtension(file).TrimStart('.').ToLowerInvariant();
            var category = GuessCategory(ext);
            var summary = Path.GetExtension(file).TrimStart('.').ToUpperInvariant();

            if (PendingBatch.TryAddFile(file, category, new FileInfo(file).Length, summary) && string.IsNullOrWhiteSpace(PendingBatch.OutputFormat))
            {
                PendingBatch.OutputFormat = _defaultFormats.GetValueOrDefault(category, ext);
            }
        }

        OnPropertyChanged(nameof(HasTasks));
        OnPropertyChanged(nameof(IsEmpty));
        UpdateStatus();
        CommandManager.InvalidateRequerySuggested();
    }

    public void EnqueuePendingBatch()
    {
        if (PendingBatch.Category == null || PendingBatch.Files.Count == 0 || string.IsNullOrWhiteSpace(PendingBatch.OutputFormat))
            return;

        var batchId = $"B{Batches.Count + 1:000}";
        var batch = new BatchItemViewModel
        {
            BatchId = batchId,
            Category = PendingBatch.Category.Value,
            ConfigSummary = BuildBatchSummary(PendingBatch)
        };

        foreach (var file in PendingBatch.Files)
        {
            batch.Tasks.Add(CreateTask(batchId, file));
        }

        batch.Refresh();
        Batches.Add(batch);
        PendingBatch.Reset();
        OnPropertyChanged(nameof(OutputDirectory));
        RefreshAllBatchStats();
    }

    public void MarkUnfinishedTasksAsFailed()
    {
        foreach (var batch in Batches)
        {
            foreach (var task in batch.Tasks.Where(t => t.Status is ConversionStatus.Pending or ConversionStatus.Running or ConversionStatus.Cancelled))
            {
                task.Status = ConversionStatus.Failed;
                task.Message = "失败：任务已停止";
                task.Progress = 0;
            }

            batch.Refresh();
        }

        RefreshAllBatchStats();
    }

    private void RetryFailedTasks()
    {
        foreach (var task in Batches.SelectMany(batch => batch.Tasks).Where(task => task.Status == ConversionStatus.Failed))
        {
            task.Status = ConversionStatus.Pending;
            task.Message = "等待中";
            task.Progress = 0;
        }

        RefreshAllBatchStats();
    }

    private void RefreshFormats()
    {
        FormatPresets.Clear();
        var category = StringToCategory(SelectedCategory);
        if (category == null)
        {
            OnPropertyChanged(nameof(NoFormatPresets));
            return;
        }

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
        if (string.IsNullOrWhiteSpace(format))
            return;

        var category = StringToCategory(SelectedCategory);
        if (category != null)
            _defaultFormats[category.Value] = format;

        if (PendingBatch.Category == category || (category == null && PendingBatch.Category != null))
            PendingBatch.OutputFormat = format;

        AppendLog($"已将 {(category == null ? "全部" : CategoryToString(category.Value))} 目标格式设为 {format.ToUpperInvariant()}");
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

    private void AddFolder()
    {
        var dialog = new OpenFolderDialog
        {
            Title = "选择包含待转换文件的文件夹",
            Multiselect = false
        };

        if (dialog.ShowDialog() != true)
            return;

        var files = Directory.EnumerateFiles(dialog.FolderName);
        AddFiles(files);
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
        var dir = !string.IsNullOrWhiteSpace(PendingBatch.OutputDirectory)
            ? PendingBatch.OutputDirectory
            : Path.GetDirectoryName(inputPath)!;
        var fileName = Path.GetFileNameWithoutExtension(inputPath) + "_converted." + outputFormat;
        return Path.Combine(dir, fileName);
    }

    private TaskItemViewModel CreateTask(string batchId, PendingBatchFileViewModel file)
    {
        var inputFormat = Path.GetExtension(file.InputPath).TrimStart('.').ToLowerInvariant();
        var outputFormat = PendingBatch.OutputFormat;

        return new TaskItemViewModel
        {
            BatchId = batchId,
            FileName = file.FileName,
            InputPath = file.InputPath,
            InputFormat = inputFormat,
            OutputFormat = outputFormat,
            OutputPath = GenerateOutputPath(file.InputPath, outputFormat),
            Category = PendingBatch.Category ?? GuessCategory(inputFormat),
            Status = ConversionStatus.Pending,
            Message = "等待中",
            ParameterSummary = file.Summary
        };
    }

    private static string BuildBatchSummary(PendingBatchViewModel pendingBatch)
    {
        var parts = new List<string>();

        if (!string.IsNullOrWhiteSpace(pendingBatch.OutputFormat))
            parts.Add(pendingBatch.OutputFormat.ToUpperInvariant());

        foreach (var option in pendingBatch.Options)
            parts.Add($"{option.Key}={option.Value}");

        return parts.Count > 0 ? string.Join(" / ", parts) : "默认配置";
    }

    private void RemoveTask(TaskItemViewModel? task)
    {
        if (task == null)
            return;

        var batch = Batches.FirstOrDefault(item => item.Tasks.Contains(task));
        if (batch == null)
            return;

        batch.Tasks.Remove(task);
        if (batch.Tasks.Count == 0)
            Batches.Remove(batch);

        RefreshAllBatchStats();
    }

    private void ClearTasks()
    {
        Batches.Clear();
        RefreshAllBatchStats();
    }

    private async void StartConversion()
    {
        IsBusy = true;
        _cts = new CancellationTokenSource();
        CommandManager.InvalidateRequerySuggested();
        AppendLog("开始转换任务...");

        var pendingTasks = Batches.SelectMany(batch => batch.Tasks)
            .Where(task => task.Status is ConversionStatus.Pending or ConversionStatus.Failed)
            .ToList();
        var stopwatch = Stopwatch.StartNew();

        foreach (var task in pendingTasks)
        {
            if (_cts.IsCancellationRequested)
            {
                AppendLog("转换已取消，停止后续任务。");
                break;
            }

            var supportedFormats = _conversionService.GetFormats(task.Category)
                .Select(format => format.Extension)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (!supportedFormats.Contains(task.OutputFormat))
            {
                task.Status = ConversionStatus.Failed;
                task.Message = $"不支持的输出格式：{task.OutputFormat}";
                AppendLog($"{task.FileName}: {task.Message}");
                RefreshAllBatchStats();
                continue;
            }

            task.Status = ConversionStatus.Running;
            task.Message = "转换中...";

            var progress = new Progress<ProgressInfo>(info =>
            {
                task.Progress = info.Percent;
                task.Message = info.Message;
                task.Status = info.Status;
                RefreshAllBatchStats();
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

            RefreshAllBatchStats();
        }

        stopwatch.Stop();
        _cts.Dispose();
        _cts = null;
        IsBusy = false;
        RefreshAllBatchStats();
        CommandManager.InvalidateRequerySuggested();
        AppendLog($"所有任务处理完毕。总耗时：{stopwatch.Elapsed.TotalSeconds:F1}s");
        UpdateStatus();
    }

    private void CancelConversion()
    {
        _cts?.Cancel();
        AppendLog("用户请求取消转换...");
        MarkUnfinishedTasksAsFailed();
    }

    private void OpenOutput(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return;

        Process.Start("explorer.exe", $"/select,\"{path}\"");
    }

    private void AppendLog(string message)
    {
        LogText += $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
    }

    private void RefreshAllBatchStats()
    {
        foreach (var batch in Batches)
            batch.Refresh();

        OnPropertyChanged(nameof(CanAddNewTasks));
        OnPropertyChanged(nameof(TotalTaskCount));
        OnPropertyChanged(nameof(HasTasks));
        OnPropertyChanged(nameof(IsEmpty));
        UpdateTotalProgress();
        UpdateStatus();
        CommandManager.InvalidateRequerySuggested();
    }

    private void UpdateTotalProgress()
    {
        var tasks = Batches.SelectMany(batch => batch.Tasks).ToList();
        TotalProgress = tasks.Count > 0 ? tasks.Average(task => task.Progress) : 0;
    }

    private void UpdateStatus()
    {
        var batchCount = Batches.Count;
        var tasks = Batches.SelectMany(batch => batch.Tasks).ToList();
        var total = tasks.Count;
        var pending = tasks.Count(task => task.Status == ConversionStatus.Pending);
        var running = tasks.Count(task => task.Status == ConversionStatus.Running);
        var succeeded = tasks.Count(task => task.Status == ConversionStatus.Succeeded);
        var failed = tasks.Count(task => task.Status == ConversionStatus.Failed);
        var dir = string.IsNullOrWhiteSpace(PendingBatch.OutputDirectory) ? "与源文件相同" : PendingBatch.OutputDirectory;

        if (IsBusy)
        {
            StatusText = $"执行中 · 批次 {batchCount} · 运行 {running} · 待处理 {pending} · 完成 {succeeded} · 失败 {failed}";
        }
        else if (total == 0)
        {
            StatusText = PendingBatch.Files.Count == 0
                ? "就绪 · 点击“添加文件”或拖拽文件到此处"
                : $"待入队 {PendingBatch.Files.Count} 个文件 · 输出目录：{dir}";
        }
        else
        {
            StatusText = $"共 {batchCount} 个批次 / {total} 个任务 · 待处理 {pending} · 完成 {succeeded} · 失败 {failed} · 输出目录：{dir}";
        }
    }

    private void OnBatchesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.NewItems != null)
        {
            foreach (BatchItemViewModel batch in e.NewItems)
                batch.PropertyChanged += OnBatchPropertyChanged;
        }

        if (e.OldItems != null)
        {
            foreach (BatchItemViewModel batch in e.OldItems)
                batch.PropertyChanged -= OnBatchPropertyChanged;
        }

        RefreshAllBatchStats();
    }

    private void OnBatchPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(BatchItemViewModel.TotalProgress)
            or nameof(BatchItemViewModel.PendingCount)
            or nameof(BatchItemViewModel.RunningCount)
            or nameof(BatchItemViewModel.SucceededCount)
            or nameof(BatchItemViewModel.FailedCount))
        {
            UpdateTotalProgress();
            UpdateStatus();
        }
    }

    private void OnPendingBatchPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(PendingBatchViewModel.OutputDirectory))
            OnPropertyChanged(nameof(OutputDirectory));

        UpdateStatus();
        CommandManager.InvalidateRequerySuggested();
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
