using System.Collections.ObjectModel;
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
    private bool _isBusy;

    public ObservableCollection<TaskItemViewModel> Tasks { get; } = new();
    public ObservableCollection<string> Categories { get; } = new() { "全部", "Video", "Audio", "Image", "Document" };
    public ObservableCollection<string> AvailableFormats { get; } = new();

    public string SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (SetProperty(ref _selectedCategory, value))
            {
                RefreshFormats();
                FilterTasks();
            }
        }
    }

    public string LogText
    {
        get => _logText;
        set => SetProperty(ref _logText, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    public RelayCommand AddFilesCommand { get; }
    public RelayCommand ClearCommand { get; }
    public RelayCommand StartCommand { get; }
    public RelayCommand OpenOutputCommand { get; }

    public MainViewModel()
    {
        var toolsDir = Path.Combine(AppContext.BaseDirectory, "tools");
        _dependencyManager = new DependencyManager(toolsDir, new Progress<string>(msg => AppendLog(msg)));
        _conversionService = new ConversionService(_dependencyManager);

        AddFilesCommand = new RelayCommand(_ => AddFiles());
        ClearCommand = new RelayCommand(_ => ClearTasks(), _ => Tasks.Count > 0 && !IsBusy);
        StartCommand = new RelayCommand(_ => StartConversion(), _ => Tasks.Count > 0 && !IsBusy);
        OpenOutputCommand = new RelayCommand(p => OpenOutput(p?.ToString()));

        BindingOperations.EnableCollectionSynchronization(Tasks, new object());
        RefreshFormats();
    }

    private void RefreshFormats()
    {
        AvailableFormats.Clear();
        var category = SelectedCategory switch
        {
            "Video" => ConversionCategory.Video,
            "Audio" => ConversionCategory.Audio,
            "Image" => ConversionCategory.Image,
            "Document" => ConversionCategory.Document,
            _ => (ConversionCategory?)null
        };

        foreach (var format in _conversionService.GetFormats(category).Select(f => f.Extension).Distinct().OrderBy(x => x))
            AvailableFormats.Add(format);
    }

    private void FilterTasks()
    {
        // UI can filter via CollectionView; keep simple here
    }

    public void AddFiles(IEnumerable<string> files)
    {
        foreach (var file in files)
        {
            if (!File.Exists(file)) continue;
            var ext = Path.GetExtension(file).TrimStart('.').ToLowerInvariant();
            var category = GuessCategory(ext);
            var defaultOutput = category switch
            {
                ConversionCategory.Video => "mp4",
                ConversionCategory.Audio => "mp3",
                ConversionCategory.Image => "png",
                ConversionCategory.Document => "pdf",
                _ => ext
            };

            var dir = Path.GetDirectoryName(file) ?? "";
            var output = Path.Combine(dir, Path.GetFileNameWithoutExtension(file) + "_converted." + defaultOutput);

            var task = new TaskItemViewModel
            {
                FileName = Path.GetFileName(file),
                InputPath = file,
                InputFormat = ext,
                OutputFormat = defaultOutput,
                OutputPath = output,
                Category = category,
                Status = ConversionStatus.Pending,
                Message = "等待中"
            };
            Tasks.Add(task);
        }
        OnPropertyChanged(nameof(Tasks));
        CommandManager.InvalidateRequerySuggested();
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

    private void ClearTasks()
    {
        Tasks.Clear();
        OnPropertyChanged(nameof(Tasks));
        CommandManager.InvalidateRequerySuggested();
    }

    private async void StartConversion()
    {
        IsBusy = true;
        CommandManager.InvalidateRequerySuggested();
        AppendLog("开始转换任务...");

        foreach (var task in Tasks.Where(t => t.Status == ConversionStatus.Pending))
        {
            task.Status = ConversionStatus.Running;
            task.Message = "转换中...";

            var progress = new Progress<ProgressInfo>(p =>
            {
                task.Progress = p.Percent;
                task.Message = p.Message;
                task.Status = p.Status;
            });

            try
            {
                var result = await _conversionService.ConvertAsync(task.ToModel(), progress);
                task.Status = result.Status;
                task.Message = result.Status == ConversionStatus.Succeeded
                    ? $"完成 ({result.Duration.TotalSeconds:F1}s)"
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

        IsBusy = false;
        CommandManager.InvalidateRequerySuggested();
        AppendLog("所有任务处理完毕。");
    }

    private void OpenOutput(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
    }

    private void AppendLog(string message)
    {
        LogText += $"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}";
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
}
