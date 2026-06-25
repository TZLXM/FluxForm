using System.Collections.Generic;
using System.Collections.ObjectModel;
using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public sealed class PendingBatchViewModel : ObservableObject
{
    private const string MixedCategoryValidationMessage = "当前批次只支持同类型文件，请分别添加视频、音频、图片或文档文件。";

    private ConversionCategory? _category;
    private string _outputFormat = string.Empty;
    private string _outputDirectory = string.Empty;
    private string _validationMessage = string.Empty;

    public ObservableCollection<PendingBatchFileViewModel> Files { get; } = new();
    public Dictionary<string, string> Options { get; } = new(StringComparer.OrdinalIgnoreCase);

    public ConversionCategory? Category
    {
        get => _category;
        private set => SetProperty(ref _category, value);
    }

    public string OutputFormat
    {
        get => _outputFormat;
        set => SetProperty(ref _outputFormat, value);
    }

    public string OutputDirectory
    {
        get => _outputDirectory;
        set => SetProperty(ref _outputDirectory, value);
    }

    public string ValidationMessage
    {
        get => _validationMessage;
        private set => SetProperty(ref _validationMessage, value);
    }

    public bool TryAddFile(string inputPath, ConversionCategory category, long fileSizeBytes, string summary)
    {
        if (Category is { } existingCategory && existingCategory != category)
        {
            ValidationMessage = MixedCategoryValidationMessage;
            return false;
        }

        Category = category;
        ValidationMessage = string.Empty;
        Files.Add(new PendingBatchFileViewModel
        {
            InputPath = inputPath,
            FileName = System.IO.Path.GetFileName(inputPath),
            FileSizeBytes = fileSizeBytes,
            Summary = summary
        });

        return true;
    }

    public void SetOption(string key, string value)
    {
        Options[key] = value;
    }

    public void Reset()
    {
        Files.Clear();
        Category = null;
        OutputFormat = string.Empty;
        OutputDirectory = string.Empty;
        Options.Clear();
        ValidationMessage = string.Empty;
    }
}
