using System.Collections.Generic;
using System.IO;
using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public class TaskItemViewModel : ObservableObject
{
    private ConversionStatus _status;
    private double _progress;
    private string _message = string.Empty;
    private string _outputFormat = string.Empty;
    private string _outputPath = string.Empty;

    public Guid Id { get; } = Guid.NewGuid();

    public string FileName { get; set; } = string.Empty;
    public string BatchId { get; set; } = string.Empty;
    public string InputPath { get; set; } = string.Empty;
    public string InputFormat { get; set; } = string.Empty;
    public ConversionCategory Category { get; set; }
    public string ParameterSummary { get; set; } = string.Empty;
    public Dictionary<string, string> Options { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public string OutputFormat
    {
        get => _outputFormat;
        set
        {
            if (SetProperty(ref _outputFormat, value))
            {
                if (!string.IsNullOrWhiteSpace(OutputPath))
                {
                    var dir = Path.GetDirectoryName(OutputPath)!;
                    var fileName = Path.GetFileNameWithoutExtension(OutputPath) + "." + value;
                    OutputPath = Path.Combine(dir, fileName);
                }
            }
        }
    }

    public string OutputPath
    {
        get => _outputPath;
        set => SetProperty(ref _outputPath, value);
    }

    public ConversionStatus Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }

    public double Progress
    {
        get => _progress;
        set => SetProperty(ref _progress, value);
    }

    public string Message
    {
        get => _message;
        set => SetProperty(ref _message, value);
    }

    public string DisplayCategory => Category.ToString();

    public Core.Models.ConversionTask ToModel()
    {
        return new Core.Models.ConversionTask
        {
            InputPath = InputPath,
            OutputPath = OutputPath,
            InputFormat = InputFormat,
            OutputFormat = OutputFormat,
            Category = Category,
            Options = new Dictionary<string, string>(Options, StringComparer.OrdinalIgnoreCase)
        };
    }
}
