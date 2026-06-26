using System.IO;

namespace FluxForm.WPF.ViewModels;

public sealed class PendingBatchFileViewModel : ObservableObject
{
    private string _inputPath = string.Empty;
    private string _fileName = string.Empty;
    private long _fileSizeBytes;
    private string _summary = string.Empty;

    public string InputPath
    {
        get => _inputPath;
        set
        {
            if (SetProperty(ref _inputPath, value) && string.IsNullOrWhiteSpace(FileName))
                FileName = Path.GetFileName(value);
        }
    }

    public string FileName
    {
        get => _fileName;
        set => SetProperty(ref _fileName, value);
    }

    public long FileSizeBytes
    {
        get => _fileSizeBytes;
        set => SetProperty(ref _fileSizeBytes, value);
    }

    public string Summary
    {
        get => _summary;
        set => SetProperty(ref _summary, value);
    }
}
