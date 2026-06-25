namespace FluxForm.WPF.ViewModels;

public sealed class MediaOptionViewModel : ObservableObject
{
    private string _key = string.Empty;
    private string _value = string.Empty;
    private string _label = string.Empty;
    private string _group = string.Empty;
    private bool _isAdvanced;

    public string Key
    {
        get => _key;
        set => SetProperty(ref _key, value);
    }

    public string Value
    {
        get => _value;
        set => SetProperty(ref _value, value);
    }

    public string Label
    {
        get => _label;
        set => SetProperty(ref _label, value);
    }

    public string Group
    {
        get => _group;
        set => SetProperty(ref _group, value);
    }

    public bool IsAdvanced
    {
        get => _isAdvanced;
        set => SetProperty(ref _isAdvanced, value);
    }
}
