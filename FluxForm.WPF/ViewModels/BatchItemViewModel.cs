using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public class BatchItemViewModel : ObservableObject
{
    private double _totalProgress;
    private bool _isExpanded;

    public BatchItemViewModel()
    {
        Tasks.CollectionChanged += OnTasksCollectionChanged;
    }

    public string BatchId { get; set; } = string.Empty;
    public ConversionCategory Category { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public string ConfigSummary { get; set; } = string.Empty;
    public ObservableCollection<TaskItemViewModel> Tasks { get; } = new();

    public int TotalCount { get; private set; }
    public int PendingCount { get; private set; }
    public int RunningCount { get; private set; }
    public int SucceededCount { get; private set; }
    public int FailedCount { get; private set; }

    public double TotalProgress
    {
        get => _totalProgress;
        private set => SetProperty(ref _totalProgress, value);
    }

    public bool IsExpanded
    {
        get => _isExpanded;
        set => SetProperty(ref _isExpanded, value);
    }

    public void Refresh()
    {
        TotalCount = Tasks.Count;
        PendingCount = Tasks.Count(t => t.Status == ConversionStatus.Pending);
        RunningCount = Tasks.Count(t => t.Status == ConversionStatus.Running);
        SucceededCount = Tasks.Count(t => t.Status == ConversionStatus.Succeeded);
        FailedCount = Tasks.Count(t => t.Status == ConversionStatus.Failed || t.Status == ConversionStatus.Cancelled);
        TotalProgress = Tasks.Count == 0 ? 0 : Tasks.Average(t => t.Progress);

        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(PendingCount));
        OnPropertyChanged(nameof(RunningCount));
        OnPropertyChanged(nameof(SucceededCount));
        OnPropertyChanged(nameof(FailedCount));
    }

    private void OnTasksCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.OldItems is not null)
        {
            foreach (TaskItemViewModel task in e.OldItems)
            {
                task.PropertyChanged -= OnTaskPropertyChanged;
            }
        }

        if (e.NewItems is not null)
        {
            foreach (TaskItemViewModel task in e.NewItems)
            {
                task.PropertyChanged += OnTaskPropertyChanged;
            }
        }

        Refresh();
    }

    private void OnTaskPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(TaskItemViewModel.Status) or nameof(TaskItemViewModel.Progress))
        {
            Refresh();
        }
    }
}
