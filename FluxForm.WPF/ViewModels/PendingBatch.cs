using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public sealed class PendingBatch
{
    private PendingBatch(IReadOnlyList<TaskItemViewModel> items)
    {
        Items = items;
    }

    public IReadOnlyList<TaskItemViewModel> Items { get; }

    public static PendingBatch Create(IEnumerable<TaskItemViewModel> tasks)
    {
        var items = tasks
            .Where(task => task.Status == ConversionStatus.Pending)
            .ToList();

        return new PendingBatch(items);
    }
}
