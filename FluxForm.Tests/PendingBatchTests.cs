using FluxForm.Core.Models;
using FluxForm.WPF.ViewModels;

namespace FluxForm.Tests;

public class PendingBatchTests
{
    [Fact]
    public void Create_WhenTasksContainPendingAndNonPending_IncludesOnlyPendingTasks()
    {
        var pendingA = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending };
        var running = new TaskItemViewModel { FileName = "b.mp3", Status = ConversionStatus.Running };
        var pendingB = new TaskItemViewModel { FileName = "c.png", Status = ConversionStatus.Pending };
        var failed = new TaskItemViewModel { FileName = "d.pdf", Status = ConversionStatus.Failed };

        var batch = PendingBatch.Create(new[] { pendingA, running, pendingB, failed });

        Assert.Equal(2, batch.Items.Count);
        Assert.Same(pendingA, batch.Items[0]);
        Assert.Same(pendingB, batch.Items[1]);
    }

    [Fact]
    public void Create_WhenNoPendingTasks_ReturnsEmptyBatch()
    {
        var succeeded = new TaskItemViewModel { FileName = "done.mp4", Status = ConversionStatus.Succeeded };
        var failed = new TaskItemViewModel { FileName = "fail.mp3", Status = ConversionStatus.Failed };

        var batch = PendingBatch.Create(new[] { succeeded, failed });

        Assert.Empty(batch.Items);
    }

    [Fact]
    public void Create_WhenTasksIsNull_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => PendingBatch.Create(null!));
    }
}
