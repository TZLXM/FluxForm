using System.Collections.Generic;
using FluxForm.Core.Models;
using FluxForm.WPF.ViewModels;

namespace FluxForm.Tests;

public class MainViewModelBatchFlowTests
{
    [Fact]
    public void TryAddFile_WhenCategoryMatches_AddsFileAndPreservesBatchConfiguration()
    {
        var batch = new PendingBatchViewModel();

        var firstAccepted = batch.TryAddFile("C:/media/intro.mp4", ConversionCategory.Video, 1024, "1080p H.264");
        batch.OutputFormat = "mp4";
        batch.OutputDirectory = "C:/output";
        batch.SetOption("crf", "23");

        var secondAccepted = batch.TryAddFile("C:/media/trailer.mkv", ConversionCategory.Video, 2048, "4K HEVC");

        Assert.True(firstAccepted);
        Assert.True(secondAccepted);
        Assert.Equal(ConversionCategory.Video, batch.Category);
        Assert.Equal("mp4", batch.OutputFormat);
        Assert.Equal("C:/output", batch.OutputDirectory);
        Assert.Equal("23", batch.Options["crf"]);
        Assert.Collection(
            batch.Files,
            file => AssertPendingFile(file, "C:/media/intro.mp4", "intro.mp4", 1024, "1080p H.264"),
            file => AssertPendingFile(file, "C:/media/trailer.mkv", "trailer.mkv", 2048, "4K HEVC"));
        Assert.Equal(string.Empty, batch.ValidationMessage);
    }

    [Fact]
    public void TryAddFile_WhenCategoryMixed_RejectsFileAndSetsChineseValidationMessage()
    {
        var batch = new PendingBatchViewModel();
        batch.TryAddFile("C:/media/intro.mp4", ConversionCategory.Video, 1024, "1080p H.264");

        var accepted = batch.TryAddFile("C:/media/song.mp3", ConversionCategory.Audio, 512, "320kbps");

        Assert.False(accepted);
        Assert.Single(batch.Files);
        Assert.Equal(ConversionCategory.Video, batch.Category);
        Assert.Equal("当前批次只支持同类型文件，请分别添加视频、音频、图片或文档文件。", batch.ValidationMessage);
    }

    [Fact]
    public void SetOption_UsesCaseInsensitiveDictionaryAndOverwritesExistingValue()
    {
        var batch = new PendingBatchViewModel();

        batch.SetOption("CRF", "23");
        batch.SetOption("crf", "19");

        Assert.Single(batch.Options);
        Assert.True(batch.Options.ContainsKey("CRF"));
        Assert.Equal("19", batch.Options["crf"]);
    }

    [Fact]
    public void Reset_ClearsFilesCategoryOutputOptionsAndValidationState()
    {
        var batch = new PendingBatchViewModel();
        batch.TryAddFile("C:/docs/spec.pdf", ConversionCategory.Document, 4096, "A4 PDF");
        batch.OutputFormat = "pdf";
        batch.OutputDirectory = "D:/exports";
        batch.SetOption("dpi", "300");
        batch.TryAddFile("C:/media/song.mp3", ConversionCategory.Audio, 512, "320kbps");

        batch.Reset();

        Assert.Empty(batch.Files);
        Assert.Null(batch.Category);
        Assert.Equal(string.Empty, batch.OutputFormat);
        Assert.Equal(string.Empty, batch.OutputDirectory);
        Assert.Empty(batch.Options);
        Assert.Equal(string.Empty, batch.ValidationMessage);
    }

    [Fact]
    public void BatchItem_updates_counts_and_progress_from_child_tasks()
    {
        var batch = new BatchItemViewModel
        {
            BatchId = "B001",
            Category = ConversionCategory.Video,
            ConfigSummary = "MP4 / H.264 / 1080p / 30fps"
        };

        batch.Tasks.Add(new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending, Progress = 0, ParameterSummary = "H.264 · 1080p" });
        batch.Tasks.Add(new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Succeeded, Progress = 100, ParameterSummary = "H.264 · 1080p" });
        batch.Tasks.Add(new TaskItemViewModel { FileName = "c.mp4", Status = ConversionStatus.Failed, Progress = 0, ParameterSummary = "H.264 · 1080p" });

        batch.Refresh();

        Assert.Equal(3, batch.TotalCount);
        Assert.Equal(1, batch.PendingCount);
        Assert.Equal(1, batch.SucceededCount);
        Assert.Equal(1, batch.FailedCount);
        Assert.Equal(33.333333333333336, batch.TotalProgress, 6);
    }

    [Fact]
    public void BatchItem_updates_statistics_when_child_status_changes()
    {
        var pendingTask = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending, Progress = 0 };
        var runningTask = new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Running, Progress = 50 };
        var batch = new BatchItemViewModel();

        batch.Tasks.Add(pendingTask);
        batch.Tasks.Add(runningTask);

        Assert.Equal(2, batch.TotalCount);
        Assert.Equal(1, batch.PendingCount);
        Assert.Equal(1, batch.RunningCount);
        Assert.Equal(0, batch.SucceededCount);

        pendingTask.Status = ConversionStatus.Succeeded;

        Assert.Equal(0, batch.PendingCount);
        Assert.Equal(1, batch.RunningCount);
        Assert.Equal(1, batch.SucceededCount);
        Assert.Equal(25, batch.TotalProgress, 6);
    }

    [Fact]
    public void BatchItem_updates_total_progress_when_child_progress_changes()
    {
        var firstTask = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Running, Progress = 20 };
        var secondTask = new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Running, Progress = 40 };
        var batch = new BatchItemViewModel();

        batch.Tasks.Add(firstTask);
        batch.Tasks.Add(secondTask);

        Assert.Equal(30, batch.TotalProgress, 6);

        secondTask.Progress = 100;

        Assert.Equal(60, batch.TotalProgress, 6);
    }

    [Fact]
    public void BatchItem_updates_statistics_when_tasks_are_added_or_removed()
    {
        var firstTask = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending, Progress = 0 };
        var secondTask = new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Cancelled, Progress = 10 };
        var batch = new BatchItemViewModel();

        batch.Tasks.Add(firstTask);

        Assert.Equal(1, batch.TotalCount);
        Assert.Equal(1, batch.PendingCount);
        Assert.Equal(0, batch.FailedCount);
        Assert.Equal(0, batch.TotalProgress, 6);

        batch.Tasks.Add(secondTask);

        Assert.Equal(2, batch.TotalCount);
        Assert.Equal(1, batch.PendingCount);
        Assert.Equal(1, batch.FailedCount);
        Assert.Equal(5, batch.TotalProgress, 6);

        batch.Tasks.Remove(firstTask);

        Assert.Equal(1, batch.TotalCount);
        Assert.Equal(0, batch.PendingCount);
        Assert.Equal(1, batch.FailedCount);
        Assert.Equal(10, batch.TotalProgress, 6);
    }

    private static void AssertPendingFile(
        PendingBatchFileViewModel file,
        string inputPath,
        string fileName,
        long fileSizeBytes,
        string summary)
    {
        Assert.Equal(inputPath, file.InputPath);
        Assert.Equal(fileName, file.FileName);
        Assert.Equal(fileSizeBytes, file.FileSizeBytes);
        Assert.Equal(summary, file.Summary);
    }
}
