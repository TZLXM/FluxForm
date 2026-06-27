using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using FluxForm.Core.Models;
using FluxForm.Core.Services;
using FluxForm.WPF.ViewModels;

namespace FluxForm.Tests;

public class MainViewModelBatchFlowTests
{
    [Fact]
    public void MainViewModel_adds_pending_batch_to_queue_and_clears_pending_state()
    {
        var vm = new MainViewModel();

        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
        vm.PendingBatch.OutputFormat = "mkv";
        vm.PendingBatch.OutputDirectory = "D:/out";
        vm.PendingBatch.SetOption("videoCodec", "libx264");
        vm.PendingBatch.SetOption("preset", "medium");
        vm.SetPendingOption("frameRate", "30");

        vm.EnqueuePendingBatch();

        var batch = Assert.Single(vm.Batches);
        var task = Assert.Single(batch.Tasks);
        Assert.Equal(ConversionCategory.Video, task.Category);
        Assert.StartsWith("D:/out", task.OutputPath);
        Assert.EndsWith("demo_converted.mkv", task.OutputPath);
        Assert.Equal(3, task.Options.Count);
        Assert.Equal("libx264", task.Options["videoCodec"]);
        Assert.Equal("medium", task.Options["preset"]);
        Assert.Equal("30", task.Options["frameRate"]);
        Assert.Empty(vm.PendingBatch.Files);
        Assert.True(vm.IsPendingBatchEmpty);
        Assert.Equal(string.Empty, vm.PendingFrameRate);
        Assert.Equal(string.Empty, vm.PendingAspectRatio);
        Assert.False(vm.CanAddNewTasks);
        Assert.Equal(1, vm.TotalTaskCount);
    }

    [Fact]
    public void PendingBatch_state_is_independent_from_queued_batch_empty_state()
    {
        var vm = new MainViewModel();
        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4");
        vm.PendingBatch.OutputFormat = "mkv";

        vm.EnqueuePendingBatch();

        Assert.False(vm.IsEmpty);
        Assert.True(vm.IsPendingBatchEmpty);
        Assert.Equal("请添加同类型文件开始配置", vm.PendingFileSummary);
    }

    [Fact]
    public void Pending_category_refreshes_format_presets_for_that_category()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);

        Assert.Empty(vm.FormatPresets);

        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4");

        Assert.Collection(
            vm.FormatPresets.OrderBy(x => x.Extension),
            preset => Assert.Equal("mkv", preset.Extension),
            preset => Assert.Equal("mp4", preset.Extension));
    }

    [Fact]
    public void Selecting_output_format_does_not_rebuild_format_presets()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);
        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4");
        var collectionChangedCount = 0;
        vm.FormatPresets.CollectionChanged += (_, _) => collectionChangedCount++;

        vm.PendingBatch.OutputFormat = "mkv";

        Assert.Equal("mkv", vm.PendingBatch.OutputFormat);
        Assert.True(vm.CanEnqueuePendingBatch);
        Assert.Equal(0, collectionChangedCount);
    }

    [Fact]
    public void ClearPendingBatchCommand_clears_pending_configuration_without_touching_queue()
    {
        var vm = new MainViewModel();
        var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
        batch.Tasks.Add(new TaskItemViewModel { FileName = "queued.mp4", Status = ConversionStatus.Pending });
        vm.Batches.Add(batch);

        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4");
        vm.PendingBatch.OutputFormat = "mkv";
        vm.OutputDirectory = "D:/out";
        vm.PendingFrameRate = "60";

        Assert.True(vm.ClearPendingBatchCommand.CanExecute(null));

        vm.ClearPendingBatchCommand.Execute(null);

        Assert.Single(vm.Batches);
        Assert.Empty(vm.PendingBatch.Files);
        Assert.Null(vm.PendingBatch.Category);
        Assert.Equal(string.Empty, vm.PendingBatch.OutputFormat);
        Assert.Equal(string.Empty, vm.OutputDirectory);
        Assert.Equal(string.Empty, vm.PendingFrameRate);
        Assert.False(vm.CanEnqueuePendingBatch);
        Assert.Empty(vm.FormatPresets);
        Assert.Empty(vm.CommonFormatPresets);
    }

    [Fact]
    public void Common_format_presets_are_limited_for_audio_and_image_batches()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);

        vm.PendingBatch.TryAddFile("D:/media/song.wav", ConversionCategory.Audio, 1024, "WAV");

        Assert.Equal(new[] { "wav", "mp3", "flac", "ogg" }, vm.CommonFormatPresets.Select(x => x.Extension));

        vm.PendingBatch.Reset();
        vm.PendingBatch.TryAddFile("D:/media/photo.webp", ConversionCategory.Image, 1024, "WEBP");

        Assert.Equal(new[] { "png", "jpg" }, vm.CommonFormatPresets.Select(x => x.Extension));
    }

    [Fact]
    public void ApplyFormatCommand_accepts_non_first_common_format()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);
        vm.PendingBatch.TryAddFile("D:/media/song.wav", ConversionCategory.Audio, 1024, "WAV");

        vm.ApplyFormatCommand.Execute("flac");

        Assert.Equal("flac", vm.PendingBatch.OutputFormat);
        Assert.True(vm.CanEnqueuePendingBatch);
    }

    [Fact]
    public void Pending_option_properties_update_options_and_clear_on_reset()
    {
        var vm = new MainViewModel();

        vm.PendingFrameRate = "60";
        vm.PendingAspectRatio = "16:9";

        Assert.Equal("60", vm.PendingBatch.Options["frameRate"]);
        Assert.Equal("16:9", vm.PendingBatch.Options["aspectRatio"]);

        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4");
        vm.PendingBatch.OutputFormat = "mp4";
        vm.EnqueuePendingBatch();

        Assert.Equal(string.Empty, vm.PendingFrameRate);
        Assert.Equal(string.Empty, vm.PendingAspectRatio);
        Assert.Empty(vm.PendingBatch.Options);
    }


    [Fact]
    public void RetryFailedTask_resets_only_the_selected_failed_task()
    {
        var vm = new MainViewModel();
        var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
        var target = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Failed, Message = "失败", Progress = 42 };
        var otherFailed = new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Failed, Message = "失败", Progress = 17 };
        var succeeded = new TaskItemViewModel { FileName = "c.mp4", Status = ConversionStatus.Succeeded, Message = "完成", Progress = 100 };
        batch.Tasks.Add(target);
        batch.Tasks.Add(otherFailed);
        batch.Tasks.Add(succeeded);
        vm.Batches.Add(batch);

        vm.RetryFailedTask(target);

        Assert.Equal(ConversionStatus.Pending, target.Status);
        Assert.Equal("等待中", target.Message);
        Assert.Equal(0, target.Progress);
        Assert.Equal(ConversionStatus.Failed, otherFailed.Status);
        Assert.Equal(17, otherFailed.Progress);
        Assert.Equal(ConversionStatus.Succeeded, succeeded.Status);
    }

    [Fact]
    public void RetryFailedTask_ignores_non_failed_task()
    {
        var vm = new MainViewModel();
        var task = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Succeeded, Message = "完成", Progress = 100 };
        var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
        batch.Tasks.Add(task);
        vm.Batches.Add(batch);

        vm.RetryFailedTask(task);

        Assert.Equal(ConversionStatus.Succeeded, task.Status);
        Assert.Equal("完成", task.Message);
        Assert.Equal(100, task.Progress);
    }

    [Fact]
    public void AddFiles_while_busy_does_not_add_pending_files()
    {
        using var tempDir = new TempDir();
        var filePath = tempDir.CreateFile("demo.mp4");
        var vm = new MainViewModel();
        SetIsBusy(vm, true);

        vm.AddFiles(new[] { filePath });

        Assert.Empty(vm.PendingBatch.Files);
    }

    [Fact]
    public void EnqueuePendingBatch_while_busy_does_not_add_batch()
    {
        var vm = new MainViewModel();
        vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
        vm.PendingBatch.OutputFormat = "mkv";
        SetIsBusy(vm, true);

        vm.EnqueuePendingBatch();

        Assert.Empty(vm.Batches);
        Assert.Single(vm.PendingBatch.Files);
    }

    [Fact]
    public async Task StartConversion_processes_tasks_in_serial_order()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);
        AddBatch(vm, ("first.mp4", ConversionStatus.Succeeded, null), ("second.mp4", ConversionStatus.Succeeded, null));

        vm.StartCommand.Execute(null);
        await service.WaitForCallCountAsync(1);

        Assert.Equal(new[] { "first.mp4" }, service.StartedFileNames);
        Assert.Equal(ConversionStatus.Running, vm.Batches[0].Tasks[0].Status);
        Assert.Equal(ConversionStatus.Pending, vm.Batches[0].Tasks[1].Status);

        service.CompleteNext(ConversionResult.Success(service.StartedTasks[0].Id, "D:/out/first.mp4", TimeSpan.FromSeconds(1)));
        await service.WaitForCallCountAsync(2);

        Assert.Equal(new[] { "first.mp4", "second.mp4" }, service.StartedFileNames);
        Assert.Equal(ConversionStatus.Succeeded, vm.Batches[0].Tasks[0].Status);
        Assert.Equal(ConversionStatus.Running, vm.Batches[0].Tasks[1].Status);

        service.CompleteNext(ConversionResult.Success(service.StartedTasks[1].Id, "D:/out/second.mp4", TimeSpan.FromSeconds(1)));
        await WaitUntilAsync(() => !vm.IsBusy);

        Assert.All(vm.Batches[0].Tasks, task => Assert.Equal(ConversionStatus.Succeeded, task.Status));
    }

    [Fact]
    public async Task CancelConversion_marks_unfinished_tasks_as_cancelled()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);
        AddBatch(vm, ("first.mp4", ConversionStatus.Succeeded, null), ("second.mp4", ConversionStatus.Succeeded, null), ("third.mp4", ConversionStatus.Succeeded, null));

        vm.StartCommand.Execute(null);
        await service.WaitForCallCountAsync(1);

        vm.CancelCommand.Execute(null);
        service.CompleteNext(ConversionResult.Cancelled(service.StartedTasks[0].Id));
        await WaitUntilAsync(() => !vm.IsBusy);

        var tasks = vm.Batches[0].Tasks;
        Assert.Equal(ConversionStatus.Cancelled, tasks[0].Status);
        Assert.Equal("已取消", tasks[0].Message);
        Assert.Equal(ConversionStatus.Cancelled, tasks[1].Status);
        Assert.Equal(ConversionStatus.Cancelled, tasks[2].Status);
    }

    [Fact]
    public async Task RetryFailedTask_returns_task_to_pending_and_requeues_it()
    {
        var service = new ControlledConversionService();
        var vm = CreateViewModel(service);
        AddBatch(vm, ("first.mp4", ConversionStatus.Succeeded, null), ("second.mp4", ConversionStatus.Failed, "转码失败"));

        vm.StartCommand.Execute(null);
        await service.WaitForCallCountAsync(1);
        service.CompleteNext(ConversionResult.Success(service.StartedTasks[0].Id, "D:/out/first.mp4", TimeSpan.FromSeconds(1)));
        await service.WaitForCallCountAsync(2);
        service.CompleteNext(ConversionResult.Failure(service.StartedTasks[1].Id, "转码失败", TimeSpan.FromSeconds(1)));
        await WaitUntilAsync(() => !vm.IsBusy);

        var failedTask = vm.Batches[0].Tasks[1];
        Assert.Equal(ConversionStatus.Failed, failedTask.Status);

        vm.RetryFailedTask(failedTask);

        Assert.Equal(ConversionStatus.Pending, failedTask.Status);
        Assert.Equal("等待中", failedTask.Message);
        Assert.Equal(0, failedTask.Progress);

        vm.StartCommand.Execute(null);
        await service.WaitForCallCountAsync(3);

        Assert.Equal("second.mp4", service.StartedFileNames.Last());
        service.CompleteNext(ConversionResult.Success(service.StartedTasks[2].Id, "D:/out/second.mp4", TimeSpan.FromSeconds(1)));
        await WaitUntilAsync(() => !vm.IsBusy && failedTask.Status == ConversionStatus.Succeeded);

        Assert.Equal(ConversionStatus.Succeeded, failedTask.Status);
    }

    [Fact]
    public void MainViewModel_stop_marks_unfinished_tasks_as_cancelled()
    {
        var vm = new MainViewModel();
        var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
        batch.Tasks.Add(new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Running });
        batch.Tasks.Add(new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Pending });
        batch.Tasks.Add(new TaskItemViewModel { FileName = "c.mp4", Status = ConversionStatus.Succeeded });
        vm.Batches.Add(batch);

        vm.MarkUnfinishedTasksAsCancelled();

        Assert.Equal(ConversionStatus.Cancelled, batch.Tasks[0].Status);
        Assert.Equal(ConversionStatus.Cancelled, batch.Tasks[1].Status);
        Assert.Equal(ConversionStatus.Succeeded, batch.Tasks[2].Status);
    }

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
        Assert.Equal(0, batch.CancelledCount);
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
        Assert.Equal(0, batch.FailedCount);
        Assert.Equal(1, batch.CancelledCount);
        Assert.Equal(5, batch.TotalProgress, 6);

        batch.Tasks.Remove(firstTask);

        Assert.Equal(1, batch.TotalCount);
        Assert.Equal(0, batch.PendingCount);
        Assert.Equal(0, batch.FailedCount);
        Assert.Equal(1, batch.CancelledCount);
        Assert.Equal(10, batch.TotalProgress, 6);
    }

    [Fact]
    public void TaskItem_exposes_localized_status_text()
    {
        var task = new TaskItemViewModel { Status = ConversionStatus.Pending };
        Assert.Equal("等待中", task.StatusText);

        task.Status = ConversionStatus.Running;
        Assert.Equal("转换中", task.StatusText);

        task.Status = ConversionStatus.Succeeded;
        Assert.Equal("已完成", task.StatusText);

        task.Status = ConversionStatus.Failed;
        Assert.Equal("失败", task.StatusText);

        task.Status = ConversionStatus.Cancelled;
        Assert.Equal("已取消", task.StatusText);
    }

    [Fact]
    public void StatusText_for_queued_tasks_separates_cancelled_count_and_omits_pending_output_directory()
    {
        var vm = new MainViewModel
        {
            OutputDirectory = "D:/pending-output"
        };
        var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
        batch.Tasks.Add(new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending });
        batch.Tasks.Add(new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Failed });
        batch.Tasks.Add(new TaskItemViewModel { FileName = "c.mp4", Status = ConversionStatus.Cancelled });

        vm.Batches.Add(batch);

        Assert.Contains("取消 1", vm.StatusText);
        Assert.Contains("失败 1", vm.StatusText);
        Assert.DoesNotContain("D:/pending-output", vm.StatusText);
    }

    [Fact]
    public void BatchItem_does_not_update_aggregate_values_after_removed_task_changes()
    {
        var removedTask = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending, Progress = 0 };
        var remainingTask = new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Succeeded, Progress = 100 };
        var batch = new BatchItemViewModel();

        batch.Tasks.Add(removedTask);
        batch.Tasks.Add(remainingTask);
        batch.Tasks.Remove(removedTask);

        Assert.Equal(1, batch.TotalCount);
        Assert.Equal(0, batch.PendingCount);
        Assert.Equal(1, batch.SucceededCount);
        Assert.Equal(100, batch.TotalProgress, 6);

        removedTask.Status = ConversionStatus.Running;
        removedTask.Progress = 50;

        Assert.Equal(1, batch.TotalCount);
        Assert.Equal(0, batch.PendingCount);
        Assert.Equal(0, batch.RunningCount);
        Assert.Equal(1, batch.SucceededCount);
        Assert.Equal(100, batch.TotalProgress, 6);
    }

    [Fact]
    public void BatchItem_does_not_update_aggregate_values_after_dispose()
    {
        var task = new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Pending, Progress = 0 };
        var batch = new BatchItemViewModel();

        batch.Tasks.Add(task);
        batch.Dispose();

        task.Status = ConversionStatus.Succeeded;
        task.Progress = 100;

        Assert.Equal(1, batch.TotalCount);
        Assert.Equal(1, batch.PendingCount);
        Assert.Equal(0, batch.SucceededCount);
        Assert.Equal(0, batch.TotalProgress, 6);
    }


    private static MainViewModel CreateViewModel(IConversionService service)
    {
        return new MainViewModel(service);
    }

    private static void AddBatch(MainViewModel vm, params (string fileName, ConversionStatus resultStatus, string? errorMessage)[] files)
    {
        var batch = new BatchItemViewModel
        {
            BatchId = "B001",
            Category = ConversionCategory.Video,
            ConfigSummary = "MP4"
        };

        foreach (var (fileName, _, _) in files)
        {
            batch.Tasks.Add(new TaskItemViewModel
            {
                BatchId = batch.BatchId,
                FileName = fileName,
                InputPath = $"D:/media/{fileName}",
                InputFormat = "mp4",
                OutputFormat = "mkv",
                OutputPath = $"D:/out/{Path.GetFileNameWithoutExtension(fileName)}_converted.mkv",
                Category = ConversionCategory.Video,
                Status = ConversionStatus.Pending,
                Message = "等待中"
            });
        }

        vm.Batches.Add(batch);
    }

    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000)
    {
        var start = Environment.TickCount64;
        while (!condition())
        {
            if (Environment.TickCount64 - start > timeoutMs)
                throw new TimeoutException("Condition was not met within the timeout.");

            await Task.Delay(20);
        }
    }

    private sealed class ControlledConversionService : IConversionService
    {
        private readonly Queue<TaskCompletionSource<ConversionResult>> _pending = new();
        private readonly TaskCompletionSource<bool> _callObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public List<ConversionTask> StartedTasks { get; } = new();
        public List<string> StartedFileNames { get; } = new();

        public Task<ConversionResult> ConvertAsync(ConversionTask task, IProgress<ProgressInfo>? progress = null, CancellationToken cancellationToken = default)
        {
            progress?.Report(new ProgressInfo
            {
                TaskId = task.Id,
                Status = ConversionStatus.Running,
                Percent = 5,
                Message = "转换中..."
            });

            StartedTasks.Add(task);
            StartedFileNames.Add(Path.GetFileName(task.InputPath));

            var tcs = new TaskCompletionSource<ConversionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (cancellationToken.CanBeCanceled)
            {
                cancellationToken.Register(() =>
                {
                    if (!tcs.Task.IsCompleted)
                        tcs.TrySetResult(ConversionResult.Cancelled(task.Id));
                });
            }

            _pending.Enqueue(tcs);
            _callObserved.TrySetResult(true);
            return tcs.Task;
        }

        public IReadOnlyList<FormatInfo> GetFormats(ConversionCategory? category = null)
        {
            var formats = new[]
            {
                new FormatInfo { Category = ConversionCategory.Video, Extension = "mkv", Name = "MKV" },
                new FormatInfo { Category = ConversionCategory.Video, Extension = "mp4", Name = "MP4" },
                new FormatInfo { Category = ConversionCategory.Audio, Extension = "aac", Name = "AAC" },
                new FormatInfo { Category = ConversionCategory.Audio, Extension = "flac", Name = "FLAC" },
                new FormatInfo { Category = ConversionCategory.Audio, Extension = "mp3", Name = "MP3" },
                new FormatInfo { Category = ConversionCategory.Audio, Extension = "ogg", Name = "OGG" },
                new FormatInfo { Category = ConversionCategory.Audio, Extension = "opus", Name = "OPUS" },
                new FormatInfo { Category = ConversionCategory.Audio, Extension = "wav", Name = "WAV" },
                new FormatInfo { Category = ConversionCategory.Image, Extension = "gif", Name = "GIF" },
                new FormatInfo { Category = ConversionCategory.Image, Extension = "jpg", Name = "JPG" },
                new FormatInfo { Category = ConversionCategory.Image, Extension = "png", Name = "PNG" },
                new FormatInfo { Category = ConversionCategory.Image, Extension = "webp", Name = "WEBP" }
            };

            return category == null ? formats : formats.Where(x => x.Category == category).ToArray();
        }

        public async Task WaitForCallCountAsync(int expectedCount, int timeoutMs = 5000)
        {
            var start = Environment.TickCount64;
            while (StartedTasks.Count < expectedCount)
            {
                if (Environment.TickCount64 - start > timeoutMs)
                    throw new TimeoutException($"Expected {expectedCount} calls but saw {StartedTasks.Count}.");

                await Task.Delay(20);
            }
        }

        public void CompleteNext(ConversionResult result)
        {
            if (_pending.Count == 0)
                throw new InvalidOperationException("No pending conversion to complete.");

            var next = _pending.Dequeue();
            next.TrySetResult(result);
        }
    }

    private static void SetIsBusy(MainViewModel vm, bool value)
    {
        var property = typeof(MainViewModel).GetProperty(nameof(MainViewModel.IsBusy));
        Assert.NotNull(property);
        property.SetValue(vm, value);
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"FluxFormTests_{Guid.NewGuid():N}");

        public TempDir()
        {
            Directory.CreateDirectory(Path);
        }

        public string CreateFile(string name)
        {
            var filePath = System.IO.Path.Combine(Path, name);
            File.WriteAllText(filePath, "test");
            return filePath;
        }

        public void Dispose()
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, true);
        }
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
