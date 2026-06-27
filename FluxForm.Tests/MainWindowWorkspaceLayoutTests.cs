using System.IO;
using System.Reflection;

namespace FluxForm.Tests;

public class MainWindowWorkspaceLayoutTests
{
    [Fact]
    public void MainWindow_xaml_contains_workspace_sections_and_primary_actions()
    {
        var xaml = File.ReadAllText(GetProjectFile("FluxForm.WPF", "MainWindow.xaml"));

        Assert.Contains("待配置区", xaml);
        Assert.Contains("批次队列", xaml);
        Assert.Contains("添加文件", xaml);
        Assert.Contains("添加文件夹", xaml);
        Assert.Contains("输出目录", xaml);
        Assert.Contains("开始", xaml);
        Assert.Contains("停止", xaml);
        Assert.Contains("清空", xaml);
        Assert.Contains("加入队列", xaml);
        Assert.Contains("当前批次输出目录", xaml);
        Assert.Contains("重新加入失败任务", xaml);
        Assert.DoesNotContain("任务5", xaml);
    }

    [Fact]
    public void MainWindow_xaml_binds_pending_batch_and_batches_regions()
    {
        var xaml = File.ReadAllText(GetProjectFile("FluxForm.WPF", "MainWindow.xaml"));

        Assert.Contains("PendingBatch.Files", xaml);
        Assert.Contains("PendingBatch.OutputFormat", xaml);
        Assert.Contains("PendingBatch.ValidationMessage", xaml);
        Assert.Contains("IsPendingBatchEmpty", xaml);
        Assert.Contains("PendingFrameRate", xaml);
        Assert.Contains("PendingAspectRatio", xaml);
        Assert.Contains("EnqueuePendingBatchCommand", xaml);
        Assert.Contains("ClearPendingBatchCommand", xaml);
        Assert.Contains("ItemsSource=\"{Binding Batches}\"", xaml);
        Assert.Contains("StatusText", xaml);
        Assert.Contains("RemoveTaskCommand", xaml);
        Assert.Contains("OpenOutputCommand", xaml);
    }

    [Fact]
    public void MainWindow_output_format_picker_is_selection_only_and_uses_common_shortcuts()
    {
        var xaml = File.ReadAllText(GetProjectFile("FluxForm.WPF", "MainWindow.xaml"));

        Assert.Contains("IsEditable=\"False\"", xaml);
        Assert.DoesNotContain("Text=\"{Binding PendingBatch.OutputFormat", xaml);
        Assert.Contains("ItemsSource=\"{Binding CommonFormatPresets}\"", xaml);
        Assert.Contains("Command=\"{Binding DataContext.ApplyFormatCommand, RelativeSource={RelativeSource AncestorType=Window}}\"", xaml);
    }

    [Fact]
    public void MainViewModel_source_declares_pending_batch_batch_queue_and_minimum_commands()
    {
        var source = File.ReadAllText(GetProjectFile("FluxForm.WPF", "ViewModels", "MainViewModel.cs"));

        Assert.Contains("public PendingBatchViewModel PendingBatch", source);
        Assert.Contains("public ObservableCollection<BatchItemViewModel> Batches", source);
        Assert.Contains("public ObservableCollection<FormatPreset> CommonFormatPresets", source);
        Assert.Contains("public RelayCommand AddFolderCommand", source);
        Assert.Contains("public RelayCommand EnqueuePendingBatchCommand", source);
        Assert.Contains("public RelayCommand ClearPendingBatchCommand", source);
        Assert.Contains("public RelayCommand RetryFailedTasksCommand", source);
    }

    private static string GetProjectFile(params string[] parts)
    {
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        var root = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
        return Path.Combine(new[] { root }.Concat(parts).ToArray());
    }
}
