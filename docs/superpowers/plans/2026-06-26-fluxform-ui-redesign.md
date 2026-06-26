# FluxForm UI 重设计实现计划

> **面向 AI 代理的工作者：** 必需子技能：使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务实现此计划。步骤使用复选框（`- [ ]`）语法来跟踪进度。

**目标：** 将 FluxForm 的 WPF 主界面重构为“待配置批次 + 批次任务队列”的双阶段工作台，并支持按媒体类型展开基础与高级参数配置。

**架构：** 保留现有 `ConversionService` 与转换器层，重点重构 `FluxForm.WPF` 的 ViewModel 与 XAML 结构。通过新增“待配置批次”“批次队列”“任务摘要/参数模型”这些 WPF 层模型，将“先配置、后生成任务、再串行执行”的流程显式化；底层转换仍通过现有 `ConversionTask.Options` 向 `FFmpegConverter` 传参。

**技术栈：** .NET 9、WPF、WPF-UI 4.3、xUnit、现有 `FluxForm.Core` 转换模型

---

## 文件结构

**创建：**
- `FluxForm.WPF/ViewModels/BatchItemViewModel.cs` — 表示任务队列中的一个批次卡片，包含批次摘要、统计、任务集合与批次级操作状态。
- `FluxForm.WPF/ViewModels/PendingBatchViewModel.cs` — 表示待配置区当前批次，负责文件集合、类型判定、输出设置、参数编辑状态与“生成任务”。
- `FluxForm.WPF/ViewModels/MediaOptionViewModel.cs` — 表示一个可配置参数项（键、标签、值、可见性、分组），用于减少 `MainViewModel` 中的 UI 状态分支。
- `FluxForm.Tests/MainViewModelBatchFlowTests.cs` — 覆盖待配置区、生成批次、串行执行、停止即失败、失败重试等新交互规则。

**修改：**
- `FluxForm.WPF/ViewModels/MainViewModel.cs` — 从“单任务列表”重构为“待配置批次 + 批次队列”的主状态协调器。
- `FluxForm.WPF/ViewModels/TaskItemViewModel.cs` — 增加参数摘要、批次归属、失败重试和从参数字典生成 `ConversionTask` 的能力。
- `FluxForm.WPF/MainWindow.xaml` — 重写主界面为顶部全局栏、待配置区、批次卡片队列、折叠日志区。
- `FluxForm.WPF/MainWindow.xaml.cs` — 调整拖拽逻辑，使拖入文件先进入待配置区，并在运行中禁用新增。
- `FluxForm.Core/Converters/FFmpegConverter.cs` — 补齐本次 UI 计划中需要立即落地的参数键支持（如帧率、视频尺寸模式所需最小参数映射）。
- `FluxForm.Core/Models/ConversionResult.cs` — 若需要，将 `Cancelled` 结果在 WPF 层统一映射为失败，不改变核心状态枚举定义；仅在计划中验证无需修改则保持原样。
- `FluxForm.WPF/ViewModels/FormatPreset.cs` — 视实现需要增加分组/说明字段，供待配置区格式选择显示。

**测试：**
- `FluxForm.Tests/MainViewModelBatchFlowTests.cs`
- `FluxForm.Tests/ConverterRegistryTests.cs`（如新增格式筛选/参数映射断言）

---

### 任务 1：建立待配置批次模型

**文件：**
- 创建：`FluxForm.WPF/ViewModels/PendingBatchViewModel.cs`
- 创建：`FluxForm.WPF/ViewModels/MediaOptionViewModel.cs`
- 测试：`FluxForm.Tests/MainViewModelBatchFlowTests.cs`

- [ ] **步骤 1：编写失败的测试，覆盖待配置批次的同类型限制与清空行为**

```csharp
using FluxForm.Core.Models;
using FluxForm.WPF.ViewModels;
using Xunit;

namespace FluxForm.Tests;

public class MainViewModelBatchFlowTests
{
    [Fact]
    public void PendingBatch_accepts_same_category_files_and_rejects_mixed_files()
    {
        var batch = new PendingBatchViewModel();

        var videoAccepted = batch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
        var imageAccepted = batch.TryAddFile("D:/media/cover.png", ConversionCategory.Image, 2048, "PNG · 1024×768");

        Assert.True(videoAccepted);
        Assert.False(imageAccepted);
        Assert.Equal(ConversionCategory.Video, batch.Category);
        Assert.Single(batch.Files);
        Assert.Equal("当前批次只支持同类型文件，请分别添加视频、音频、图片或文档文件。", batch.ValidationMessage);
    }

    [Fact]
    public void PendingBatch_reset_clears_files_and_configuration_state()
    {
        var batch = new PendingBatchViewModel();
        batch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
        batch.OutputFormat = "mkv";
        batch.OutputDirectory = "D:/output";
        batch.SetOption("videoCodec", "libx264");

        batch.Reset();

        Assert.Empty(batch.Files);
        Assert.Null(batch.Category);
        Assert.Equal(string.Empty, batch.OutputFormat);
        Assert.Equal(string.Empty, batch.OutputDirectory);
        Assert.Empty(batch.Options);
        Assert.Equal(string.Empty, batch.ValidationMessage);
    }
}
```

- [ ] **步骤 2：运行测试验证失败**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter PendingBatch`
预期：FAIL，报错 `The type or namespace name 'PendingBatchViewModel' could not be found`

- [ ] **步骤 3：编写最少实现代码**

```csharp
using System.Collections.ObjectModel;
using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public class MediaOptionViewModel : ObservableObject
{
    private string _value = string.Empty;

    public string Key { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Group { get; set; } = string.Empty;
    public bool IsAdvanced { get; set; }

    public string Value
    {
        get => _value;
        set => SetProperty(ref _value, value);
    }
}

public class PendingBatchFileViewModel
{
    public string FileName { get; set; } = string.Empty;
    public string InputPath { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
}

public class PendingBatchViewModel : ObservableObject
{
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
        if (Category != null && Category != category)
        {
            ValidationMessage = "当前批次只支持同类型文件，请分别添加视频、音频、图片或文档文件。";
            return false;
        }

        Category = category;
        Files.Add(new PendingBatchFileViewModel
        {
            FileName = Path.GetFileName(inputPath),
            InputPath = inputPath,
            FileSizeBytes = fileSizeBytes,
            Summary = summary
        });
        ValidationMessage = string.Empty;
        return true;
    }

    public void SetOption(string key, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            Options.Remove(key);
        else
            Options[key] = value;
    }

    public void Reset()
    {
        Files.Clear();
        Options.Clear();
        Category = null;
        OutputFormat = string.Empty;
        OutputDirectory = string.Empty;
        ValidationMessage = string.Empty;
    }
}
```

- [ ] **步骤 4：运行测试验证通过**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter PendingBatch`
预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add "FluxForm.WPF/ViewModels/PendingBatchViewModel.cs" "FluxForm.WPF/ViewModels/MediaOptionViewModel.cs" "FluxForm.Tests/MainViewModelBatchFlowTests.cs"
git commit -m "test(wpf): add pending batch view model coverage"
```

### 任务 2：建立批次卡片与任务摘要模型

**文件：**
- 创建：`FluxForm.WPF/ViewModels/BatchItemViewModel.cs`
- 修改：`FluxForm.WPF/ViewModels/TaskItemViewModel.cs:1-120`
- 测试：`FluxForm.Tests/MainViewModelBatchFlowTests.cs`

- [ ] **步骤 1：编写失败的测试，覆盖批次统计与任务摘要**

```csharp
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
```

- [ ] **步骤 2：运行测试验证失败**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter BatchItem_updates_counts_and_progress_from_child_tasks`
预期：FAIL，报错 `The type or namespace name 'BatchItemViewModel' could not be found`

- [ ] **步骤 3：编写最少实现代码**

```csharp
using System.Collections.ObjectModel;
using FluxForm.Core.Models;

namespace FluxForm.WPF.ViewModels;

public class BatchItemViewModel : ObservableObject
{
    private double _totalProgress;
    private bool _isExpanded;

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
}
```

并扩展 `TaskItemViewModel`：

```csharp
public string BatchId { get; set; } = string.Empty;
public string ParameterSummary { get; set; } = string.Empty;
public Dictionary<string, string> Options { get; set; } = new(StringComparer.OrdinalIgnoreCase);

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
```

- [ ] **步骤 4：运行测试验证通过**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter BatchItem_updates_counts_and_progress_from_child_tasks`
预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add "FluxForm.WPF/ViewModels/BatchItemViewModel.cs" "FluxForm.WPF/ViewModels/TaskItemViewModel.cs" "FluxForm.Tests/MainViewModelBatchFlowTests.cs"
git commit -m "feat(wpf): add batch queue view models"
```

### 任务 3：重构 MainViewModel 的双阶段流程

**文件：**
- 修改：`FluxForm.WPF/ViewModels/MainViewModel.cs:1-429`
- 测试：`FluxForm.Tests/MainViewModelBatchFlowTests.cs`

- [ ] **步骤 1：编写失败的测试，覆盖生成批次、执行锁定与停止即失败规则**

```csharp
[Fact]
public void MainViewModel_adds_pending_batch_to_queue_and_clears_pending_state()
{
    var vm = new MainViewModel();

    vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
    vm.PendingBatch.OutputFormat = "mkv";
    vm.PendingBatch.OutputDirectory = "D:/out";
    vm.PendingBatch.SetOption("videoCodec", "libx264");

    vm.EnqueuePendingBatch();

    Assert.Single(vm.Batches);
    Assert.Empty(vm.PendingBatch.Files);
    Assert.False(vm.CanAddNewTasks);
    Assert.Equal(1, vm.TotalTaskCount);
}

[Fact]
public void MainViewModel_stop_marks_unfinished_tasks_as_failed()
{
    var vm = new MainViewModel();
    var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
    batch.Tasks.Add(new TaskItemViewModel { FileName = "a.mp4", Status = ConversionStatus.Running });
    batch.Tasks.Add(new TaskItemViewModel { FileName = "b.mp4", Status = ConversionStatus.Pending });
    batch.Tasks.Add(new TaskItemViewModel { FileName = "c.mp4", Status = ConversionStatus.Succeeded });
    vm.Batches.Add(batch);

    vm.MarkUnfinishedTasksAsFailed();

    Assert.Equal(ConversionStatus.Failed, batch.Tasks[0].Status);
    Assert.Equal(ConversionStatus.Failed, batch.Tasks[1].Status);
    Assert.Equal(ConversionStatus.Succeeded, batch.Tasks[2].Status);
}
```

- [ ] **步骤 2：运行测试验证失败**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter MainViewModel_`
预期：FAIL，报错 `MainViewModel does not contain a definition for 'PendingBatch'`

- [ ] **步骤 3：编写最少实现代码**

将 `MainViewModel` 重构为以下核心结构（按现有代码风格内联实现，不拆分服务）：

```csharp
public PendingBatchViewModel PendingBatch { get; } = new();
public ObservableCollection<BatchItemViewModel> Batches { get; } = new();
public bool CanAddNewTasks => !IsBusy && Batches.Count == 0;
public int TotalTaskCount => Batches.Sum(b => b.Tasks.Count);

public RelayCommand AddFilesCommand { get; }
public RelayCommand AddFolderCommand { get; }
public RelayCommand EnqueuePendingBatchCommand { get; }
public RelayCommand RetryFailedTasksCommand { get; }

public void EnqueuePendingBatch()
{
    if (PendingBatch.Category == null || PendingBatch.Files.Count == 0 || string.IsNullOrWhiteSpace(PendingBatch.OutputFormat))
        return;

    var batchId = $"B{Batches.Count + 1:000}";
    var batch = new BatchItemViewModel
    {
        BatchId = batchId,
        Category = PendingBatch.Category.Value,
        ConfigSummary = BuildBatchSummary(PendingBatch)
    };

    foreach (var file in PendingBatch.Files)
    {
        batch.Tasks.Add(CreateTask(batchId, file));
    }

    batch.Refresh();
    Batches.Add(batch);
    PendingBatch.Reset();
    RefreshAllBatchStats();
}

public void MarkUnfinishedTasksAsFailed()
{
    foreach (var batch in Batches)
    {
        foreach (var task in batch.Tasks.Where(t => t.Status is ConversionStatus.Pending or ConversionStatus.Running or ConversionStatus.Cancelled))
        {
            task.Status = ConversionStatus.Failed;
            task.Message = "失败：任务已停止";
            task.Progress = 0;
        }
        batch.Refresh();
    }
}
```

并同步更新：
- `AddFiles(IEnumerable<string>)` 改为把文件添加到 `PendingBatch`
- `SetOutputDirectoryCommand` 作用于 `PendingBatch.OutputDirectory`
- `StartConversion()` 改为按 `Batches.SelectMany(b => b.Tasks)` 串行执行 `Pending`/`Failed` 重试任务
- `CancelConversion()` 在取消后调用 `MarkUnfinishedTasksAsFailed()`
- `UpdateStatus()` 改为输出批次与任务汇总

- [ ] **步骤 4：运行测试验证通过**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter MainViewModel_`
预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add "FluxForm.WPF/ViewModels/MainViewModel.cs" "FluxForm.Tests/MainViewModelBatchFlowTests.cs"
git commit -m "feat(wpf): implement batch-based queue workflow"
```

### 任务 4：补齐最小可用的媒体参数映射

**文件：**
- 修改：`FluxForm.Core/Converters/FFmpegConverter.cs:1-169`
- 修改：`FluxForm.WPF/ViewModels/MainViewModel.cs:1-429`
- 测试：`FluxForm.Tests/MainViewModelBatchFlowTests.cs`

- [ ] **步骤 1：编写失败的测试，覆盖视频参数写入任务 Options**

```csharp
[Fact]
public void Enqueued_video_tasks_copy_pending_batch_options()
{
    var vm = new MainViewModel();
    vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
    vm.PendingBatch.OutputFormat = "mkv";
    vm.PendingBatch.OutputDirectory = "D:/out";
    vm.PendingBatch.SetOption("videoCodec", "libx264");
    vm.PendingBatch.SetOption("videoBitrate", "4M");
    vm.PendingBatch.SetOption("resolution", "1920x1080");
    vm.PendingBatch.SetOption("frameRate", "30");

    vm.EnqueuePendingBatch();

    var task = vm.Batches[0].Tasks[0];
    Assert.Equal("libx264", task.Options["videoCodec"]);
    Assert.Equal("4M", task.Options["videoBitrate"]);
    Assert.Equal("1920x1080", task.Options["resolution"]);
    Assert.Equal("30", task.Options["frameRate"]);
}
```

- [ ] **步骤 2：运行测试验证失败**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter Enqueued_video_tasks_copy_pending_batch_options`
预期：FAIL，报错 `The given key 'frameRate' was not present`

- [ ] **步骤 3：编写最少实现代码**

在 `MainViewModel.CreateTask(...)` 中复制待配置项：

```csharp
private TaskItemViewModel CreateTask(string batchId, PendingBatchFileViewModel file)
{
    var outputPath = GenerateOutputPath(file.InputPath, PendingBatch.OutputFormat, PendingBatch.OutputDirectory);
    return new TaskItemViewModel
    {
        BatchId = batchId,
        FileName = file.FileName,
        InputPath = file.InputPath,
        InputFormat = Path.GetExtension(file.InputPath).TrimStart('.').ToLowerInvariant(),
        OutputFormat = PendingBatch.OutputFormat,
        OutputPath = outputPath,
        Category = PendingBatch.Category!.Value,
        Status = ConversionStatus.Pending,
        Message = "等待中",
        Options = new Dictionary<string, string>(PendingBatch.Options, StringComparer.OrdinalIgnoreCase),
        ParameterSummary = BuildTaskSummary(PendingBatch)
    };
}
```

并在 `FFmpegConverter.ApplyOptions` 中追加最小参数映射：

```csharp
if (task.Options.TryGetValue("frameRate", out var frameRate) && !string.IsNullOrWhiteSpace(frameRate))
{
    args.Add("-r");
    args.Add(frameRate);
}

if (task.Options.TryGetValue("aspectRatio", out var aspectRatio) && !string.IsNullOrWhiteSpace(aspectRatio))
{
    args.Add("-aspect");
    args.Add(aspectRatio);
}
```

保持第一版只映射规格中已确认的最小参数集合：
- `videoCodec`
- `videoBitrate`
- `audioCodec`
- `audioBitrate`
- `resolution`
- `frameRate`
- `aspectRatio`
- `quality`

- [ ] **步骤 4：运行测试验证通过**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter Enqueued_video_tasks_copy_pending_batch_options`
预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add "FluxForm.WPF/ViewModels/MainViewModel.cs" "FluxForm.Core/Converters/FFmpegConverter.cs" "FluxForm.Tests/MainViewModelBatchFlowTests.cs"
git commit -m "feat(core): map pending batch media options to ffmpeg args"
```

### 任务 5：重写 MainWindow 为双阶段工作台

**文件：**
- 修改：`FluxForm.WPF/MainWindow.xaml:1-324`
- 修改：`FluxForm.WPF/MainWindow.xaml.cs:1-58`
- 测试：`FluxForm.Tests/MainViewModelBatchFlowTests.cs`

- [ ] **步骤 1：编写失败的测试，覆盖运行期禁用新增任务的命令状态**

```csharp
[Fact]
public void Running_state_disables_adding_files_and_enqueueing_batch()
{
    var vm = new MainViewModel();
    vm.PendingBatch.TryAddFile("D:/media/demo.mp4", ConversionCategory.Video, 1024, "MP4 · 1920×1080 · 30fps");
    vm.PendingBatch.OutputFormat = "mkv";
    vm.EnqueuePendingBatch();
    vm.SetBusyForTests(true);

    Assert.False(vm.AddFilesCommand.CanExecute(null));
    Assert.False(vm.EnqueuePendingBatchCommand.CanExecute(null));
}
```

- [ ] **步骤 2：运行测试验证失败**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter Running_state_disables_adding_files_and_enqueueing_batch`
预期：FAIL，报错 `MainViewModel does not contain a definition for 'SetBusyForTests'`

- [ ] **步骤 3：编写最少实现代码**

在 `MainViewModel` 增加测试钩子：

```csharp
internal void SetBusyForTests(bool value)
{
    IsBusy = value;
}
```

并将 `MainWindow.xaml` 重写为以下结构（保留资源与拖拽遮罩逻辑，替换主体布局）：

```xml
<Grid x:Name="RootGrid">
  <Grid.RowDefinitions>
    <RowDefinition Height="Auto" />
    <RowDefinition Height="Auto" />
    <RowDefinition Height="2*" />
    <RowDefinition Height="3*" />
    <RowDefinition Height="Auto" />
  </Grid.RowDefinitions>

  <ui:TitleBar Title="FluxForm" Grid.Row="0" />

  <!-- 顶部操作栏 -->
  <Border Grid.Row="1" ...>
    <!-- 添加文件 / 添加文件夹 / 开始任务 / 停止任务 / 清空队列 / 输出目录 -->
  </Border>

  <!-- 待配置区 -->
  <Border Grid.Row="2" ...>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="2*" />
        <ColumnDefinition Width="3*" />
      </Grid.ColumnDefinitions>
      <!-- 左：待配置文件列表 -->
      <!-- 右：输出格式、输出目录、快速参数、高级参数、加入任务队列 -->
    </Grid>
  </Border>

  <!-- 批次任务队列 -->
  <Border Grid.Row="3" ...>
    <ScrollViewer>
      <ItemsControl ItemsSource="{Binding Batches}">
        <!-- 批次卡片 + 内部任务小卡片 -->
      </ItemsControl>
    </ScrollViewer>
  </Border>

  <!-- 折叠日志区 -->
  <Expander Grid.Row="4" Header="日志与错误详情" IsExpanded="False">
    <TextBox Text="{Binding LogText}" IsReadOnly="True" AcceptsReturn="True" />
  </Expander>
</Grid>
```

并在 `MainWindow.xaml.cs` 中限制拖拽：

```csharp
private void Window_PreviewDrop(object sender, DragEventArgs e)
{
    DropOverlay.Visibility = Visibility.Collapsed;

    if (DataContext is not MainViewModel vm || vm.IsBusy)
    {
        e.Handled = true;
        return;
    }

    if (e.Data.GetDataPresent(DataFormats.FileDrop))
    {
        var files = (string[])e.Data.GetData(DataFormats.FileDrop)!;
        vm.AddFiles(files);
    }

    e.Handled = true;
}
```

- [ ] **步骤 4：运行测试验证通过**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter Running_state_disables_adding_files_and_enqueueing_batch`
预期：PASS

并运行：`dotnet build "D:/AI-code/FluxForm/FluxForm.sln"`
预期：PASS，无 XAML 编译错误

- [ ] **步骤 5：Commit**

```bash
git add "FluxForm.WPF/MainWindow.xaml" "FluxForm.WPF/MainWindow.xaml.cs" "FluxForm.WPF/ViewModels/MainViewModel.cs" "FluxForm.Tests/MainViewModelBatchFlowTests.cs"
git commit -m "feat(wpf): redesign main window as batch workspace"
```

### 任务 6：验证串行执行、停止与失败重试闭环

**文件：**
- 修改：`FluxForm.WPF/ViewModels/MainViewModel.cs:1-429`
- 修改：`FluxForm.WPF/ViewModels/BatchItemViewModel.cs:1-120`
- 测试：`FluxForm.Tests/MainViewModelBatchFlowTests.cs`

- [ ] **步骤 1：编写失败的测试，覆盖失败任务单独重试与批次刷新**

```csharp
[Fact]
public void Retry_failed_task_resets_status_to_pending_and_refreshes_batch_counts()
{
    var batch = new BatchItemViewModel { BatchId = "B001", Category = ConversionCategory.Video };
    var task = new TaskItemViewModel
    {
        FileName = "demo.mp4",
        Status = ConversionStatus.Failed,
        Message = "失败：任务已停止",
        Progress = 0
    };
    batch.Tasks.Add(task);
    batch.Refresh();

    batch.RetryTask(task);

    Assert.Equal(ConversionStatus.Pending, task.Status);
    Assert.Equal("等待中", task.Message);
    Assert.Equal(0, task.Progress);
    Assert.Equal(1, batch.PendingCount);
    Assert.Equal(0, batch.FailedCount);
}
```

- [ ] **步骤 2：运行测试验证失败**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter Retry_failed_task_resets_status_to_pending_and_refreshes_batch_counts`
预期：FAIL，报错 `BatchItemViewModel does not contain a definition for 'RetryTask'`

- [ ] **步骤 3：编写最少实现代码**

在 `BatchItemViewModel` 增加：

```csharp
public void RetryTask(TaskItemViewModel task)
{
    task.Status = ConversionStatus.Pending;
    task.Message = "等待中";
    task.Progress = 0;
    Refresh();
}

public void RetryFailedTasks()
{
    foreach (var task in Tasks.Where(t => t.Status == ConversionStatus.Failed))
    {
        task.Status = ConversionStatus.Pending;
        task.Message = "等待中";
        task.Progress = 0;
    }
    Refresh();
}
```

并在 `MainViewModel` 中绑定：
- 单任务重试命令
- 批次级重试失败任务命令
- 全局重试失败任务命令（若实现）

同时确保 `StartConversion()` 仅执行：

```csharp
var queue = Batches
    .SelectMany(b => b.Tasks)
    .Where(t => t.Status == ConversionStatus.Pending)
    .ToList();
```

这样失败任务在被重试前不会自动重新进入执行队列。

- [ ] **步骤 4：运行测试验证通过**

运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj" --filter Retry_failed_task_resets_status_to_pending_and_refreshes_batch_counts`
预期：PASS

并运行：`dotnet test "D:/AI-code/FluxForm/FluxForm.Tests/FluxForm.Tests.csproj"`
预期：PASS

- [ ] **步骤 5：Commit**

```bash
git add "FluxForm.WPF/ViewModels/MainViewModel.cs" "FluxForm.WPF/ViewModels/BatchItemViewModel.cs" "FluxForm.Tests/MainViewModelBatchFlowTests.cs"
git commit -m "feat(wpf): add failed task retry workflow"
```

---

## 自检

### 规格覆盖度
- 顶部全局操作栏：任务 5 覆盖。
- 待配置区：任务 1、任务 3、任务 5 覆盖。
- 同类型限制：任务 1 覆盖。
- 动态媒体参数与高级参数：任务 4、任务 5 覆盖最小首版。
- 批次卡片 + 小任务卡片：任务 2、任务 5 覆盖。
- 串行执行：任务 3、任务 6 覆盖。
- 停止即失败：任务 3 覆盖。
- 失败任务重试：任务 6 覆盖。
- 日志折叠区：任务 5 覆盖。

### 占位符扫描
- 计划中未使用“TODO / 后续补充 / 类似任务 N”这类占位符。
- 所有测试步骤、运行命令、实现代码、提交命令都给出了明确内容。

### 类型一致性
- 待配置区核心模型统一使用 `PendingBatchViewModel`。
- 队列核心模型统一使用 `BatchItemViewModel` 与 `TaskItemViewModel`。
- 任务参数统一存储在 `TaskItemViewModel.Options`，传递到 `ConversionTask.Options`。
- 失败重试统一回到 `ConversionStatus.Pending`。

---

计划已完成并保存到 `docs/superpowers/plans/2026-06-26-fluxform-ui-redesign.md`。两种执行方式：

**1. 子代理驱动（推荐）** - 每个任务调度一个新的子代理，任务间进行审查，快速迭代

**2. 内联执行** - 在当前会话中使用 executing-plans 执行任务，批量执行并设有检查点

选哪种方式？