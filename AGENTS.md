# FluxForm 项目说明（面向开发者）

## 项目概述

FluxForm 是 Windows 平台格式转换工具，使用 C# / .NET 9 开发，包含 WPF 桌面 GUI 和命令行 CLI。

## 技术栈

- .NET 9 / C# 12
- WPF + WPF-UI 4.3（Windows 11 风格主题）
- CliWrap（调用外部 ffmpeg 进程）
- 原生命令行解析（未使用 System.CommandLine）

## 模块职责

- `FluxForm.Core`
  - `Models/`：任务、结果、进度、格式模型
  - `Converters/`：`IConverter` 抽象、`ConverterRegistry`、`FFmpegConverter`、`LibreOfficeConverter`
  - `Dependencies/`：`IDependencyManager`、`DependencyManager`（管理 ffmpeg 路径；开发时自动下载，发布时通过 MSBuild 内置）
  - `Services/`：`IConversionService`、`ConversionService`
- `FluxForm.CLI`：命令行入口，支持 `convert`、`batch`、`formats` 命令
- `FluxForm.WPF`：WPF 桌面界面，支持拖拽文件、任务列表、进度显示、日志
- `FluxForm.Tests`：xUnit 单元测试

## 构建与发布

```bash
dotnet build
dotnet test

# 发布 CLI 单文件（自包含，无需安装 .NET 运行时）
dotnet publish FluxForm.CLI/FluxForm.CLI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/cli

# 发布 WPF 单文件（自包含，无需安装 .NET 运行时）
dotnet publish FluxForm.WPF/FluxForm.WPF.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/wpf
```

## 功能开发流程

新增功能时，先判断功能类型，再按对应模块的标准步骤实现。每个步骤都有明确的文件位置和验收标准。

### 功能类型对照表

| 功能类型 | 负责项目 | 关键文件/目录 | 示例 |
|---------|---------|--------------|------|
| 新增格式转换能力 | `FluxForm.Core` | `Converters/`、`Services/ConversionService.cs` | 新增 WebP 转 PNG、PDF 转图片 |
| 新增 CLI 命令/参数 | `FluxForm.CLI` | `Program.cs` | 新增 `preview` 命令、批量重命名 |
| 新增 GUI 交互/界面 | `FluxForm.WPF` | `ViewModels/MainViewModel.cs`、`MainWindow.xaml` | 拖拽优化、设置页、任务队列 |
| 外部依赖管理 | `FluxForm.Core` | `Dependencies/DependencyManager.cs`、`Dependencies/DependencyConfig.cs` | 新增 ImageMagick、调整 ffmpeg 下载逻辑 |
| 构建/发布流程 | 根目录 / 各 `.csproj` | `build/`、`*.csproj` | 新增自包含发布、打包安装程序 |

### 新增转换器（最常用）

转换器必须实现 `FluxForm.Core.Converters.IConverter`：

```csharp
public interface IConverter
{
    ConversionCategory Category { get; }
    IReadOnlyCollection<string> SupportedInputFormats { get; }
    IReadOnlyCollection<string> SupportedOutputFormats { get; }
    bool CanConvert(string inputExtension, string outputExtension);
    Task<ConversionResult> ConvertAsync(ConversionTask task, IProgress<ProgressInfo> progress, CancellationToken cancellationToken = default);
}
```

实现步骤：

1. **新建转换器类**
   - 在 `FluxForm.Core/Converters/` 下创建，如 `ImageMagickConverter.cs`
   - 实现 `IConverter`，通过构造函数接收 `IDependencyManager`
   - 使用 `DependencyManager.EnsureAvailableAsync("xxx")` 获取外部工具路径
   - 转换过程中通过 `IProgress<ProgressInfo>` 报告进度

2. **注册转换器**
   - 打开 `FluxForm.Core/Services/ConversionService.cs`
   - 在构造函数中调用 `_registry.Register(new YourConverter(dependencyManager))`

3. **（可选）注册外部依赖**
   - 如果新转换器依赖新的外部工具，在 `DependencyManager` 的 `_configs` 字典中添加 `DependencyConfig`
   - 配置 `WindowsUrl`、`RelativeExecutablePath`、`ArchiveType` 等字段
   - 若工具太大或需要安装（如 LibreOffice），将 `ArchiveType` 设为 `null`，仅做检测和提示

4. **添加单元测试**
   - 在 `FluxForm.Tests/` 中新增或扩展测试类
   - 至少覆盖：
     - `CanConvert` 对支持/不支持格式的判断
     - `ConversionService.GetFormats()` 能返回新格式
     - 依赖不可用时的失败路径
   - 测试中使用临时目录创建 `DependencyManager`，避免污染开发环境：
     ```csharp
     var dep = new DependencyManager(Path.Combine(Path.GetTempPath(), "fluxform-test-tools"));
     ```

5. **手动验证**
   - 用 CLI 或 WPF 实际转换一个文件
   - 确认输出文件正确、进度/日志正常、错误提示清晰

### 新增 CLI 命令

1. 打开 `FluxForm.CLI/Program.cs`
2. 在 `Main` 方法的 `switch` 中添加新命令分支
3. 实现对应的 `RunXxxAsync` 方法，复用 `CreateService()` 获取 `IConversionService`
4. 参数解析保持统一风格：
   - 长参数用 `--kebab-case`，如 `--input-dir`
   - 布尔开关直接作为 flag，如 `--recursive`、`-no-overwrite`
5. 更新 `PrintUsage()`，让 `--help` 显示新命令
6. 运行 `dotnet run --project FluxForm.CLI -- <新命令>` 验证

### 新增 WPF 功能

1. **数据与交互逻辑**
   - 修改 `FluxForm.WPF/ViewModels/MainViewModel.cs`
   - 使用 `ObservableObject` 基类的 `SetProperty<T>()` 实现可绑定属性
   - 使用 `RelayCommand` 声明命令
   - 耗时操作使用 `async/await`，通过 `IProgress<ProgressInfo>` 更新任务进度

2. **界面调整**
   - 修改 `FluxForm.WPF/MainWindow.xaml`
   - 使用 WPF-UI 控件保持视觉一致：
     - 窗口基类：`ui:FluentWindow`
     - 按钮：`ui:Button` + `ui:SymbolIcon`
     - 主题资源：`{ui:ThemeResource CardStrokeColorDefaultBrush}` 等

3. **拖拽文件**
   - 已在 `MainWindow` 上设置 `AllowDrop="True"`
   - 新增/修改 `Window_DragEnter` 和 `Window_Drop` 事件处理
   - 通过 `DataContext` 调用 `MainViewModel.AddFiles(files)`

4. 启动 WPF 验证界面布局、绑定、命令响应和日志输出

### 开发中检查

每完成一个子模块，运行：

```bash
dotnet build
```

### 功能完成后验收

```bash
dotnet test

# 若改动可能影响发布流程
dotnet publish FluxForm.CLI/FluxForm.CLI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/cli
dotnet publish FluxForm.WPF/FluxForm.WPF.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/wpf
```

#### 手动验收表

| 功能类型 | 验收方式 |
|---------|---------|
| 转换器 | 用 CLI 或 WPF 实际转换一个文件，确认输出正确、进度更新、日志无异常 |
| CLI 命令 | 运行命令并检查输出、帮助信息、错误提示 |
| WPF 功能 | 启动 WPF，按用户操作路径验证界面和日志 |
| 依赖管理 | 删除本地 `tools/ffmpeg/`，验证能否自动恢复或正确提示 |
| 构建/发布 | 检查发布目录结构、单文件 exe 可运行、外部依赖已打包 |

### 文档与提交

- 如果修改了架构、构建流程或开发方式，同步更新本 `AGENTS.md`
- 按 Conventional Commits 规范提交，例如：
  - `feat(core): add ImageMagick PDF to image converter`
  - `feat(cli): add preview command for output files`
  - `feat(wpf): add settings page for default output directory`
- 提交前确认 `.gitignore` 已排除新增的中间文件或缓存目录

## 版本控制与提交规范

本项目采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范编写提交信息，便于生成变更日志和版本号。

### 提交信息格式

```
<type>(<scope>): <subject>

<body>        # 可选：说明修改原因、影响范围、 breaking changes

<footer>      # 可选：关联 Issue、BREAKING CHANGE 等
```

- `type`（必填）：本次提交的类型
- `scope`（可选）：影响的模块或项目，如 `cli`、`wpf`、`core`、`deps`、`build`
- `subject`（必填）：简短描述，使用祈使句，首字母不大写，末尾不加句号

### 常用 type

| Type | 含义 |
|------|------|
| `feat` | 新功能 |
| `fix` | 修复 bug |
| `docs` | 仅文档修改（README、AGENTS.md 等） |
| `style` | 代码格式调整，不影响逻辑（空格、分号、换行等） |
| `refactor` | 重构，既不是新增功能也不是修复 bug |
| `perf` | 性能优化 |
| `test` | 新增或修改测试 |
| `chore` | 构建脚本、工具配置、清理临时文件等杂项 |
| `build` | 影响构建系统或外部依赖的变更（如 csproj、MSBuild targets） |
| `ci` | CI/CD 配置变更 |

### 常用 scope

- `cli`：命令行程序
- `wpf`：桌面 GUI
- `core`：核心库（Models、Converters、Services、Dependencies）
- `deps`：外部依赖管理（ffmpeg、LibreOffice）
- `build`：构建、发布脚本与配置
- `docs`：文档

### 提交示例

```
feat(cli): add batch conversion progress output

fix(wpf): correct drag-drop file path handling

docs: update AGENTS.md with commit conventions

build: bundle ffmpeg into publish directory via MSBuild

chore: remove unused temporary files
```

### 提交前检查清单

提交前请在本地执行以下检查，确保主分支始终可构建、可测试：

```bash
dotnet build
dotnet test
```

如果修改了发布流程或外部依赖，建议额外验证：

```bash
dotnet publish FluxForm.CLI/FluxForm.CLI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/cli
dotnet publish FluxForm.WPF/FluxForm.WPF.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish/wpf
```

### 分支与提交流程

- `main` 为主分支，保持可构建、可发布状态
- 新功能或修复建议从 `main` 切出功能分支：
  - `feat/<short-desc>` 或 `feature/<short-desc>`
  - `fix/<short-desc>`
  - `docs/<short-desc>`
- 每个提交尽量只做一件事，避免把多个不相关的改动混在一起
- 不要提交自动生成文件、敏感信息或大体积二进制文件（如 `bin/`、`obj/`、`publish/`、`tools-cache/`、`.user` 文件等）

### 版本标签

发布新版本时，使用语义化版本号打标签：

```bash
git tag -a v1.0.0 -m "release v1.0.0"
```

版本号规则遵循 [SemVer](https://semver.org/lang/zh-CN/)：
- `MAJOR`：不兼容的 API/行为变更
- `MINOR`：向下兼容的功能新增
- `PATCH`：向下兼容的问题修复

## 外部依赖

- ffmpeg：发布时通过 `build/FFmpeg.targets` 自动从 `tools-cache/ffmpeg-release-essentials.zip`（或联网从 gyan.dev 下载）解压到发布目录的 `tools/ffmpeg/` 下，随应用一起分发。开发调试时若本地不存在，仍由 `DependencyManager` 自动下载到 `tools/ffmpeg/`。
- LibreOffice：文档转换时优先在系统常见目录查找，未找到则提示用户安装。未启用自动下载（安装包过大）。

## 注意事项

- WPF 项目目标框架为 `net9.0-windows`；CLI 和 Core 为 `net9.0`。
- WPF-UI 控件命名空间前缀为 `ui="http://schemas.lepo.co/wpfui/2022/xaml"`，窗口基类使用 `FluentWindow`。
- 添加新的转换器时，实现 `IConverter` 并在 `ConversionService` 中注册。
