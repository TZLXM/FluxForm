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
  - `Dependencies/`：`IDependencyManager`、`DependencyManager`（自动下载 ffmpeg）
  - `Services/`：`IConversionService`、`ConversionService`
- `FluxForm.CLI`：命令行入口，支持 `convert`、`batch`、`formats` 命令
- `FluxForm.WPF`：WPF 桌面界面，支持拖拽文件、任务列表、进度显示、日志
- `FluxForm.Tests`：xUnit 单元测试

## 构建与发布

```bash
dotnet build
dotnet test

# 发布 CLI 单文件
dotnet publish FluxForm.CLI/FluxForm.CLI.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish/cli

# 发布 WPF 单文件
dotnet publish FluxForm.WPF/FluxForm.WPF.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish/wpf
```

## 外部依赖

- ffmpeg：通过 DependencyManager 自动从 gyan.dev 下载并解压到 `tools/ffmpeg/`。
- LibreOffice：文档转换时优先在系统常见目录查找，未找到则提示用户安装。未启用自动下载（安装包过大）。

## 注意事项

- WPF 项目目标框架为 `net9.0-windows`；CLI 和 Core 为 `net9.0`。
- WPF-UI 控件命名空间前缀为 `ui="http://schemas.lepo.co/wpfui/2022/xaml"`，窗口基类使用 `FluentWindow`。
- 添加新的转换器时，实现 `IConverter` 并在 `ConversionService` 中注册。
