# FluxForm

FluxForm 是一款运行在 Windows 上的格式转换工具，支持视频、音频、图片和文档格式互转，提供桌面 GUI 和命令行 CLI 两种使用方式。

## 功能

- **视频**：MP4、MKV、AVI、MOV、WMV、FLV、WebM 等格式互转
- **音频**：MP3、AAC、FLAC、WAV、OGG、M4A、WMA、OPUS 等格式互转
- **图片**：JPG、PNG、WebP、BMP、GIF、TIFF 等格式互转
- **文档**：PDF、DOCX、XLSX、PPTX、TXT、HTML 等格式互转（需安装 LibreOffice）

## 运行环境

- Windows 10/11 x64
- [.NET 9 运行时](https://dotnet.microsoft.com/download/dotnet/9.0)（框架依赖版本）

## 下载与运行

### 桌面版

进入 `publish/wpf`，双击运行 `FluxForm.WPF.exe`。

### 命令行版

进入 `publish/cli`，运行 `FluxForm.CLI.exe`：

```powershell
# 查看帮助
FluxForm.CLI.exe --help

# 查看支持的格式
FluxForm.CLI.exe formats

# 转换单个文件
FluxForm.CLI.exe convert input.mp4 output.mkv

# 批量转换
FluxForm.CLI.exe batch --input-dir ./videos --output-dir ./output --to mp4
```

## 依赖说明

- **FFmpeg**：首次使用媒体/图片转换时，FluxForm 会自动下载并解压到 `tools/ffmpeg/`。
- **LibreOffice**：文档转换需要预先安装 LibreOffice（Windows 版），FluxForm 会尝试在常见安装目录查找。

## 开发

```powershell
dotnet build
dotnet test

# 发布单文件 EXE
dotnet publish FluxForm.CLI/FluxForm.CLI.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish/cli
dotnet publish FluxForm.WPF/FluxForm.WPF.csproj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish/wpf
```

## 项目结构

```
FluxForm/
├── FluxForm.Core/      # 转换引擎、格式注册、依赖管理
├── FluxForm.CLI/       # 命令行入口
├── FluxForm.WPF/       # WPF 桌面 GUI
├── FluxForm.Tests/     # 单元测试
└── publish/            # 发布输出
```

## 许可

MIT
