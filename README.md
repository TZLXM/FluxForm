# FluxForm

FluxForm 是一款运行在 Windows 上的格式转换工具，支持视频、音频、图片和文档格式互转，提供桌面 GUI 和命令行 CLI 两种使用方式。

## 功能

- **视频**：MP4、MKV、AVI、MOV、WMV、FLV、WebM 等格式互转
- **音频**：MP3、AAC、FLAC、WAV、OGG、M4A、WMA、OPUS 等格式互转
- **图片**：JPG、PNG、WebP、BMP、GIF、TIFF 等格式互转
- **文档**：PDF、DOCX、XLSX、PPTX、TXT、HTML 等格式互转（需安装 LibreOffice）

## 运行环境

- Windows 10/11 x64
- 正式发布产物默认采用自包含发布，最终用户无需额外安装 .NET 9 运行时

## 下载与运行

### 桌面版

进入 `publish/wpf`，双击运行 `FluxForm.WPF.exe`。如果发布时启用了 FFmpeg 打包，请保留同级 `tools/ffmpeg/` 目录不变。

### 命令行版

进入 `publish/cli`，运行 `FluxForm.CLI.exe`。如果发布时启用了 FFmpeg 打包，请保留同级 `tools/ffmpeg/` 目录不变：

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

- **FFmpeg**：开发调试时，如果本地不存在，FluxForm 会自动下载并解压到 `tools/ffmpeg/`。正式 publish 默认不联网下载 FFmpeg，以保证发布速度和稳定性；若 `tools-cache/ffmpeg-release-essentials.zip` 存在，或发布脚本显式传入 `-BundleFFmpeg`，MSBuild 会将 FFmpeg 放入发布目录下的 `tools/ffmpeg/`。如果确实需要发布时联网下载，使用 `-DownloadFFmpeg`。
- **LibreOffice**：文档转换需要预先安装 LibreOffice（Windows 版），FluxForm 会尝试在常见安装目录查找。

## 开发

优先使用仓库内脚本作为统一入口：

```powershell
./scripts/build.ps1
./scripts/test.ps1
./scripts/publish-cli.ps1
./scripts/publish-wpf.ps1
```

仓库通过 `global.json` 固定 .NET 9 SDK 选择策略，并通过 `Directory.Build.props` 启用 NuGet lock file。新增或升级 NuGet 包后，请运行 `dotnet restore .\FluxForm.sln --use-lock-file` 并提交更新后的 `packages.lock.json`。发布脚本使用独立的临时 lock path，避免 RID 发布修改项目根目录的锁文件。

如需生成包含 FFmpeg 的发布目录，优先把 `ffmpeg-release-essentials.zip` 放到 `tools-cache/` 后运行：

```powershell
./scripts/publish-cli.ps1 -BundleFFmpeg
./scripts/publish-wpf.ps1 -BundleFFmpeg
```

如需允许发布脚本联网下载 FFmpeg：

```powershell
./scripts/publish-wpf.ps1 -DownloadFFmpeg
```

如果你要在发布前做一轮完整检查，可以运行：

```powershell
./scripts/release-check.ps1
```

如果需要额外确认 WPF 可启动出主窗口，可以运行：

```powershell
./scripts/smoke-wpf.ps1

# 或在发布检查后验证发布产物窗口
./scripts/release-check.ps1 -RunWpfSmoke
```

## GitHub 协作

- PR 请使用仓库内模板，说明改动范围、测试命令、是否涉及 WPF、publish、FFmpeg 或 LibreOffice。
- Bug / Feature 请使用 Issue templates，尽量提供 Windows 版本、输入/输出格式、日志和验收标准。
- CI 在 PR 和 `main` push 时执行 `release-check`，覆盖 Release build/test 和 CLI/WPF publish。
- Release workflow 可通过 `workflow_dispatch` 手动触发，也会在 `v*` tag push 时生成 CLI/WPF artifacts。
- Dependabot 每周检查 GitHub Actions 和各项目 NuGet 依赖。

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
