# FluxForm Rust 水球交互平台重构设计

**日期：** 2026-09-25

**状态：** 已通过对话设计评审、独立交叉审阅与用户复核

**范围：** 视频、音频、图片转换；网页、跨平台桌面和通用 MCP 三种独立入口

## 1. 背景与目标

现有 FluxForm 使用 C#、.NET 9 和 WPF。转换核心与 CLI 已具备一定边界，但桌面表现层存在三个根本问题：

- WPF 仅面向 Windows，不能满足 Windows、macOS 和 Linux 的统一桌面体验。
- XAML/MVVM 页面集中且维护成本高，不利于 Agent 参与视觉和交互迭代。
- 传统窗口、表单和任务卡片无法承载产品期望的“活体水球”直接操控体验。

本次重构不是在 WPF 上继续换肤，而是建立 Rust-first 的新平台。目标是提供三种相互独立、共享转换语义的入口：

1. 匿名即用的网页转换应用，文件上传到服务器处理。
2. Windows、macOS 和 Linux 桌面应用，完全离线并随安装包提供 FFmpeg。
3. 独立的通用 MCP Server，供 Agent 调用用户电脑上的本地转换引擎。

桌面和网页采用同一套水球视觉语言；MCP 入口不包含视觉界面。三种入口可以分开迭代和发布。

## 2. 非目标

首轮重构明确不包含：

- 文档格式转换及 LibreOffice 分发。
- 用户账号、云端历史记录和永久文件存储。
- 网页版多水球。
- 将任意 FFmpeg 参数直接暴露给用户或 Agent。
- 直接链接 FFmpeg 原生库或通过 FFI 调用 libav*。
- 首版 HEIC/HEIF 支持；相关能力保留扩展边界，但不阻塞首发。
- 在新版本达到功能基线前删除现有 C#、CLI 或 WPF 实现。

## 3. 核心设计原则

### 3.1 一套引擎，三个适配器

转换规则、任务状态、参数验证、FFmpeg 命令构建和错误语义只实现一次。桌面、网页和 MCP 只负责各自的输入、输出和传输方式。

### 3.2 业务状态独立于水球渲染

Rust Runtime 是任务真相来源。水球只呈现状态并发送意图；窗口销毁、WebGL 上下文丢失或 React 组件重建都不能改变任务事实。

### 3.3 固定但可扩展的能力目录

FluxForm 维护经过测试的有向转换矩阵，不直接暴露 FFmpeg 构建所报告的全部格式。固定白名单可以包含大量格式，但每一条输入到输出的边都必须有明确测试与参数约束。

### 3.4 外部进程隔离

FFmpeg 和 FFprobe 作为独立可执行文件运行。Rust 负责进程生命周期、参数构造、进度解析、取消、超时和进程树终止。

### 3.5 原子输出与临时文件生命周期

所有输出先写入与最终目标相同文件系统、相同目录下的唯一临时文件。FFmpeg 命令必须显式传入输出 muxer 与 codec，不能依赖临时文件扩展名猜测格式。建议命名形如 `.fluxform-<job-id>.partial.<final-extension>`。

提交过程为：

1. 在任务进入 `finalizing` 前确定并独占目标路径。
2. FFmpeg 写入临时文件；完成后使用 FFprobe 验证容器、流和关键属性。
3. 刷新临时文件与父目录，并调用平台适配的原子 no-replace 或 replace 操作。
4. `reject`、`rename` 和 `replace` 均在提交时再次检查，不能仅在任务开始时检查。
5. 取消与提交通过同一个状态锁线性化；一旦开始最终提交，取消不能与重命名并发。
6. 不支持可靠原子替换的文件系统必须失败并给出明确说明，不能退化为先删除正式文件再移动。

失败、取消或崩溃不会留下看似完整的损坏输出。启动恢复根据任务日志清理或核对遗留临时文件。

## 4. 总体架构

```text
FluxForm
├─ crates/
│  ├─ fluxform-protocol    版本化请求、事件、错误和 JSON Schema
│  ├─ fluxform-core        转换计划、格式矩阵和任务状态机
│  ├─ fluxform-ffmpeg      FFmpeg/FFprobe 进程适配器
│  ├─ fluxform-runtime     队列、并发、取消和文件生命周期
│  └─ fluxform-limits      上传、配额、超时和资源策略
│
├─ packages/
│  ├─ water-ui             React 交互组件和语义层
│  ├─ water-renderer       Three.js、Shader 和性能分级
│  └─ client-sdk           Web 与桌面共用的 TypeScript 类型客户端
│
└─ apps/
   ├─ water-lab            纯视觉与状态模拟实验场
   ├─ web                  单水球网页应用
   ├─ server               Rust HTTP API、静态资源和转换 Worker
   ├─ desktop              Tauri 跨平台桌面应用
   └─ agent                通用 MCP Server
```

建议的基础技术为：

- Rust、Tokio、Serde。
- Axum 提供网页 API、静态资源和 SSE。
- SQLite 保存匿名任务、配额和临时文件元数据。
- Tauri 2 提供桌面壳层、透明窗口、系统文件对话框和多窗口管理。
- React、TypeScript、Three.js 与自定义 WebGL Shader 提供水球界面。
- MCP stdio 作为 Agent 的首发传输方式。

## 5. 共享转换协议

### 5.1 请求模型

```text
ConversionRequest
├─ protocol_version
├─ inputs[]
├─ category              video | audio | image
├─ output_format
├─ output_target
├─ overwrite_policy      reject | rename | replace
├─ options
│  ├─ video
│  ├─ audio
│  └─ image
└─ client_context
```

`output_target` 是入口适配器的受限枚举，而不是通用字符串：

- 桌面：`LocalDirectory`，只能来自系统目录选择器或经过规范化校验的本地目录。
- MCP：`LocalPath` 或 `ManagedJobDirectory`，受 MCP 配置的允许根目录约束。
- 网页：只能是 `ManagedArtifact`，由服务端生成内部目标 ID；客户端永远不能提交服务器文件系统路径。

参数使用强类型字段。首版不提供 `extra_args`、`raw_ffmpeg_args` 或等价逃生口。

视频参数覆盖编码预设、质量、分辨率、帧率、宽高比和音频保留策略；音频参数覆盖编码器、码率、采样率和声道；图片参数覆盖质量、尺寸、比例和透明背景策略。

尺寸变化必须显式使用 `contain`、`cover` 或 `stretch`；默认 `contain` 并保持宽高比。输入含 Alpha 而输出格式不支持 Alpha 时，默认合成到白色背景并在执行前展示警告；方向元数据默认应用到像素后再输出。

### 5.2 状态模型

```text
created
→ validating
→ queued
→ probing
→ converting
→ finalizing
→ completed

任意处理中状态
→ failed | cancelling | cancelled | interrupted
```

事件包括：

- `job.state_changed`
- `job.progress`
- `job.warning`
- `job.completed`
- `job.failed`
- `queue.position_changed`

每个任务维护单调递增的 `revision`。事件 ID 等于该任务 revision；客户端重连时提交最后看到的 revision。服务端在任务有效期内保留足以恢复的终态与有限事件记录：能够重放时继续重放，存在缺口时返回 `resync_required`，客户端随后获取带当前 revision 的权威快照。完成事件不得在任务下载有效期结束前消失。

### 5.3 错误模型

首版稳定错误码包括：

- `unsupported_input`
- `unsupported_conversion`
- `mixed_category`
- `invalid_option`
- `file_too_large`
- `quota_exceeded`
- `queue_full`
- `ffprobe_failed`
- `conversion_failed`
- `output_too_large`
- `timeout`
- `cancelled`
- `interrupted`
- `storage_unavailable`

错误同时包含机器可读代码、面向用户的简短说明和可选诊断详情。诊断详情不得泄露服务器绝对路径或任意命令行内容。

### 5.4 传输映射

- 桌面：Tauri IPC 调用同进程 Rust Runtime。
- 网页：HTTP JSON 提交任务，SSE 接收事件。
- Agent：MCP JSON-RPC 调用本地 Runtime。

协议使用显式 `v1` 版本并生成 JSON Schema。三个入口可以独立升级，但不得静默改变同一版本的字段含义。

## 6. 首版格式能力

首版围绕 FFmpeg 提供固定转换矩阵。以下列表定义候选容器和文件族，不代表仅凭扩展名即可接受：

- 视频候选输入：MP4、MOV、MKV、WebM、AVI、M4V、MPG、MPEG、WMV、FLV。
- 视频候选输出：MP4、MOV、MKV、WebM。
- 音频候选输入：MP3、AAC、M4A、WAV、FLAC、OGG、OPUS、WMA。
- 音频候选输出：MP3、AAC、M4A、WAV、FLAC、OGG、OPUS。
- 图片候选输入：JPEG/JPG、PNG、WebP、BMP、TIFF/TIF、静态 GIF。
- 图片候选输出：JPEG、PNG、WebP、BMP、TIFF。

版本化 capability manifest 才是产品承诺的权威来源。每条有向转换边必须声明：

- 输入 demuxer/container、允许的 codec 与流拓扑。
- 输出 muxer、video/audio/image codec 和明确的 stream mapping。
- 字幕、附件、封面、Alpha、方向与 metadata 的保留、转换或丢弃策略。
- 参数范围、默认值、FFmpeg 构建 profile 和三平台可用性。
- 探测规则、真实样本、失败样本和期望诊断。

容器受支持不等于其中任意 codec 都受支持。例如 MOV、MKV、AVI 和 OGG 必须在 FFprobe 后按 manifest 判断实际流。OPUS 表示 codec，具体输出容器由转换边明确指定。

首版图片路径只接受单帧输入。动画 GIF、动画 WebP 和多页 TIFF 返回明确的不支持错误，避免静默丢帧。

在实现转换矩阵前必须冻结每个平台的 FFmpeg 构建 profile、许可证策略和输出 codec；manifest 只能引用该 profile 实际包含且获准分发的能力。新增格式必须同时补充上述声明、真实样本测试和三平台验证。

HEIC/HEIF 作为后续“兼容输入格式”候选，预期优先支持转换到 JPEG、PNG 和 WebP，而不是同时承诺 HEIC 编码。后续可通过新的转换后端接入 libheif，而不改变现有入口协议。

## 7. 水球交互模型

### 7.1 基本语义

- 主水球代表一条独立队列。
- 主水球内部气泡代表文件、批次和状态。
- 外围小水球代表当前上下文中的选项和动作。
- 同次拖入的同类文件自动组成一个共享格式与参数的批次。
- 一个主水球只接受一个媒体类别。异类文件靠近时产生排斥波纹并提示分开添加。
- 转换期间可以继续拖入同类文件，形成后续批次。
- 桌面端每颗水球按 FIFO 顺序一次执行一个批次；不同水球之间由全局 Runtime 控制并发数。
- 网页端只有一颗水球，批次按 FIFO 接纳，但调度器可以在单 IP 与全站上限内同时执行多个已接纳批次，因此完成顺序可能不同于提交顺序。

### 7.2 交互状态机

```text
idle
→ attracting
→ absorbing
→ configuring
→ ready
→ converting
→ completed

attracting → rejecting → idle
converting → failed → retrying | dismissed
```

完整流程为：

1. 用户将同类文件拖向水球。
2. 每个文件在接近边缘时被小水球包裹。
3. 松开后，小水球通过液桥融入主水球。
4. 文件名称和缩略图出现在主水球内部。
5. 输出格式与保存位置水球从主体分裂。
6. 常用格式直接展示；其余格式收纳在 `…` 水球中。
7. 用户点击内部批次气泡后，外围选项切换为该格式的详细参数。
8. 配置完成后，外围出现明确的开始水球。
9. 转换中，配置水球融回主体，仅保留取消等运行期动作。
10. 完成后，结果水球从主体分裂；文件同时已经写入预设位置。
11. 点击结果水球提供打开文件和打开所在位置。

### 7.3 错误表达

失败状态必须醒目但不快速闪烁：

- 水球外围逐渐染为半透明暗红色，内部仍保留蓝色水体。
- 表面流动短暂变得不对称并产生轻微紊乱。
- 失败批次气泡显示文字和错误图标，不能只依赖颜色。
- 外围分裂出查看原因、重试和移除操作水球。

### 7.4 关闭行为

- 关闭非最后一颗水球时，如果该水球有运行或等待任务，显示作用域仅限该水球的终止确认。
- 关闭最后一颗水球且存在任务时，主体收缩并分裂出“继续转换”和“终止并退出”确认水球。
- 确认退出后，Runtime 停止接收任务、取消全部 FFmpeg、等待短暂清理窗口、终止残留进程树、删除 `.partial` 文件并退出。
- 没有任务时，最后一颗水球可以直接关闭。
- 正常退出后清空所有水球、批次和队列，只保留应用设置与材质偏好。

## 8. 水球渲染与性能

### 8.1 三层结构

```text
语义交互层：React/HTML
  文件名、参数文字、点击区域、键盘和屏幕阅读器语义

水球渲染层：Three.js + Shader
  轮廓、体积吸收、折射、反射、法线流动和焦散

状态控制层
  将任务和交互状态映射为材质、运动和布局参数
```

文字与关键命中区域不得直接烘焙到水体纹理中，以免折射后难以阅读并失去可访问性。

### 8.2 视觉基准

主材质采用深海蓝水体颜色与高透明度组合：

- 中央通过厚度吸收呈现深蓝，而不是简单降低透明度。
- 边缘使用明亮青蓝菲涅耳反射。
- 内部存在缓慢体积流动和稀疏焦散。
- 虹彩仅作为克制高光，不形成魔法或塑料质感。
- 桌面端采用近似折射，不实时捕获并扭曲其他应用画面。

### 8.3 动态模型

- 待机时外轮廓近乎静止，仅保留低频不规则形变和可观察的内部流动。
- 鼠标或文件靠近时，接触点产生隆起、凹陷和局部波纹。
- 吸收时产生向内涡流；分裂和融合使用液桥与表面张力动画。
- 拖动窗口时，内部液体表现出与运动相反的惯性偏移。
- 完成时产生一次稳定的明亮外扩波纹。

### 8.4 性能分级

- 待机：20–30 FPS，降低内部渲染分辨率，不运行完整流体模拟。
- 直接交互：临时提升到 60 FPS，并启用局部扰动场。
- 转换中：目标 30 FPS，通过内部流向与语义文字共同表达进度。
- 非焦点水球：降低帧率和分辨率。
- 被遮挡、系统锁屏或休眠：暂停渲染。
- 多水球：基于帧时间自动降低非活动水球质量。
- `prefers-reduced-motion` 或应用设置启用时，减少轮廓形变和融合动画，但保留颜色、文字和状态变化。
- GPU、WebGL 或 Shader 初始化失败时，切换到静态高质量水球图层；文件拖放、参数选择、进度、错误、键盘和屏幕阅读器操作仍必须完整可用。

首版性能验收使用一台 8 GB 内存、集成显卡的参考设备：单颗待机水球连续 60 秒平均 CPU 不高于 3%、GPU 不高于 8%；三颗待机水球总 CPU 不高于 8%、GPU 不高于 15%、应用 RSS 不高于 400 MiB；交互态 p95 帧时间不高于 25 ms。未达到预算时必须自动降级，不能以牺牲转换可靠性维持动画。

## 9. Water Lab

Water Lab 是正式 `water-renderer` 的开发入口，不是一次性原型。它只能消费 `fluxform-protocol` 生成的 TypeScript 状态与事件 fixtures，不能发明独立的临时状态模型。

它使用模拟数据覆盖：

- 待机
- 文件靠近
- 拒绝异类文件
- 吸收与融合
- 格式和参数选择
- 排队与并行转换
- 完成与结果分裂
- 失败与重试
- 退出确认

仅在开发构建中提供材质与性能调节器。确认后的值保存为版本化材质预设，网页与 Tauri 共用，正式产品不显示调节器。

## 10. 桌面端设计

### 10.1 单进程多窗口

用户通过重复启动 FluxForm 创建新的独立水球。实现上不得创建多个完整 Runtime：

1. 第一次启动创建唯一 Tauri 主进程、Runtime 和水球窗口。
2. 后续启动实例通过平台单实例机制通知已有进程创建新水球窗口。
3. 后续实例完成通知后立即退出。

因此用户得到多个独立透明窗口，而任务、并发限制和 FFmpeg 子进程仍由一个 Runtime 管理。

### 10.2 跨平台窗口能力

- 目标形态是无标题栏、透明背景、可自由拖动的独立窗口，但必须先通过平台可行性门槛。
- 门槛分别验证 Windows、macOS、X11 和 Wayland 上的透明度、文件拖放、窗口拖动、焦点、关闭、DPI、多显示器以及透明区域命中测试。
- 透明矩形中水球之外的像素不得大面积截获桌面点击。优先使用平台输入区域；不可用时收紧窗口边界，并只在外围水球展开期间扩大交互区域。
- macOS 透明窗口需要 Tauri 的 `macOSPrivateApi`，因此首版 macOS 采用签名、公证后的直接 DMG 分发，不承诺 Mac App Store。
- Wayland 不支持全局窗口位置和 always-on-top 语义；Wayland 版本作为普通层级、由用户定位的无边框小窗口运行，不承诺桌面挂件式置顶体验。
- 如果目标合成器连 Alpha 透明也无法可靠提供，降级为紧凑、无传统表单结构、带不透明深色背景的无边框小窗口，而不是伪装成仍然透明。
- 任一平台的降级不得阻止文件转换、键盘操作和错误恢复。

### 10.3 离线分发

- 每个平台和 CPU 架构提供对应 FFmpeg 与 FFprobe。
- 安装和首次运行都不得下载转换依赖或 WebView 运行时。
- Windows 安装器使用 Tauri `offlineInstaller` WebView2 模式；不使用默认的联网 bootstrapper。
- macOS 使用系统 WebKit，并通过直接 DMG 分发、代码签名和公证验证离线首次运行。
- Linux 首版离线基线为 x86_64 AppImage，构建基线不高于 Ubuntu 22.04 / Debian 12；X11 提供完整窗口目标，Wayland 使用上一节定义的降级行为。其他发行版和包格式只有通过独立兼容性测试后才列为支持。
- Runtime 只执行应用分发目录中经过校验的二进制文件。
- 发布产物包含依赖版本、构建选项、许可证和必要通知。
- 每次升级 FFmpeg 构建后重新运行格式矩阵和跨平台样本测试。
- Windows、macOS 和 Linux 都必须在断网、干净的测试系统上完成安装与首次启动验收。

FFmpeg 编译选项、编解码器许可和各分发渠道要求必须在格式 manifest 实现前形成版本化构建 profile，并在发布时再次审查。设计不假设所有可编译编码器都适合随产品分发；未进入已批准 profile 的 codec 不得出现在 UI 或协议能力响应中。

## 11. 网页应用与服务端

### 11.1 产品行为

- 匿名即用，不提供账号和永久历史记录。
- 网页只显示一颗主水球。
- 单水球可包含多个批次，服务端按资源限制并行执行多个 FFmpeg Worker。
- 浏览器关闭不立即取消服务端任务。
- 持有临时任务能力令牌的用户可以在有效期内恢复查看进度和下载结果。
- 输入、输出、任务元数据和下载令牌到期后一并删除。

### 11.2 单应用部署

构建产物至少包含：

```text
fluxform-server
ffmpeg/
data/
fluxform.toml
```

`fluxform-server` 单个 Rust 应用负责：

- 提供构建时内嵌的 Web 前端资源。
- 提供版本化 HTTP API 与 SSE。
- 管理 SQLite、队列、配额和临时文件清理。
- 启动并监管 FFmpeg Worker。

它既能直接监听 HTTP，也能部署在 Nginx 后方。Nginx 模式要求：

- SSE 路径关闭代理缓冲。
- 上传路径设置与 FluxForm 相同或更严格的 `client_max_body_size` 和 `client_body_timeout`。
- 上传路径关闭 `proxy_request_buffering`，让应用在接收过程中执行字节、时间和磁盘限制；部署检查验证请求确实未先完整落入 Nginx 临时目录。
- 只有来自显式可信代理地址的转发头才用于计算客户端 IP。
- 前端路由由应用入口回退处理。
- Nginx 只负责 TLS、域名和代理，不要求单独部署前端目录。

### 11.3 上传与任务流程

1. 浏览器先提交文件元数据、目标格式和批次摘要。
2. 服务端在单个 SQLite 事务中检查声明大小、IP 每日配额、并发限制、全站队列、已预留上传字节和磁盘安全余量，并预留上传槽位与声明字节；没有可信长度时预留单文件硬上限。
3. 通过预检后创建有到期时间的上传会话；未开始或中断的会话到期后释放全部预留。
4. 应用将请求体流式写入该任务的 staging 文件，每个 chunk 都更新实际字节数、总耗时和空闲超时；实际大小将超过当前预留时必须先原子扩充预留，扩充失败或超过硬上限、磁盘水位、时间限制时立即中断并删除 staging 文件。
5. `Content-Length` 只用于早期拒绝，不能代替流式计数。上传完成后按实际字节结算预留，并使用内容探测与受限 FFprobe 验证格式。
6. 任务进入有界队列；经过授权的事件流推送队列位置、进度和终态。
7. 成功后创建受授权保护的短期下载 artifact，并展示结果水球。
8. 到期清理器在确认没有活跃 Worker 租约后，删除输入、输出、任务记录和令牌。

### 11.4 配置化限制

以下限制必须可配置并提供安全默认值，但不属于协议固定常量：

- 单文件大小
- 单批文件数与总大小
- 同时上传会话数与全站预留字节
- 上传空闲超时、总时长和废弃会话有效期
- 单 IP 每日任务数
- 单 IP 同时运行数
- 全站并发 Worker 数与队列长度
- 单任务最大运行时间
- 最大输出大小
- 下载有效期
- 磁盘最低空闲量与清理水位

部署者应根据 CPU、磁盘和带宽容量调整这些值。应用启动时校验配置间的一致性。

### 11.5 安全边界

- 文件使用随机内部 ID，用户文件名只作为展示元数据。
- 所有路径必须被限制在任务工作目录内。
- FFmpeg 参数只能由强类型请求生成。
- FFprobe 与 FFmpeg 都使用 manifest 允许的 demuxer/protocol，显式设置协议白名单，并禁用网络协议；仅靠 `file` 白名单不能代替文件系统隔离。
- 公网模式必须启用可验证的 OS 沙箱：Worker 只能读取当前任务输入和只读工具文件，只能写当前任务目录，无网络出口，并受到进程数、CPU、内存、文件大小、打开文件数和运行时间限制。
- 生产服务器的首个受支持沙箱目标是 Linux。若沙箱初始化或能力自检失败，公网上传模式拒绝启动；本地开发模式必须显式选择且不得作为生产默认值。
- 超时、取消或失败时终止完整进程树。
- 日志不记录原始文件内容，不长期保存完整 IP。
- IP 配额是滥用抑制手段，不被视为强身份认证。

首版采用单服务器、SQLite 和本地临时磁盘。队列与存储通过 Rust trait 隔离，以便真实扩容需求出现后替换为 Redis、对象存储和独立 Worker，但首版不实现这些分布式组件。

### 11.6 匿名授权与事件恢复

- 创建上传会话时生成至少 256 bit 随机能力令牌；数据库只保存令牌哈希、作用域和到期时间。
- 能力令牌限定到单个匿名任务或批次，并分别授权状态、事件、取消和下载；所有相关端点逐次校验。
- 令牌不得出现在查询字符串、服务器日志或 Referer 中。浏览器使用内存或 `sessionStorage` 保存；恢复链接只把令牌放在 URL fragment，页面读取后立即清除 fragment。
- 浏览器使用带 `Authorization: Bearer` 的 fetch 流消费 SSE，以避免原生 `EventSource` 无法设置授权头的问题。
- 状态修改请求同时校验 `Origin`，响应设置严格 CSP 与 `Referrer-Policy: no-referrer`。
- 下载响应使用 `Content-Disposition: attachment`、`Cache-Control: no-store` 和 `X-Content-Type-Options: nosniff`。
- 事件恢复遵循第 5.2 节的 revision、重放和快照契约。

### 11.7 文件状态与一致性

数据库和文件系统不能由同一个 SQLite 事务原子提交，因此文件生命周期使用显式状态与幂等协调：

```text
reserved → uploading → staged → queued → running
→ output_staged → committed → expiring → deleted
```

- 每次状态推进先记录可恢复意图，再执行幂等文件操作，最后记录完成状态。
- Worker 持有任务租约；清理器不得删除拥有有效租约的输入或输出。
- 任务 TTL 从终态开始计算，运行中任务不会因创建时间过早而被删除。
- 启动协调器扫描数据库和任务目录，完成未完成的删除、回滚无记录 staging 文件，并核对 committed artifact。
- 配额预留、上传状态与每日计数由 SQLite 保证一致；跨文件系统副作用由协调器最终一致地修复。

## 12. 通用 MCP Server

`fluxform-agent` 是独立本地程序，不依赖 Tauri、网页服务或已安装的桌面版，并随自己的安装包提供 FFmpeg 与 FFprobe。

首发使用通用 MCP stdio，提供：

- `inspect_media`
- `list_conversions`
- `plan_conversion`
- `start_conversion`
- `get_job`
- `cancel_job`
- `batch_convert`
- `cleanup_jobs`

长任务异步执行并立即返回 `job_id`。Agent 通过 `get_job` 获取进度和结果，避免单次 MCP 调用长时间阻塞。

首版 MCP 任务是会话作用域：`job_id` 只在当前 stdio Server 生命周期内有效。客户端关闭 stdin、进程收到退出信号或传输断开时，Server 停止接收新任务、取消仍在运行的 FFmpeg、等待短暂清理窗口并终止残留进程树。已原子提交的用户输出保留；等待队列与临时文件清空。首版不承诺重启后继续 `get_job`，未来若引入常驻 daemon 必须发布新的持久化语义。

安全默认值为：

- 禁止任意 FFmpeg 参数。
- 默认拒绝覆盖现有文件。
- 输出路径必须显式指定或位于受控任务目录。
- 清理命令只删除 Agent 工作目录和临时结果，不删除已成功写入的用户目标文件。
- 失败返回稳定错误码和可操作说明。

后续可以为 Codex 或其他 Agent 制作安装包装，但 MCP 工具语义保持通用。

## 13. 持久化与异常恢复

### 13.1 桌面

- 正常退出清空全部水球、批次和队列。
- 仅保留应用设置、窗口偏好和材质/性能偏好。
- 异常退出后不恢复转换；下次启动按第 3.5 节的任务日志核对并清理孤立临时文件，同时显示一次非正常结束提示。
- 用户已经成功写入的正式输出不会被清理。

### 13.2 网页服务

- 排队任务在服务重启后可以重新入队。
- 运行中任务标记为 `interrupted`；输入仍有效时最多自动从头重试一次。
- SQLite 事务保证数据库内的配额预留、任务创建和状态推进一致；文件系统通过第 11.7 节的幂等协调器恢复。
- 启动协调和周期清理共同处理过期与孤立文件，并跳过持有有效 Worker 租约的任务。

### 13.3 Agent

- 每个任务使用独立工作目录。
- MCP Server 结束时按会话作用域取消任务；异常退出后，下次启动清理孤立临时文件。
- 已完成的用户输出保持不变。
- 新会话无法查询旧 `job_id`；需要 Agent 根据用户目标显式重新提交。

## 14. 验证策略

### 14.1 Rust 单元与属性测试

- 格式矩阵与有向转换边。
- 参数验证和 FFmpeg 命令构造。
- 路径规范化与输出命名。
- 原子 no-replace/replace 提交、状态机和取消/提交竞争条件。
- 上传字节预留、配额、过期、Worker 租约和并发算法。
- 任何用户字符串都不能变成未经验证的命令参数。

### 14.2 转换集成测试

- 使用小型真实视频、音频和图片样本。
- 验证输出存在、可被 FFprobe 读取且关键媒体属性符合预期。
- 覆盖成功、超时、取消、损坏输入、恶意嵌套协议、目标路径竞争和磁盘不足路径。
- Windows、macOS 和 Linux 分别验证打包后的 FFmpeg 路径。
- 对 capability manifest 中每条边验证实际 container、codec、stream mapping、Alpha/方向/metadata 策略。

### 14.3 协议与入口测试

- HTTP、Tauri IPC 和 MCP 对等价请求产生一致的计划、状态和错误码。
- JSON Schema 兼容性测试防止意外破坏 `v1`。
- Web 覆盖流式超限中止、预留竞争、废弃上传、磁盘水位、能力令牌所有端点、SSE revision/重放/快照和租约感知清理。
- MCP 覆盖异步任务、stdio EOF 取消、进程树终止、路径权限和结构化错误。

### 14.4 视觉与桌面测试

- Water Lab 对关键状态做视觉回归截图。
- 所有 Shader 在目标浏览器/WebView 编译通过。
- 验证低性能档位、减少动态效果和 WebGL 上下文恢复。
- 验证 GPU 禁用时的静态水球仍可完成完整键盘与屏幕阅读器流程，并验证第 8.4 节性能预算。
- 桌面覆盖重复启动创建窗口、多窗口资源调度、单球关闭和最后窗口退出确认。
- 在 Windows、macOS、X11 和 Wayland 上验证透明区域命中、文件拖放、焦点、DPI、多显示器和约定降级。
- 在三平台断网干净环境中验证安装与首次启动；macOS 额外验证签名、公证和直接 DMG 分发。

### 14.5 黄金路径

每个正式入口至少验证：

```text
输入文件
→ 类型与能力识别
→ 选择格式和参数
→ 提交与排队
→ 进度
→ 完成与结果访问
→ 错误重试
→ 取消与清理
```

## 15. 迭代与迁移顺序

### 阶段 0：契约与可行性门槛

- 建立最小 `fluxform-protocol` 状态、事件、revision 和错误模型，并生成 Water Lab fixtures。
- 冻结第一版 FFmpeg 构建/许可证 profile，再据此冻结 capability manifest。
- 在 Windows、macOS、X11 和 Wayland 制作最小 Tauri 水球窗口探针，验证透明、命中、拖放、拖动、重复启动和降级路径。
- 制作最小服务端安全探针，验证流式上传硬限制、能力令牌、Linux Worker 沙箱、协议白名单和原子输出提交。
- 任一门槛失败时先调整产品承诺，不进入依赖该承诺的完整实现。

### 阶段 1：Water Lab

- 基于阶段 0 的协议 fixtures 建立共享水球渲染器和状态机。
- 确定深海蓝、高透明水体材质。
- 验证待机、吸附、融合、完成、错误、静态 fallback 和性能分级。

### 阶段 2：Rust 转换内核

- 建立 Rust workspace、已批准 manifest 和 FFmpeg 适配器。
- 通过测试壳完成真实转换、沙箱策略和跨平台进程控制。

### 阶段 3：网页单应用

- 完成流式上传、能力令牌、配额预留、文件协调器和 Worker 队列。
- 将 Web 前端嵌入 `fluxform-server`。
- 验证直接运行和 Nginx 代理两种部署。

### 阶段 4：Tauri 桌面端

- 在阶段 0 已验证的窗口能力上完成单水球离线转换。
- 再完成重复启动、多窗口、共享 Runtime 和退出确认。
- 发布 Windows、macOS 和已声明 Linux 基线的离线安装包。

### 阶段 5：通用 MCP Server

- 提供独立打包、本地会话作用域异步任务和通用 MCP 工具。
- 为不同 Agent 补充安装说明，而不改变核心协议。

### 阶段 6：旧版本退役

- 迁移期间保留 C# 版本作为行为和结果参考。
- 新 Rust 引擎和至少一个新入口稳定前，不删除旧代码。
- 新桌面版达到约定功能基线后停止发布 WPF。
- 最后移除 .NET/WPF 构建、安装和发布流程。

## 16. 风险与控制

- **真实水体性能：** 用分级渲染、动态分辨率和按交互升档控制，不以持续完整流体模拟换取生命感。
- **透明窗口平台差异：** 在阶段 0 验证命中与分发可行性；macOS 直接分发，Wayland 不承诺置顶，并提供明确的不透明无边框降级。
- **多窗口资源竞争：** 所有窗口共享单一 Runtime，由全局并发器限制 FFmpeg 进程数。
- **匿名服务滥用：** 通过流式字节限制、原子预留、IP、并发、队列、时间、磁盘和输出限制共同抑制，明确其不是强认证。
- **匿名结果泄露：** 所有任务端点使用高熵、有作用域、短期能力令牌，禁止查询字符串携带并对下载禁用缓存。
- **恶意媒体输入：** 使用内容探测、协议/demuxer 白名单、无网络 OS 沙箱、超时、资源上限、依赖更新和真实模糊测试样本。
- **数据库与文件系统分离：** 使用显式文件状态、Worker 租约和幂等启动协调器恢复，而不声称 SQLite 能原子提交文件操作。
- **FFmpeg 分发：** 在格式实现前固定构建 profile，校验二进制、记录许可证与构建选项，并在每次发布时复核。
- **重写范围过大：** 按入口独立迭代，旧版保留至新实现通过黄金路径和转换回归。

## 17. 完成标准

设计实现达到以下结果时，可认为新平台架构完成：

1. 网页、桌面和 MCP 使用相同 Rust 转换规则、状态和错误语义。
2. Water Lab 与桌面共享同一水球材质和状态映射。
3. 网页可作为单应用直接运行，也可在流式限额、能力授权和 Worker 沙箱均启用时部署在 Nginx 后方。
4. 桌面在声明的 Windows、macOS 和 Linux 基线上离线安装与运行，并随包提供经过验证的 FFmpeg 和必要 WebView 运行时。
5. 重复启动桌面应用可创建新水球，但后台保持单 Runtime。
6. 最后一颗水球关闭时能确认并可靠终止所有转换进程。
7. MCP Server 可被通用 Agent 独立安装和调用，不依赖其他入口。
8. 所有输出显式指定 muxer/codec，并通过同文件系统的原子提交；取消、失败和崩溃路径均能协调临时文件。
9. 首版 capability manifest 与获准分发的 FFmpeg profile 一致，并通过三平台真实样本测试。
10. 旧 WPF 仅在新桌面入口达到约定功能基线后退役。

## 18. 关键技术依据

- Tauri 窗口配置与 macOS 透明窗口限制：<https://v2.tauri.app/reference/config/>
- Tauri Windows 离线 WebView2 安装：<https://v2.tauri.app/distribute/windows-installer/>
- Tauri Linux AppImage 基线限制：<https://v2.tauri.app/distribute/appimage/>
- Tao 的 X11/Wayland 窗口能力差异：<https://docs.rs/tao/latest/src/tao/window.rs.html>
- Nginx 请求体缓冲与上传限制：<https://nginx.org/en/docs/http/ngx_http_proxy_module.html>、<https://nginx.org/en/docs/http/ngx_http_core_module.html>
- FFmpeg 协议白名单：<https://ffmpeg.org/ffmpeg-protocols.html>
- FFmpeg 输出格式显式选择：<https://www.ffmpeg.org/ffmpeg.html>
- FFmpeg 分发与许可证注意事项：<https://ffmpeg.org/legal.html>
