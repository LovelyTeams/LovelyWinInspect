<div align="center">

<img src="docs/logo.png" width="128" alt="LovelyWinInspect logo" />

# LovelyWinInspect

**Windows 安全基线核查 & 应急响应工作台**

一个 exe，双击运行，几十秒内摸清一台 Windows 主机的安全配置和异常痕迹。

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows)
![Rust](https://img.shields.io/badge/Rust-2024%20edition-orange?logo=rust)
![UI](https://img.shields.io/badge/UI-GPUI-8A2BE2)
![Offline](https://img.shields.io/badge/离线运行-无需安装-success)

[功能](#-功能一览) · [快速开始](#-快速开始) · [检测范围](#-检测范围) · [构建](#-从源码构建) · [更新日志](CHANGELOG.md) · [常见问题](#-常见问题) · [许可证](#-许可证)

</div>

---

## 📖 简介

LovelyWinInspect 面向**安全运维与应急响应人员**，把日常需要在 `regedit`、`eventvwr`、`taskschd.msc`、`netstat`、`secpol.msc` 之间来回切换的排查工作，整合进一个原生桌面应用：

- 🛡️ **基线核查**：对照 CIS、微软安全基线和等保 2.0 的常见要求，逐项检查本机配置，并给出加固建议
- 🔍 **应急排查**：采集进程、网络、启动项、账户、日志和文件痕迹，自动标出异常
- 🧭 **入侵还原**：把分散的痕迹按 ATT&CK 战术阶段汇总，生成一条可以回溯的时间线
- 📦 **证据固定**：一键导出 HTML / JSON / CSV 报告、原始日志和文本证据，并附 SHA256 清单

工具使用 **Rust + [GPUI](https://www.gpui.rs/)** 编写，数据全部通过 Win32 API 和注册表原生读取：**只读、离线、单文件、无需安装任何运行时**。

---

## ✨ 功能一览

| | 模块 | 说明 |
|:-:|---|---|
| 🏠 | **总览** | 主机概况、高危发现、基线合规率、可疑持久化、外联统计、证据采集时间线 |
| 🛡️ | **基线核查** | 账户策略 · 审计策略 · 日志配置 · 安全选项 · 网络与服务 · 系统防护，**100+ 项**检查，每项附期望值、当前值和加固建议 |
| 🧭 | **入侵还原** | 10 个 ATT&CK 战术阶段汇总，日志、持久化、文件、进程痕迹合并成一条时间线，可以按阶段和风险筛选 |
| ⚙️ | **进程分析** | 路径、命令行、用户、父子关系、Authenticode 签名（内嵌签名和编录签名都校验），识别系统进程伪装和父进程异常；列表 / 进程树两种视图，可加载进程模块（DLL）并逐个校验签名 |
| 🌐 | **网络连接** | TCP/UDP（IPv4/IPv6）连接和监听端口，关联到进程，标出公网外联；DNS 缓存（为远程地址补充域名）与 ARP / 邻居表快照，提示网关 MAC 重复 |
| 🚀 | **启动项** | 覆盖 25+ 类自启动位置，详见[检测范围](#-检测范围) |
| 👥 | **账户与登录** | 本地账户、隐藏账户、新建账户、组成员、当前会话、登录来源统计、暴力破解聚合 |
| 📜 | **日志分析** | 登录、账户变更、服务与计划任务、日志清除、远程桌面、远程访问、PowerShell、Defender 等关键事件 |
| 📁 | **文件排查** | 新增可执行文件和脚本、Web 目录变更、执行痕迹（Prefetch / BAM）、用户活动记录、Hosts、PowerShell 历史 |
| 💽 | **文件管理** | 目录树浏览（含隐藏 / 系统文件）、按名称 / 类型 / 时间 / 大小递归搜索可疑文件；文本、十六进制与 PE 信息预览（节熵值、导入表、敏感 API）；可疑文件隔离与还原 |
| 🗄️ | **注册表取证** | 程序启动记录 (UserAssist)、ShimCache、MuiCache、最近文档、地址栏与搜索历史、文件对话框记录、网络连接历史、网络共享、Office 信任文档与宏设置、工具使用痕迹、敏感键变更时间线 |
| ⚙️ | **设置** | 自动排查、默认回溯天数、浅色 / 深色 / 跟随系统主题、导出目录与默认导出内容；版本更新直连 GitHub Releases 检查新版本 |
| 📤 | **证据导出** | HTML 报告、JSON、CSV、原始 `.evtx`、文本证据，自动生成 `manifest_sha256.txt` |

**体验细节**

- 🎨 Mini 侧边栏工作台布局，有浅色和深色两套主题；侧边栏数字角标提示各模块的待关注项
- ⚡ 采集过程实时展示，每完成一个阶段就刷新界面；大列表使用虚拟滚动，几千条记录也流畅
- 🔎 每条记录都可以点开详情抽屉，一键复制全部字段；抽屉不遮挡列表，可边看详情边切换记录
- 🔍 各列表支持关键字搜索（Ctrl+F）与点击表头排序；↑ / ↓ 切换记录，Esc 关闭详情，Ctrl+C 复制当前详情
- 🏷️ 可给任意记录打上“确认恶意 / 可疑待查 / 误报 / 已处理”标签并写备注，导出报告时一并带上
- 🧾 审计策略或日志容量不足时，日志类结论会带上“可能不完整”的提示，避免误判
- 🖱️ 右键菜单与详情抽屉提供处置动作：定位文件、复制路径与命令行、计算哈希、在注册表中定位；结束进程、恢复隐藏文件、禁用启动项、停止服务、删除计划任务（自动备份 XML）、防火墙封禁 IP、隔离文件。高危动作均需二次确认并写入处置日志
- 🖥️ 支持无界面模式，可以批量或脚本化采集

---

<!--
## 🖼️ 界面预览

把截图放进 docs/screenshots/ 后取消本段注释，并在顶部导航中加回“截图”链接。
建议在测试机或虚拟机中截取，避免泄露真实主机名、IP 与账户信息。
可用 `LovelyWinInspect.exe --page <名称>` 直接打开指定页面再截图。

| 总览 | 入侵还原 |
|:-:|:-:|
| ![总览](docs/screenshots/overview.png) | ![入侵还原](docs/screenshots/timeline.png) |
| **基线核查** | **启动项排查** |
| ![基线核查](docs/screenshots/baseline.png) | ![启动项](docs/screenshots/persistence.png) |

---
-->

## 🚀 快速开始

1. 从 [Releases](../../releases) 下载 `LovelyWinInspect.exe`
2. **右键 → 以管理员身份运行**。也可以直接双击，再点击右上角的“非管理员 · 点击提权重启”
3. 程序启动后自动开始排查，一般 20～60 秒完成，具体取决于日志量和磁盘
4. 在左侧侧边栏切换模块查看结果，在“导出”页打包证据

> 💡 安全日志、审计策略和部分注册表需要管理员权限才能读取。非管理员运行时，相关检查项会显示为“无法检测”。

### 命令行

```text
LovelyWinInspect.exe [选项]

  --page <名称>      指定启动页：overview | baseline | timeline | process | network |
                     persistence | account | eventlog | file | registry | files | export
  --tab <名称>       配合 --page 预选页内视图：dns | arp（网络）、rootcert（启动项）、ads（文件）、
                     tree（进程树）
  --open <路径>      打开文件管理并定位到指定文件或目录（选中文件时显示预览）
  --json <文件>      无界面模式：完成采集后把结果写入 JSON 文件
  --days <N>         日志与文件痕迹的回溯天数（默认 30）
  --export           无界面模式下同时导出完整证据包
  --evtx             配合 --export，额外导出原始 .evtx 日志
  --check-update     查询 GitHub Releases 上的最新版本后退出（加 --pre 包含预发布）
  -V, --version      显示版本号
  -h, --help         显示帮助
```

例如在多台主机上批量采集最近 7 天的数据并打包证据：

```bash
LovelyWinInspect.exe --json result.json --days 7 --export
```

设置环境变量 `LWI_LOG=1` 后，程序会把内部日志输出到 stderr，便于排查问题。设置保存在 `%APPDATA%\LovelyWinInspect\settings.json`。

---

## 🔬 检测范围

<details>
<summary><b>🛡️ 基线核查（100+ 项）</b></summary>

| 分类 | 主要检查项 |
|---|---|
| 账户策略 | 密码复杂度、长度、有效期、历史；账户锁定阈值、时长、计数器重置时间；Guest、内置管理员；空密码和永不过期的账户；管理员组成员；LAPS（域成员） |
| 审计策略 | 登录、凭据验证、账户与组管理、进程创建、策略变更、特殊登录、计划任务、服务安装、敏感特权使用、可移动存储等 20+ 个子类别；命令行记录；PowerShell 脚本块、模块日志和转录 |
| 日志配置 | Security、System、Application 的日志容量、保留方式、自动归档 |
| 安全选项 | UAC 及其增强项、LM/NTLM 认证级别、NTLM 会话安全、匿名枚举与匿名共享、WDigest、LSA 保护、自动登录、远程 UAC 限制、用户权限分配、CredSSP、登录横幅、屏幕保护锁定等 |
| 网络与服务 | SMBv1、SMB 签名、不安全的来宾登录、RDP 的 NLA、加密级别和会话超时、远程注册表、高危服务、防火墙三个配置文件、WinRM、LLMNR、NetBIOS、mDNS、WebClient、Print Spooler、网络共享、对外监听的高危端口、TCP/IP 协议栈加固 |
| 系统防护 | 杀毒软件实时防护、Defender 策略与排除项、篡改防护、自动更新、补丁时效、PowerShell 2.0、安全启动、VBS/Credential Guard、BitLocker、ASR 规则、AlwaysInstallElevated、时间同步、漏洞缓解选项、卷影副本（只读列举） |

域成员专属项只在已加域的主机上检查，服务器专属项只在 Server 系统上检查。

</details>

<details>
<summary><b>🚀 启动项与持久化位置（25+ 类）</b></summary>

- 注册表 Run / RunOnce / RunOnceEx / Policies\Explorer\Run（HKLM 和所有已加载的用户配置），以及 StartupApproved 中的启用状态
- 系统服务与驱动（ImagePath、ServiceDll、签名），服务故障后执行的命令
- 计划任务（解析 XML），包括缺少安全描述符的隐藏任务
- 启动目录（解析 `.lnk` 目标）、登录脚本和组策略脚本、PowerShell 配置文件
- Winlogon（Shell、Userinit）、IFEO 与 SilentProcessExit、AppInit_DLLs、AppCertDlls
- LSA 认证包、通知包和安全包，BootExecute，KnownDlls 排除项，WOW64 模拟层
- 打印监视器、时间提供程序、Netsh Helper、Active Setup
- WMI 永久事件订阅、用户级 COM 注册覆盖、可执行文件关联、屏幕保护程序
- 端口转发规则、指向可写目录或无签名程序的防火墙入站放行规则
- 辅助功能程序是否被替换（与系统程序比对哈希）
- 受信任根证书：本机与各用户的 ROOT 存储，提示回溯期内新写入的自签名根证书

</details>

<details>
<summary><b>📜 事件日志</b></summary>

| 通道 | 事件 ID |
|---|---|
| Security | 4624 / 4625（登录，聚合暴力破解）、4648、4688、4697、4698 / 4699 / 4702、4719、4720 / 4722 / 4724 / 4725 / 4726 / 4738 / 4781、4728 / 4732 / 4733 / 4756、5140、1102 |
| System | 7045、7040、104、6005 / 6006 / 6008 |
| 远程桌面 | RemoteConnectionManager 1149、LocalSessionManager 21 / 24 / 25、RDPClient 1024 |
| PowerShell | 4104（系统标记的告警级脚本块）、400（2.0 引擎调用） |
| 其他 | Defender 1116 / 1117 / 5001 / 5007 / 5010 / 5012、TaskScheduler 106 / 140 / 141、WMI-Activity 5861、BITS 59、WinRM 91 |

</details>

<details>
<summary><b>📁 文件与活动痕迹</b></summary>

- 临时目录、公共目录、下载目录、ProgramData 等位置中新增的可执行文件和脚本（校验签名，识别双扩展名），以及下载来源和备用数据流
- Web 根目录中近期变更的脚本（IIS、XAMPP、phpStudy、Tomcat 等）
- 执行痕迹：Prefetch、BAM
- 用户活动：最近访问、运行对话框记录、远程桌面外连记录、近期安装的软件、USB 存储设备
- Hosts 文件、PowerShell 命令历史

</details>

---

## 📦 证据包结构

```text
LovelyWinInspect_Reports/<主机名>_<时间>/
├── report.html            # 可直接发送的图文报告
├── report.json            # 完整结构化数据
├── manifest_sha256.txt    # 所有证据文件的 SHA256 清单
├── csv/                   # 调查发现、基线、时间线、进程、连接、DNS 缓存、邻居表、卷影副本、启动项、账户、事件、文件
├── evtx/                  # 原始日志（可选）
└── evidence/              # hosts、PowerShell 历史、非微软计划任务 XML、进程 / 连接 / DNS 缓存 / ARP 快照、处置动作日志
```

---

## 🤖 持续集成

仓库内置 [GitHub Actions 工作流](.github/workflows/build.yml)：在 `windows-latest` 上执行单元测试与构建，
跑一次无界面采集作为冒烟测试，再用 UPX 压缩（校验官方发布包 SHA256，约 14 MB → 4 MB），
上传构建产物；推送 `v*` 标签时自动创建 Release。

> UPX 会明显提高部分杀毒软件的误报率。若不需要压缩，可在 Actions 页面手动触发并取消勾选 UPX。

## 🔧 从源码构建

**环境要求**

- Windows 10 / 11（x64）
- [Rust](https://rustup.rs/) 1.85 及以上（项目使用 Rust 2024 edition）
- Visual Studio Build Tools，需要勾选“使用 C++ 的桌面开发”（提供 MSVC 链接器和 Windows SDK）

**构建**

```bash
git clone <仓库地址>
cd LovelyWinInspect
cargo build --release
```

产物位于 `target/release/LovelyWinInspect.exe`。

**发布新版本**

1. 修改 `Cargo.toml` 中的 `version`
2. 在 [CHANGELOG.md](CHANGELOG.md) 顶部添加该版本的更新日志：`## [x.y.z] - 日期`
3. 提交并推送后打标签：`git tag vx.y.z`，再执行 `git push origin vx.y.z`

CI 会先检查标签与 `Cargo.toml` 版本一致、更新日志不为空，任何一项不满足就不会发布；构建通过后用该版本的更新日志加上下载说明与 SHA256 生成 Release 说明。本地预览发布说明：`./tools/release_notes.ps1 -Tag vx.y.z -Exe target/release/LovelyWinInspect.exe`。

**更换图标**

把新图片保存为 `assets/logo.png`（也支持 `.webp` / `.jpg`），先执行 `python tools/make_icons.py`，再执行 `cargo build --release`。需要安装 Pillow。

脚本会生成标题栏 logo、报告 logo 和多尺寸的 `app.ico`，构建时自动嵌入 exe。

### 项目结构

```text
src/
├── main.rs            # 入口、窗口、无界面模式
├── model.rs           # 数据模型（全部可序列化）
├── actions.rs         # 处置：结束进程、恢复隐藏属性、禁用启动项等（唯一的写操作入口）
├── analysis.rs        # 研判：风险评分、调查发现、时间线、ATT&CK 汇总
├── report.rs          # 导出：HTML / JSON / CSV / evtx / 证据清单
├── collect/           # 采集：主机、进程、网络、启动项、账户、会话、日志、文件、基线、签名校验
└── ui/                # GPUI 界面：标题栏、侧边栏、详情抽屉和各个页面
assets/                # 图标资源
tools/                 # 辅助脚本
```

---

## 🧭 设计原则

- **采集只读**：采集阶段只读取系统状态，不修改注册表、服务或文件。证据只写入导出目录；读取本地安全策略时会生成一个临时文件，读完立即删除
- **处置可控**：右键菜单中的处置动作是唯一会修改系统的入口，破坏性动作均需二次确认，且全部记录到 `%APPDATA%\LovelyWinInspect\actions.log` 并随证据包导出；禁用自启动项使用与任务管理器相同的机制，可随时恢复
- **原生**：尽量直接调用 Win32 API（Toolhelp、IP Helper、EvtQuery、NetAPI、WinTrust 等），减少对外部命令的依赖
- **离线**：不联网、不上传任何数据；签名校验也只使用本地缓存，不做在线吊销检查
- **可解释**：每个风险判定都附带研判依据、原始数据位置和处置建议

---

## ❓ 常见问题

<details>
<summary><b>杀毒软件提示风险或拦截？</b></summary>

工具需要大量读取系统敏感位置（服务、启动项、安全日志、LSA 配置等），而且自行编译的程序没有数字签名，所以可能触发部分杀软的启发式规则。建议在杀软中把工具目录加入信任；正式分发时可以为 exe 加上代码签名，减少误报。

</details>

<details>
<summary><b>为什么必须用管理员权限运行？</b></summary>

安全日志、审计策略、本地安全策略、计划任务目录和部分进程信息只有管理员才能读取。非管理员也能运行，但相关检查项会标记为“无法检测”。

</details>

<details>
<summary><b>发现了“高危”就一定是被入侵了吗？</b></summary>

不一定。规则基于异常特征，例如“未签名且位于可写目录”或“非默认配置”，目的是帮你快速缩小排查范围。最终结论需要结合业务背景人工研判。每条发现都附有依据和原始数据位置，方便复核。

</details>

<details>
<summary><b>支持哪些系统？</b></summary>

面向 Windows 10 / 11 开发和测试。界面基于 GPUI，需要 Windows 10 1703 或 Windows Server 2019 及以上，服务器专属检查项会自动启用；Windows Server 2016 尚未验证。

Windows Server 2008 / 2008 R2 / 2012 等旧系统目前无法启动。后续计划提供只含命令行采集的精简版，在旧系统上导出 JSON，再导入到新系统的界面中分析。详见[旧版 Windows 兼容性与离线分析规划](docs/legacy-os-and-json-import.md)。

</details>

---

## 🗺️ 路线图

- [ ] 导入 JSON 报告进行离线分析
- [ ] 旧系统（Server 2008 R2 等）命令行采集精简版
- [ ] 多主机结果汇总与对比
- [ ] 自定义规则与白名单
- [ ] 更多执行痕迹解析（Amcache、ShimCache、SRUM 等）
- [ ] 报告模板自定义与 PDF 导出
- [ ] 英文界面

欢迎通过 Issue 提出需求或反馈误报。

---

## ⚠️ 免责声明

本工具仅用于**授权范围内**的安全检查、基线加固与应急响应。请在获得主机所有者授权的前提下使用，使用者需自行承担使用本工具产生的一切后果。

---

## 🙏 致谢

部分检查项的思路参考了以下优秀的开源项目和资料。所有代码均在本项目中独立实现：

[HardeningKitty](https://github.com/scipag/HardeningKitty) ·
[Microsoft Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319) ·
[Kansa](https://github.com/davehull/Kansa) ·
[Live-Forensicator](https://github.com/Johnng007/Live-Forensicator) ·
[KapeFiles](https://github.com/EricZimmerman/KapeFiles) ·
[Velociraptor](https://github.com/Velocidex/velociraptor) ·
[Emergency-Response-Notes](https://github.com/Bypass007/Emergency-Response-Notes)

界面基于 Zed 团队开源的 [GPUI](https://github.com/zed-industries/zed/tree/main/crates/gpui) 构建，图标风格参考 [Lucide](https://lucide.dev/)（ISC）。

---

## 📄 许可证

本项目采用 **[GNU Affero General Public License v3.0](LICENSE)**（AGPL-3.0）。

<div align="center">

Made with 💙 for Lovelyteams

</div>
