# 旧版 Windows 兼容性与离线分析规划

> 起因：[Issue #1 无法在 server 2008 上运行](https://github.com/LovelyTeams/LovelyWinInspect/issues/1)
> 记录日期：2026-10-19（基于 v0.1.0 Release 构建分析）

## 结论

- **当前版本不支持 Windows Server 2008 / 2008 R2**，图形界面也不可能在这两个系统上运行。
- 图形界面的实际最低要求是 **Windows 10 1703 / Windows Server 2019**。Server 2016（内核版本 1607）按依赖推断同样无法启动，**尚未实测**。
- 决定：**先继续开发当前版本**。旧系统支持按下面两个阶段推进：
  1. 在图形界面里加入「导入 JSON 报告」，支持离线分析；
  2. 给旧系统单独构建一个只有命令行的精简版，在目标机上采集 JSON，再拿到新系统上导入分析。

## 现象

在 Server 2008 上双击启动，系统弹出加载错误：

```
LovelyWinInspect.exe - 无法找到入口
无法定位程序输入点 GetSystemTimePreciseAsFileTime 于动态链接库 kernel32.dll 上。
```

这是 Windows 加载器在进入 `main` 之前做导入解析时失败的。任何静态导入缺失都会让整个 exe 无法启动，**`--json` 无界面模式也会一起失败**。

## 原因：静态导入了新系统才有的 API

用 `pefile` 导出 Release 构建的导入表后，按来源整理如下（只列出旧系统缺失的项）：

| 来源 | 导入 | 最低系统 |
|---|---|---|
| Rust 标准库（1.78 起默认 target 只支持 Win10+） | `kernel32!GetSystemTimePreciseAsFileTime` | Win8 / 2012 |
| | `bcryptprimitives!ProcessPrng` | Win7 不可用 |
| | `api-ms-win-core-synch-l1-2-0!WaitOnAddress` / `WakeByAddress*` | Win8 / 2012 |
| 动态 CRT（Rust MSVC 默认） | `VCRUNTIME140.dll`、`api-ms-win-crt-*.dll` | 需安装 VC++ 2015+ 运行库，旧系统还需安装 UCRT（KB2999226） |
| GPUI 渲染与窗口 | `dcomp!DCompositionCreateDevice` | Win8 |
| | `dxgi!CreateDXGIFactory2` | Win8.1 |
| | `api-ms-win-shcore-scaling-l1-1-1!GetDpiForMonitor` | Win8.1 |
| | `user32!GetDpiForWindow` | Win10 1607 |
| | `dwrite` 中的 `IDWriteFactory5` / `IDWriteFontSetBuilder1` | Win10 1703 |
| | `icuuc!u_strlen`（`destination_list.rs`，任务栏跳转列表） | Win10 1703 |
| | `combase.dll`、`api-ms-win-core-winrt-*` | Win8 |
| 本项目代码 | `wintrust!CryptCATAdminAcquireContext2` / `CryptCATAdminCalcHashFromFileHandle2`（[signature.rs](../src/collect/signature.rs)） | Win8 / 2012 |
| | `kernel32!K32GetProcessMemoryInfo`（[process.rs](../src/collect/process.rs)） | Win7 / 2008 R2（Vista 内核上只有 `psapi!GetProcessMemoryInfo`） |

GPUI 这一层是根本限制：它的 Windows 后端基于 DirectComposition、DXGI 1.3 和 DirectWrite 的 Win10 接口，不 fork GPUI 就无法降级。所以旧系统上只能放弃界面，走命令行采集。

### 顺带发现的现有问题（与旧系统无关）

1. **C 运行库是动态链接的**。没装过 VC++ 运行库的纯净服务器，即使是新系统，也会因为缺 `VCRUNTIME140.dll` 无法启动，和 README 中「无需安装任何运行时」的说法不符。修复方法是静态链接 CRT：

   ```toml
   # .cargo/config.toml
   [target.x86_64-pc-windows-msvc]
   rustflags = ["-C", "target-feature=+crt-static"]
   ```

2. **无界面模式写出的 JSON 没有填 `tool` 和 `stages` 字段**（见 `main.rs` 的 `headless`），导入时无法识别是哪个版本采集的。做导入功能前应先补上。

## 阶段一：导入 JSON 报告进行离线分析

目标：采集机只负责 `--json` 落盘，分析、研判、出报告都在分析机上的图形界面里完成。这个功能对新系统同样有用，比如批量采集后集中分析，或复核别人发来的结果。

### 可行性

- `ScanReport` 及其所有子结构都已经 `derive(Deserialize)`，可以直接用 `serde_json::from_str` 读回来。
- `analysis::analyze` 只读写报告数据，不访问本机，所以导入后可以重新跑一遍分析，让旧数据也能用上新规则。
- `baseline::run` 依赖在线读取注册表和策略，不能离线重跑，导入时保留原结果。

### 设计要点

- **入口**：总览页或导出页加「导入报告」按钮；命令行支持 `--open <file.json>`；GPUI 已经注册了拖放（`RegisterDragDrop`），可以支持把文件拖进窗口。
- **版本兼容**：
  - 给 `ScanReport` 加 `schema_version` 字段；
  - 所有集合字段统一加 `#[serde(default)]`（目前只有 `dns_cache`、`neighbors`、`registry`、`shadow_copies` 加了），保证老版本导出的 JSON 能读；
  - 遇到比当前程序更新的 `schema_version` 时给出提示，仍尽量加载。
- **分析时间基准**：`analyze` 里的 `since = days_ago(lookback_days)` 现在以「当前时间」为基准。导入时必须改为以报告的 `finished`（或 `started`）为基准，否则回溯窗口会整体偏移，旧报告的事件全部落到窗口外。
- **离线模式（必须做）**：导入的数据来自另一台主机，右键菜单里作用于本机的动作必须禁用，否则会误操作分析机：
  - 禁用：结束进程、恢复隐藏文件、禁用启动项、定位文件、在注册表中定位、计算哈希；
  - 保留：复制字段、复制路径与命令行等纯文本操作；
  - 界面顶部常驻提示「离线报告：主机名 · 采集时间 · 工具版本」，避免把数据误认成本机的；
  - 离线模式下禁止「开始排查」覆盖当前报告，或者先确认再切回在线模式。
- **再导出**：导入的报告可以再导出 HTML / JSON / CSV，但原始 `.evtx` 和文本证据不在本机，不能导出；`manifest_sha256.txt` 中注明数据来源文件及其 SHA256。
- **不可信输入**：JSON 来自可能已被入侵的主机，需要：
  - 限制文件大小，解析失败时给出明确的错误位置；
  - 字符串字段在 HTML 报告导出时必须转义（需确认现有导出逻辑是否覆盖所有字段）；
  - 不根据报告内容自动打开路径或链接。

## 阶段二：旧系统命令行精简版（`LovelyWinInspect-legacy.exe`）

目标：在 Server 2008 R2 SP1（以及视情况在 2008 SP2）上运行 `--json` / `--export` 完成采集。

### 改动清单

1. **拆分 GPUI**：新增默认开启的 cargo feature `gui`，关闭时不编译 `ui/`、`theme`、`assets`，也不依赖 gpui，`main` 只保留命令行分支。
   - 已确认 `collect/`、`analysis`、`model`、`report` 基本不依赖 gpui；唯一的耦合是 `report.rs` 引用了 `assets::LOGO_SMALL_PNG`，需要把这个常量移到不依赖 gpui 的模块。
2. **补齐标准库的 Win8 API**，两条路线：
   - **YY-Thunks**（推荐）：stable 工具链，链接一个 obj 即可，能覆盖到 Vista / 2008 SP2。属于外部二进制依赖，需要像 UPX 一样固定版本并校验 SHA256。
   - **nightly + `x86_64-win7-windows-msvc` + `build-std`**：官方 tier 3 target，只支持 Win7 / 2008 R2 及以上，CI 需要 nightly。
3. **代码回退**：
   - `signature.rs`：运行时用 `GetProcAddress` 检测 `*2` 版本，缺失时退回 `CryptCATAdminAcquireContext` / `CryptCATAdminCalcHashFromFileHandle`（SHA1 编录）；
   - `process.rs`：`K32GetProcessMemoryInfo` 改为动态解析，Vista 内核上回退到 `psapi!GetProcessMemoryInfo`。
4. **静态 CRT**：legacy 版必须开启 `+crt-static`，否则还要求目标机安装 UCRT 和 VC++ 运行库。
5. **复查导入表**：去掉 GPUI 后，`windows` crate 自身是否仍会带入 `combase.dll`、`api-ms-win-core-winrt-error` 等新系统 DLL，要以实际构建产物的导入表为准。
6. **采集项差异**：旧系统上部分事件通道和注册表位置不存在，要逐项确认对应检查标记为「无法检测」，而不是报错或中断。

### CI 与验收

- CI 增加一个 job，产出 `LovelyWinInspect-legacy.exe`，并用脚本检查导入表里没有 Win8+ 的 API（可以维护一份禁止列表，命中即失败）。
- `windows-latest` 上只能做 `--version` / `--json` 冒烟测试；真实兼容性需要在 2008 R2 SP1 纯净虚拟机上人工验证一次 `--json` 和 `--export`。

## 待确认

- [ ] Issue 用户用的是 Server 2008 还是 2008 R2（决定是否必须走 YY-Thunks 路线）
- [ ] Server 2016 实测能否启动图形界面，并据此更新 README 的系统要求
- [ ] 是否接受引入 YY-Thunks 作为构建依赖

## 附：检查导入表

```python
# python -I check_imports.py target/release/LovelyWinInspect.exe
import sys, pefile
pe = pefile.PE(sys.argv[1], fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
for e in pe.DIRECTORY_ENTRY_IMPORT:
    names = sorted(i.name.decode() if i.name else f"#{i.ordinal}" for i in e.imports)
    print(e.dll.decode(), ", ".join(names))
```
