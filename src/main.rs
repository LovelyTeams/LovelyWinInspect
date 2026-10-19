#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod actions;
mod analysis;
mod assets;
mod collect;
mod fallback;
mod model;
mod report;
mod settings;
mod theme;
mod ui;
mod update;

use gpui::{App, AppContext, Application, Bounds, TitlebarOptions, WindowBounds, WindowOptions, px, size};


/// 无界面模式：`LovelyWinInspect.exe --json out.json [--days N] [--export [--evtx]]`，便于批量/脚本化采集。
fn headless(args: &[String]) -> bool {
    let Some(pos) = args.iter().position(|a| a == "--json") else { return false };
    let out = args.get(pos + 1).cloned().unwrap_or_else(|| "lovelywininspect.json".into());
    let days = days_arg(args).unwrap_or(30);
    let report = fallback::collect_all(days, |stage, summary, ms| println!("[{}] {} ({} ms)", stage.label(), summary, ms));
    if args.iter().any(|a| a == "--export") {
        let opts = report::ExportOptions { evtx: args.iter().any(|a| a == "--evtx"), ..Default::default() };
        match report::export(&report, opts, None) {
            Ok(r) => println!("证据已导出到 {}（{} 个文件）", r.dir.display(), r.files.len()),
            Err(e) => eprintln!("导出失败: {e}"),
        }
    }
    match serde_json::to_string_pretty(&report).map(|j| std::fs::write(&out, j)) {
        Ok(Ok(())) => println!("已写入 {out}"),
        Ok(Err(e)) => eprintln!("写入失败: {e}"),
        Err(e) => eprintln!("序列化失败: {e}"),
    }
    true
}

/// `--days N` 参数。
fn days_arg(args: &[String]) -> Option<u32> {
    args.iter().position(|a| a == "--days").and_then(|i| args.get(i + 1)).and_then(|d| d.parse().ok()).filter(|&d| d > 0)
}

/// 设置环境变量 LWI_LOG=1 时把 GPUI 与本程序的日志输出到 stderr，便于排查。
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!("[{}] {}: {}", r.level(), r.target(), r.args());
        }
    }
    fn flush(&self) {}
}

/// Release 构建是 GUI 子系统程序，默认没有控制台。带命令行参数运行时附加到调用者的控制台，
/// 否则 --json / --check-update 等命令的输出不可见。
#[cfg(not(debug_assertions))]
fn attach_parent_console() {
    use windows::Win32::Foundation::GENERIC_WRITE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE,
        STD_OUTPUT_HANDLE, SetStdHandle,
    };
    use windows::core::w;
    unsafe {
        // 从资源管理器双击启动时没有父控制台，附加失败属正常情况
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return;
        }
        // 调用方已重定向（如 app.exe > log.txt）时保留其句柄，只补齐缺失的那一个
        let missing = |which: STD_HANDLE| match GetStdHandle(which) {
            Ok(h) => h.is_invalid() || h.0.is_null(),
            Err(_) => true,
        };
        for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            if !missing(which) {
                continue;
            }
            if let Ok(h) = CreateFileW(
                w!("CONOUT$"),
                GENERIC_WRITE.0,
                FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                let _ = SetStdHandle(which, h);
            }
        }
    }
}

#[cfg(debug_assertions)]
fn attach_parent_console() {}

const USAGE: &str = "LovelyWinInspect —— Windows 安全基线核查与应急响应工作台

用法: LovelyWinInspect.exe [选项]

  --page <名称>      指定启动页：overview | baseline | timeline | process | network |
                     persistence | account | eventlog | file | registry | files |
                     export | settings
  --open <路径>      打开文件管理并定位到指定文件或目录（选中文件时显示预览）
  --report           无界面采集，导出报告后在浏览器中打开 HTML 报告
                     （无法使用图形界面的机器可用；配合 --days 指定回溯天数）
  --json <文件>      无界面模式：完成采集后把结果写入 JSON 文件
  --days <N>         日志与文件痕迹的回溯天数（默认 30）
  --export           无界面模式下同时导出完整证据包
  --evtx             配合 --export，额外导出原始 .evtx 日志
  --check-update     查询 GitHub Releases 上的最新版本后退出（加 --pre 包含预发布）
  --gpu-info         列出图形适配器并检查图形界面能否启动
  -V, --version      显示版本号
  -h, --help         显示本帮助

不带参数运行则打开图形界面。建议以管理员身份运行。";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        attach_parent_console();
    }
    if std::env::var_os("LWI_LOG").is_some() && log::set_logger(&StderrLogger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
    if args.iter().any(|a| a == "-h" || a == "--help" || a == "/?") {
        println!("{USAGE}");
        return;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("LovelyWinInspect {}", update::current_version());
        return;
    }
    if args.iter().any(|a| a == "--check-update") {
        match update::repo() {
            Some(repo) => match update::fetch_latest(&repo, args.iter().any(|a| a == "--pre")) {
                Ok(r) => println!(
                    "当前 v{} / 最新 {}（{}）{}\n{}",
                    update::current_version(),
                    r.tag,
                    r.published,
                    if update::is_newer(&r.version(), update::current_version()) { " → 有新版本" } else { "" },
                    r.url
                ),
                Err(e) => eprintln!("检查更新失败: {e}"),
            },
            None => eprintln!("未配置更新仓库（Cargo.toml repository 字段或环境变量 LWI_UPDATE_REPO）"),
        }
        return;
    }
    if args.iter().any(|a| a == "--gpu-info") {
        fallback::print_gpu_info();
        return;
    }
    let lookback = days_arg(&args).unwrap_or_else(|| settings::Settings::load().lookback_days.max(1));
    if args.iter().any(|a| a == "--report") {
        let ok = fallback::run_report(None, lookback);
        std::process::exit(if ok { 0 } else { 1 });
    }
    if headless(&args) {
        return;
    }
    // GPUI 在 Direct3D 11 不可用时会弹英文错误并崩溃，先自行探测，失败则提供无界面采集
    if let Err(reason) = fallback::probe_d3d11() {
        fallback::run_report(Some(&reason), lookback);
        return;
    }

    Application::new().with_assets(assets::Assets).run(move |cx: &mut App| {
        cx.set_global(theme::Theme::light());
        ui::input::bind_keys(cx);
        ui::app::bind_keys(cx);
        let bounds = Bounds::centered(None, size(px(1440.), px(900.)), cx);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("LovelyWinInspect".into()),
                    appears_transparent: true,
                    traffic_light_position: None,
                }),
                window_min_size: Some(size(px(1120.), px(720.))),
                ..Default::default()
            },
            |window, cx| cx.new(|cx| ui::app::AppView::new(window, cx)),
        );
        if let Err(e) = opened {
            // 例如 DirectComposition 不可用：不再静默退出，改为提供无界面采集
            fallback::run_report(Some(&format!("窗口创建失败（{e}）")), lookback);
            cx.quit();
            return;
        }
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        cx.activate(true);
    });
}
