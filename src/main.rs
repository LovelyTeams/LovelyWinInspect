#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod actions;
mod analysis;
mod assets;
mod collect;
mod model;
mod report;
mod settings;
mod theme;
mod ui;
mod update;

use gpui::{App, AppContext, Application, Bounds, TitlebarOptions, WindowBounds, WindowOptions, px, size};

use model::{ScanReport, Stage};

/// 无界面模式：`LovelyWinInspect.exe --json out.json [--days N] [--export [--evtx]]`，便于批量/脚本化采集。
fn headless(args: &[String]) -> bool {
    let Some(pos) = args.iter().position(|a| a == "--json") else { return false };
    let out = args.get(pos + 1).cloned().unwrap_or_else(|| "lovelywininspect.json".into());
    let days = args
        .iter()
        .position(|a| a == "--days")
        .and_then(|i| args.get(i + 1))
        .and_then(|d| d.parse().ok())
        .unwrap_or(30);
    let mut report = ScanReport { lookback_days: days, started: Some(chrono::Local::now()), ..Default::default() };
    for stage in Stage::ALL {
        let t = std::time::Instant::now();
        let s = collect::run_stage(stage, &mut report);
        println!("[{}] {} ({} ms)", stage.label(), s, t.elapsed().as_millis());
    }
    report.finished = Some(chrono::Local::now());
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
                     persistence | account | eventlog | file | export | settings
  --json <文件>      无界面模式：完成采集后把结果写入 JSON 文件
  --days <N>         日志与文件痕迹的回溯天数（默认 30）
  --export           无界面模式下同时导出完整证据包
  --evtx             配合 --export，额外导出原始 .evtx 日志
  --check-update     查询 GitHub Releases 上的最新版本后退出（加 --pre 包含预发布）
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
    if headless(&args) {
        return;
    }

    Application::new().with_assets(assets::Assets).run(|cx: &mut App| {
        cx.set_global(theme::Theme::light());
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
        if opened.is_err() {
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
