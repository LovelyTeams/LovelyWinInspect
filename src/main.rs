#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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

fn main() {
    if std::env::var_os("LWI_LOG").is_some() && log::set_logger(&StderrLogger).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
    let args: Vec<String> = std::env::args().collect();
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
