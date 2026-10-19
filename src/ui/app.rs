//! 主视图：自绘标题栏 + mini 侧边栏 + 页面区 + 详情抽屉；负责调度采集与导出任务。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use chrono::Local;
use gpui::{
    AnyElement, App, ClipboardItem, Context, Entity, FocusHandle, FontWeight, IntoElement, KeyBinding, ParentElement, Render,
    Styled, Subscription, Task, UniformListScrollHandle, Window, WindowControlArea, actions, div, prelude::*, px,
};

use super::components::*;
use super::input::{InputEvent, TextInput};
use super::extras::{Loadable, PreviewTab};
use super::fileman::FsState;
use super::listkit::{ListId, mark_color};
use crate::collect;
use crate::model::*;
use crate::report::{self, ExportOptions};
use super::menu::{Confirm, ContextMenu, MenuItem};
use crate::settings::{Settings, ThemeMode};
use crate::update::{self, ReleaseInfo};
use crate::theme::{Theme, theme};

actions!(lwi, [CloseDetail, SelectPrev, SelectNext, CopySelected, FocusSearch]);

const CONTEXT: &str = "AppView";

/// 主界面快捷键：Esc 关闭详情，上下键切换记录，Ctrl+C 复制当前详情，Ctrl+F 搜索。
pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("escape", CloseDetail, Some(CONTEXT)),
        KeyBinding::new("up", SelectPrev, Some(CONTEXT)),
        KeyBinding::new("down", SelectNext, Some(CONTEXT)),
        KeyBinding::new("ctrl-c", CopySelected, Some(CONTEXT)),
        KeyBinding::new("ctrl-f", FocusSearch, Some(CONTEXT)),
    ]);
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Page {
    Overview,
    Baseline,
    Timeline,
    Process,
    Network,
    Persistence,
    Account,
    EventLog,
    File,
    Registry,
    FileManager,
    Export,
    Settings,
}

pub const NAV: &[(Page, &str, &str, &str)] = &[
    (Page::Overview, "home", "总览", "总览：主机概况与调查发现"),
    (Page::Baseline, "shield-check", "基线", "安全基线核查"),
    (Page::Timeline, "route", "还原", "入侵还原：攻击时间线与 ATT&CK 阶段"),
    (Page::Process, "cpu", "进程", "进程分析"),
    (Page::Network, "globe", "网络", "网络连接"),
    (Page::Persistence, "rocket", "启动项", "持久化 / 启动项排查"),
    (Page::Account, "users", "账户", "账户与登录"),
    (Page::EventLog, "list", "日志", "系统日志分析"),
    (Page::File, "folder", "文件", "文件痕迹排查"),
    (Page::Registry, "database", "注册表", "注册表取证：执行痕迹、用户活动与网络历史"),
    (Page::FileManager, "hard-drive", "文件管理", "文件管理：浏览、搜索、预览与隔离可疑文件"),
    (Page::Export, "download", "导出", "证据与报告导出"),
];

#[derive(Clone, Default)]
pub struct Detail {
    pub title: String,
    pub subtitle: String,
    pub severity: Option<Severity>,
    pub fields: Vec<(String, String)>,
    /// 抽屉底部的处置按钮（与右键菜单一致）
    pub actions: Vec<MenuItem>,
    /// 可标记时为 (标记键, 模块, 对象名)
    pub mark: Option<(String, String, String)>,
    /// 需要按需加载的附加内容
    pub extra: DetailExtra,
}

/// 详情抽屉中按需加载的附加内容。
#[derive(Clone, Default, PartialEq)]
pub enum DetailExtra {
    #[default]
    None,
    /// 进程加载的模块
    Modules(u32),
    /// 文件内容预览
    Preview(String),
}

impl Page {
    /// 命令行 `--page <名称>` 指定启动页
    pub fn from_arg(s: &str) -> Option<Page> {
        Some(match s.to_ascii_lowercase().as_str() {
            "overview" => Page::Overview,
            "baseline" => Page::Baseline,
            "timeline" => Page::Timeline,
            "process" => Page::Process,
            "network" => Page::Network,
            "persistence" => Page::Persistence,
            "account" => Page::Account,
            "eventlog" => Page::EventLog,
            "file" => Page::File,
            "registry" => Page::Registry,
            "files" | "filemanager" => Page::FileManager,
            "export" => Page::Export,
            "settings" => Page::Settings,
            _ => return None,
        })
    }
}

impl Detail {
    pub fn new(title: impl Into<String>, subtitle: impl Into<String>, severity: Option<Severity>) -> Self {
        Self { title: title.into(), subtitle: subtitle.into(), severity, ..Default::default() }
    }

    pub fn field(mut self, k: &str, v: impl Into<String>) -> Self {
        let v = v.into();
        if !v.trim().is_empty() {
            self.fields.push((k.to_string(), v));
        }
        self
    }

    pub fn actions(mut self, items: Vec<MenuItem>) -> Self {
        self.actions = items;
        self
    }

    pub fn markable(mut self, key: String, category: &str) -> Self {
        self.mark = Some((key, category.to_string(), self.title.clone()));
        self
    }

    pub fn extra(mut self, extra: DetailExtra) -> Self {
        self.extra = extra;
        self
    }

    pub fn to_text(&self) -> String {
        let mut s = format!("{}\n{}\n", self.title, self.subtitle);
        if let Some(sev) = self.severity {
            s.push_str(&format!("风险等级: {}\n", sev.label()));
        }
        for (k, v) in &self.fields {
            s.push_str(&format!("{k}: {v}\n"));
        }
        s
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NetFilter {
    External,
    Listen,
    Suspicious,
    All,
    Dns,
    Neighbors,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventFilter {
    All,
    LogonOk,
    LogonFail,
    Rdp,
    Account,
    ServiceTask,
    Cleared,
    Process,
    PowerShell,
    Defender,
    Remote,
}

impl EventFilter {
    pub const ALL: [(EventFilter, &'static str); 11] = [
        (EventFilter::All, "全部"),
        (EventFilter::LogonOk, "登录成功"),
        (EventFilter::LogonFail, "登录失败"),
        (EventFilter::Rdp, "远程桌面"),
        (EventFilter::Remote, "远程访问"),
        (EventFilter::Account, "账户与组"),
        (EventFilter::ServiceTask, "服务与任务"),
        (EventFilter::Cleared, "日志清除"),
        (EventFilter::Process, "进程创建"),
        (EventFilter::PowerShell, "PowerShell"),
        (EventFilter::Defender, "Defender"),
    ];

    pub fn matches(self, e: &EventRecord) -> bool {
        match self {
            EventFilter::All => true,
            EventFilter::LogonOk => e.event_id == 4624,
            EventFilter::LogonFail => e.event_id == 4625,
            EventFilter::Rdp => e.channel == "RDP" || e.logon_type.starts_with("10"),
            EventFilter::Account => matches!(e.event_id, 4720 | 4722 | 4724 | 4725 | 4726 | 4738 | 4781 | 4728 | 4732 | 4733 | 4756),
            EventFilter::Remote => matches!(e.event_id, 4648 | 5140 | 91) || (e.channel == "RDP" && e.event_id == 1024),
            EventFilter::ServiceTask => matches!(e.event_id, 7045 | 7040 | 4697 | 4698 | 4699 | 4702 | 106 | 140 | 141 | 5861 | 59),
            EventFilter::Cleared => matches!(e.event_id, 1102 | 104 | 4719),
            EventFilter::Process => e.event_id == 4688,
            EventFilter::PowerShell => e.channel == "PowerShell",
            EventFilter::Defender => e.channel == "Defender",
        }
    }
}

pub struct ExportState {
    pub opts: ExportOptions,
    pub running: bool,
    pub task: Option<Task<()>>,
    pub result: Option<(std::path::PathBuf, Vec<(String, u64)>, Vec<String>)>,
    pub error: Option<String>,
}

pub struct AppView {
    pub page: Page,
    pub report: Arc<ScanReport>,
    pub has_report: bool,
    pub stages: Vec<StageLog>,
    pub scanning: bool,
    scan_task: Option<Task<()>>,
    pub lookback: u32,
    pub is_admin: bool,
    pub detail: Option<Detail>,

    pub f_baseline_group: Option<String>,
    pub f_baseline_issues: bool,
    pub f_tactic: Option<Tactic>,
    pub f_tl_min: Severity,
    pub tl_show_findings: bool,
    pub f_proc_suspicious: bool,
    pub f_net: NetFilter,
    pub f_persist_kind: Option<PersistKind>,
    pub f_persist_all: bool,
    pub f_event: EventFilter,
    pub f_file_kind: Option<ArtifactKind>,
    pub f_file_suspicious: bool,
    pub f_reg_cat: Option<crate::model::RegCategory>,
    pub menu: Option<ContextMenu>,
    pub confirm: Option<Confirm>,
    pub toast: Option<(String, bool)>,
    pub export: ExportState,
    pub settings: Settings,
    pub update: UpdateState,
    _appearance_sub: Option<gpui::Subscription>,

    pub focus_handle: FocusHandle,
    pub subscriptions: Vec<Subscription>,
    /// 各页面的搜索框
    pub searches: HashMap<Page, Entity<TextInput>>,
    /// 各列表的排序列与方向（true = 降序）
    pub sorts: HashMap<ListId, (usize, bool)>,
    pub scrolls: HashMap<ListId, UniformListScrollHandle>,
    /// 当前页面正在显示的列表及其行（供方向键切换）
    pub nav: Option<(ListId, Rc<Vec<usize>>)>,
    pub selected: Option<(ListId, usize)>,
    /// 研判标记，键见各列表的 mark_key
    pub marks: BTreeMap<String, Mark>,
    pub note_input: Entity<TextInput>,

    pub proc_tree: bool,
    pub proc_collapsed: HashSet<u32>,
    /// 进程树渲染缓存：进程下标 -> (深度, 是否有子节点)
    pub proc_depth: HashMap<usize, (u16, bool)>,
    /// 本工具添加过防火墙封禁规则的 IP
    pub blocked_ips: HashSet<String>,
    pub fs: FsState,
    pub previews: HashMap<String, Loadable<crate::collect::fsbrowse::Preview>>,
    pub preview_tab: Option<PreviewTab>,
    pub modules: HashMap<u32, Loadable<Vec<crate::collect::fsbrowse::ModuleInfo>>>,
    /// 使用软件渲染时为渲染器名称（此时关闭界面动画）
    pub software_render: Option<String>,
}

#[derive(Default)]
pub struct UpdateState {
    pub checking: bool,
    pub task: Option<Task<()>>,
    pub latest: Option<ReleaseInfo>,
    pub error: Option<String>,
    /// 本次运行中是否已手动检查过（用于显示“已是最新版本”）
    pub checked: bool,
}

pub fn resolve_theme(mode: ThemeMode, window: &Window) -> Theme {
    match mode {
        ThemeMode::Light => Theme::light(),
        ThemeMode::Dark => Theme::dark(),
        ThemeMode::System => match window.appearance() {
            gpui::WindowAppearance::Dark | gpui::WindowAppearance::VibrantDark => Theme::dark(),
            _ => Theme::light(),
        },
    }
}

impl AppView {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let settings = Settings::load();
        cx.set_global(resolve_theme(settings.theme, window));
        let appearance_sub = cx.observe_window_appearance(window, |this, window, cx| {
            if this.settings.theme == ThemeMode::System {
                cx.set_global(resolve_theme(ThemeMode::System, window));
                cx.notify();
            }
        });
        let args: Vec<String> = std::env::args().collect();
        let page = args
            .iter()
            .position(|a| a == "--page")
            .and_then(|i| args.get(i + 1))
            .and_then(|p| Page::from_arg(p))
            .unwrap_or(Page::Overview);
        // `--tab <名称>` 预选页内视图（便于截图核对）：dns / arp / rootcert / ads
        let tab = args
            .iter()
            .position(|a| a == "--tab")
            .and_then(|i| args.get(i + 1))
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        let software_render = detect_software_render(window);
        set_reduced_motion(software_render.is_some());
        if let Some(name) = &software_render {
            log::info!("使用软件渲染（{name}），已关闭界面动画");
        }
        let focus_handle = cx.focus_handle();
        window.focus(&focus_handle);
        let note_input = cx.new(|cx| TextInput::new("添加备注（随报告导出）", cx).with_icon("pencil"));
        let note_sub = cx.subscribe(&note_input, |this, input, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Changed) {
                let note = input.read(cx).text().to_string();
                this.set_mark_note(note, cx);
            }
        });
        let mut this = Self {
            page,
            report: Arc::new(ScanReport::default()),
            has_report: false,
            stages: fresh_stages(),
            scanning: false,
            scan_task: None,
            lookback: settings.lookback_days.max(1),
            is_admin: collect::process::is_elevated(),
            detail: None,
            f_baseline_group: None,
            f_baseline_issues: false,
            f_tactic: None,
            f_tl_min: Severity::Low,
            tl_show_findings: false,
            f_proc_suspicious: true,
            f_net: NetFilter::External,
            f_persist_kind: None,
            f_persist_all: false,
            f_event: EventFilter::All,
            f_file_kind: None,
            f_file_suspicious: false,
            f_reg_cat: None,
            menu: None,
            confirm: None,
            toast: None,
            export: ExportState { opts: settings.export, running: false, task: None, result: None, error: None },
            settings,
            update: UpdateState::default(),
            _appearance_sub: Some(appearance_sub),
            focus_handle,
            subscriptions: vec![note_sub],
            searches: HashMap::new(),
            sorts: HashMap::new(),
            scrolls: HashMap::new(),
            nav: None,
            selected: None,
            marks: BTreeMap::new(),
            note_input,
            proc_tree: false,
            proc_collapsed: HashSet::new(),
            proc_depth: HashMap::new(),
            blocked_ips: crate::actions::blocked_ips(),
            fs: FsState::default(),
            previews: HashMap::new(),
            preview_tab: None,
            modules: HashMap::new(),
            software_render,
        };
        match tab.as_str() {
            "dns" => this.f_net = NetFilter::Dns,
            "arp" => this.f_net = NetFilter::Neighbors,
            "rootcert" => {
                this.f_persist_kind = Some(PersistKind::RootCert);
                this.f_persist_all = true;
            }
            "ads" => this.f_file_kind = Some(ArtifactKind::AltStream),
            "tree" => {
                this.proc_tree = true;
                this.f_proc_suspicious = false;
            }
            _ => {}
        }
        // `--open <路径>`：在文件管理中定位文件或目录
        if let Some(path) = args.iter().position(|a| a == "--open").and_then(|i| args.get(i + 1)) {
            this.browse_to_file(path, cx);
        }
        if this.settings.auto_scan {
            this.start_scan(cx);
        }
        if this.settings.auto_check_update && update::repo().is_some() {
            this.check_update(false, cx);
        }
        this
    }

    pub fn save_settings(&mut self) {
        if let Err(e) = self.settings.save() {
            log::warn!("保存设置失败: {e}");
        }
    }

    /// 检查 GitHub 上的最新版本。`manual` 为 true 时会清除对该版本的忽略。
    pub fn check_update(&mut self, manual: bool, cx: &mut Context<Self>) {
        let Some(repo) = update::repo() else {
            self.update.error = Some("未配置更新仓库（Cargo.toml 中的 repository 字段）".into());
            cx.notify();
            return;
        };
        if self.update.checking {
            return;
        }
        self.update.checking = true;
        self.update.error = None;
        let pre = self.settings.include_prerelease;
        cx.notify();
        self.update.task = Some(cx.spawn(async move |this, cx| {
            let res = cx.background_executor().spawn(async move { update::fetch_latest(&repo, pre) }).await;
            let _ = this.update(cx, |this, cx| {
                this.update.checking = false;
                this.update.checked |= manual;
                match res {
                    Ok(info) => {
                        if manual && this.settings.skipped_version.as_deref() == Some(info.version().as_str()) {
                            this.settings.skipped_version = None;
                        }
                        this.update.latest = Some(info);
                    }
                    Err(e) => this.update.error = Some(e),
                }
                this.settings.last_update_check = Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
                this.save_settings();
                cx.notify();
            });
        }));
    }

    /// 有比当前更新、且未被忽略的版本时返回发布信息。
    pub fn update_available(&self) -> Option<&ReleaseInfo> {
        self.update.latest.as_ref().filter(|r| {
            update::is_newer(&r.version(), update::current_version())
                && self.settings.skipped_version.as_deref() != Some(r.version().as_str())
        })
    }

    pub fn start_scan(&mut self, cx: &mut Context<Self>) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.stages = fresh_stages();
        // 重新排查后下标会变化，关闭详情避免指向错误的记录（研判标记按稳定键保留）。
        // 文件管理的条目不来自排查报告，不受影响。
        if !matches!(self.selected, Some((ListId::Fs | ListId::Quarantine, _))) {
            self.detail = None;
            self.selected = None;
        }
        let lookback = self.lookback;
        cx.notify();
        self.scan_task = Some(cx.spawn(async move |this, cx| {
            let mut report = ScanReport {
                tool: format!("LovelyWinInspect {}", env!("CARGO_PKG_VERSION")),
                lookback_days: lookback,
                started: Some(Local::now()),
                ..Default::default()
            };
            for (i, stage) in Stage::ALL.iter().copied().enumerate() {
                let started = Local::now();
                let _ = this.update(cx, |this, cx| {
                    this.stages[i].status = StageStatus::Running;
                    this.stages[i].started = Some(started);
                    cx.notify();
                });
                let t0 = Instant::now();
                let (r, summary) = cx
                    .background_executor()
                    .spawn(async move {
                        let s = collect::run_stage(stage, &mut report);
                        (report, s)
                    })
                    .await;
                report = r;
                let elapsed = t0.elapsed().as_millis() as u64;
                let snapshot = Arc::new(report.clone());
                let _ = this.update(cx, |this, cx| {
                    this.stages[i].status = StageStatus::Done;
                    this.stages[i].elapsed_ms = elapsed;
                    this.stages[i].summary = summary;
                    this.report = snapshot;
                    this.has_report = true;
                    cx.notify();
                });
            }
            report.finished = Some(Local::now());
            let _ = this.update(cx, |this, cx| {
                report.stages = this.stages.clone();
                this.report = Arc::new(report);
                this.scanning = false;
                cx.notify();
            });
        }));
    }

    pub fn start_export(&mut self, cx: &mut Context<Self>) {
        if self.export.running || !self.has_report {
            return;
        }
        self.export.running = true;
        self.export.error = None;
        self.export.result = None;
        let mut report = (*self.report).clone();
        report.marks = self.marks.values().cloned().collect();
        let opts = self.export.opts;
        let root = self.settings.export_root();
        cx.notify();
        self.export.task = Some(cx.spawn(async move |this, cx| {
            let res = cx
                .background_executor()
                .spawn(async move { report::export(&report, opts, root.as_deref()) })
                .await;
            let _ = this.update(cx, |this, cx| {
                this.export.running = false;
                match res {
                    Ok(r) => this.export.result = Some((r.dir, r.files, r.warnings)),
                    Err(e) => this.export.error = Some(e),
                }
                cx.notify();
            });
        }));
    }

    pub fn show(&mut self, d: Detail, cx: &mut Context<Self>) {
        let note = d.mark.as_ref().and_then(|(k, _, _)| self.marks.get(k)).map(|m| m.note.clone()).unwrap_or_default();
        self.note_input.update(cx, |input, cx| input.set_text(note, cx));
        self.detail = Some(d);
        self.on_detail_opened(cx);
        cx.notify();
    }

    pub fn close_detail(&mut self, cx: &mut Context<Self>) {
        self.detail = None;
        self.selected = None;
        cx.notify();
    }

    pub fn go(&mut self, page: Page, cx: &mut Context<Self>) {
        // 抽屉没有遮罩，切换页面时侧边栏可点，需随之关闭上一页的详情
        if page != self.page {
            self.detail = None;
            self.selected = None;
            self.nav = None;
        }
        self.page = page;
        cx.notify();
    }

    // ---------------------------------------------------------------- 标题栏

    fn render_titlebar(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let done = self.stages.iter().filter(|s| s.status == StageStatus::Done).count();
        let caption = |id: &'static str, icon_name: &'static str, area: WindowControlArea, close: bool| {
            let hover_bg = if close { gpui::rgb(0xE81123).into() } else { t.card_hover };
            div()
                .id(id)
                .w(px(46.))
                .h_full()
                .flex()
                .items_center()
                .justify_center()
                .window_control_area(area)
                .hover(move |s| s.bg(hover_bg))
                .child(icon(icon_name, if icon_name == "x" { 16. } else { 14. }, t.text_muted))
        };
        div()
            .h(px(40.))
            .flex_none()
            .flex()
            .items_center()
            .bg(t.titlebar)
            .border_b_1()
            .border_color(t.border)
            .child(
                div()
                    .id("title-drag")
                    .flex_1()
                    .h_full()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pl(px(16.))
                    .window_control_area(WindowControlArea::Drag)
                    .child(if let Some(logo) = crate::assets::logo_image() {
                        gpui::img(logo).size(px(24.)).rounded(px(6.)).flex_none().into_any_element()
                    } else {
                        div()
                            .size(px(22.))
                            .rounded(px(6.))
                            .bg(t.primary)
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(icon("shield", 14., t.on_primary))
                            .into_any_element()
                    })
                    .child(div().text_size(px(13.)).font_weight(FontWeight::SEMIBOLD).child("LovelyWinInspect"))
                    .child(div().text_size(px(12.)).text_color(t.text_faint).child("Windows 基线核查与应急响应工作台")),
            )
            .when(self.scanning, |d| {
                d.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .mr_3()
                        .px_3()
                        .h(px(26.))
                        .rounded(px(13.))
                        .bg(t.primary_soft)
                        .text_color(t.primary)
                        .text_size(px(12.))
                        .child(spinner("tb-spin", 13., t.primary))
                        .child(format!("正在采集 {done}/{}", self.stages.len())),
                )
            })
            .when_some(self.software_render.clone(), |d, name| {
                d.child(
                    div()
                        .id("software-render")
                        .mr_3()
                        .flex()
                        .items_center()
                        .gap_1()
                        .px_3()
                        .h(px(26.))
                        .rounded(px(13.))
                        .bg(t.gray_soft)
                        .text_color(t.text_muted)
                        .text_size(px(12.))
                        .child(icon("monitor", 13., t.text_muted))
                        .child("软件渲染")
                        .tooltip(tooltip(format!(
                            "未检测到可用的显卡加速，当前由 CPU 绘制界面（{name}）。\n已自动关闭界面动画以降低 CPU 占用，功能不受影响。"
                        ))),
                )
            })
            .child(if self.is_admin {
                badge("管理员权限", t.green, t.green_soft).mr_3().into_any_element()
            } else {
                div()
                    .id("elevate")
                    .mr_3()
                    .flex()
                    .items_center()
                    .gap_1()
                    .px_3()
                    .h(px(26.))
                    .rounded(px(13.))
                    .bg(t.orange_soft)
                    .text_color(t.orange)
                    .text_size(px(12.))
                    .cursor_pointer()
                    .tooltip(tooltip("部分日志、策略与 SAM 信息需要管理员权限才能读取"))
                    .child(icon("alert", 13., t.orange))
                    .child("非管理员 · 点击提权重启")
                    .on_click(cx.listener(|_, _, _, cx| relaunch_as_admin(cx)))
                    .into_any_element()
            })
            .when_some(self.update_available().map(|r| r.tag.clone()), |d, tag| {
                d.child(
                    div()
                        .id("update-pill")
                        .mr_3()
                        .flex()
                        .items_center()
                        .gap_1()
                        .px_3()
                        .h(px(26.))
                        .rounded(px(13.))
                        .bg(t.primary_soft)
                        .text_color(t.primary)
                        .text_size(px(12.))
                        .cursor_pointer()
                        .child(icon("arrow-up", 13., t.primary))
                        .child(format!("发现新版本 {tag}"))
                        .on_click(cx.listener(|this, _, _, cx| this.go(Page::Settings, cx))),
                )
            })
            .child(caption("min", "minus", WindowControlArea::Min, false))
            .child(caption("max", if window.is_maximized() { "restore" } else { "square" }, WindowControlArea::Max, false))
            .child(caption("close", "x", WindowControlArea::Close, true))
    }

    // ---------------------------------------------------------------- mini 侧边栏

    fn nav_count(&self, page: Page) -> usize {
        let r = &self.report;
        match page {
            Page::Process => r.processes.iter().filter(|p| p.risk >= Severity::Medium).count(),
            Page::Network => {
                r.connections.iter().filter(|c| c.risk >= Severity::Medium).count()
                    + r.neighbors.iter().filter(|n| n.risk >= Severity::Medium).count()
                    + r.dns_cache.iter().filter(|d| d.risk >= Severity::Medium).count()
            }
            Page::Persistence => r.persistence.iter().filter(|p| p.risk >= Severity::Medium).count(),
            Page::Account => r.accounts.iter().filter(|a| a.risk >= Severity::Medium).count(),
            Page::EventLog => r.events.iter().filter(|e| e.severity >= Severity::High).count(),
            Page::File => r.files.iter().filter(|f| f.risk >= Severity::Medium).count(),
            Page::Baseline => r.baseline.iter().filter(|b| b.status == CheckStatus::Fail).count(),
            _ => 0,
        }
    }

    fn render_sidebar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let items: Vec<AnyElement> = NAV
            .iter()
            .enumerate()
            .map(|(i, (page, icon_name, label, tip))| {
                let page = *page;
                let active = self.page == page;
                let count = self.nav_count(page);
                let fg = if active { t.primary } else { t.text_muted };
                let hover = t.card_hover;
                div()
                    .id(("nav", i))
                    .relative()
                    .w(px(60.))
                    .h(px(54.))
                    .flex()
                    .flex_col()
                    .items_center()
                    .justify_center()
                    .gap(px(3.))
                    .rounded(px(10.))
                    .cursor_pointer()
                    .when(active, |d| d.bg(t.primary_soft))
                    .when(!active, move |d| d.hover(move |s| s.bg(hover)))
                    .child(icon(icon_name, 20., fg))
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(fg)
                            .when(active, |d| d.font_weight(FontWeight::MEDIUM))
                            .child(label.to_string()),
                    )
                    .when(active, |d| {
                        d.child(div().absolute().left(px(-8.)).top(px(14.)).w(px(3.)).h(px(26.)).rounded(px(2.)).bg(t.primary))
                    })
                    .when(count > 0, |d| {
                        d.child(
                            div()
                                .absolute()
                                .top(px(4.))
                                .right(px(6.))
                                .min_w(px(16.))
                                .h(px(16.))
                                .px(px(4.))
                                .rounded(px(8.))
                                .bg(if page == Page::Baseline { t.orange } else { t.red })
                                .text_color(t.on_primary)
                                .text_size(px(10.))
                                .flex()
                                .items_center()
                                .justify_center()
                                .child(if count > 99 { "99+".to_string() } else { count.to_string() }),
                        )
                    })
                    .tooltip(tooltip(*tip))
                    .on_click(cx.listener(move |this, _, _, cx| this.go(page, cx)))
                    .into_any_element()
            })
            .collect();

        let dark = t.dark;
        div()
            .w(px(76.))
            .flex_none()
            .h_full()
            .flex()
            .flex_col()
            .items_center()
            .pt(px(10.))
            .pb(px(12.))
            .gap(px(4.))
            .bg(t.sidebar)
            .border_r_1()
            .border_color(t.border)
            .children(items)
            .child(div().flex_1())
            .child({
                let active = self.page == Page::Settings;
                let has_update = self.update_available().is_some();
                let hover = t.card_hover;
                div()
                    .id("nav-settings")
                    .relative()
                    .size(px(40.))
                    .rounded(px(10.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .when(active, |d| d.bg(t.primary_soft))
                    .when(!active, move |d| d.hover(move |s| s.bg(hover)))
                    .tooltip(tooltip(if has_update { "设置 · 发现新版本" } else { "设置" }))
                    .child(icon("settings", 19., if active { t.primary } else { t.text_muted }))
                    .when(has_update, |d| d.child(div().absolute().top(px(7.)).right(px(7.)).size(px(8.)).rounded_full().bg(t.red)))
                    .on_click(cx.listener(|this, _, _, cx| this.go(Page::Settings, cx)))
            })
            .child(
                div()
                    .id("theme-toggle")
                    .size(px(40.))
                    .rounded(px(10.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .hover(move |s| s.bg(t.card_hover))
                    .tooltip(tooltip(if dark { "切换到浅色主题" } else { "切换到深色主题" }))
                    .child(icon(if dark { "sun" } else { "moon" }, 18., t.text_muted))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        this.settings.theme = if dark { ThemeMode::Light } else { ThemeMode::Dark };
                        this.save_settings();
                        cx.set_global(resolve_theme(this.settings.theme, window));
                        window.refresh();
                        cx.notify();
                    })),
            )
    }

    // ---------------------------------------------------------------- 详情抽屉

    /// 浮在内容区右侧（标题栏以下），不加遮罩：左侧列表仍可滚动和点选，点其他行直接切换详情。
    fn render_drawer(&mut self, d: Detail, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let text = d.to_text();
        let extra = self.render_detail_extra(&d.extra, cx);
        let mark_bar = d.mark.is_some().then(|| self.render_mark_bar(&t, cx));
        let actions: Vec<_> = d
            .actions
            .iter()
            .enumerate()
            .map(|(i, it)| {
                let act = it.act.clone();
                let danger = act.is_danger();
                let fg = if danger { t.red } else { t.text };
                let hover = if danger { t.red_soft } else { t.card_hover };
                div()
                    .id(("detail-act", i))
                    .flex_none()
                    .h(px(28.))
                    .px(px(10.))
                    .flex()
                    .items_center()
                    .gap_1()
                    .rounded(px(6.))
                    .border_1()
                    .border_color(if danger { t.red.opacity(0.4) } else { t.border })
                    .bg(t.card)
                    .text_color(fg)
                    .text_size(px(12.5))
                    .cursor_pointer()
                    .hover(move |s| s.bg(hover))
                    .child(icon(it.icon, 14., if danger { t.red } else { t.text_muted }))
                    .child(it.label.clone())
                    .on_click(cx.listener(move |this, _, _, cx| this.on_menu_click(act.clone(), cx)))
            })
            .collect();
        div()
            .id("drawer")
            .occlude()
            .absolute()
            .top_0()
            .right_0()
            .h_full()
            .w(px(560.))
            .bg(t.card)
            .border_l_1()
            .border_color(t.border)
            .shadow_lg()
            .flex()
            .flex_col()
            .child(
                div()
                    .flex_none()
                    .flex()
                    .items_start()
                    .gap_3()
                    .px_5()
                    .py_4()
                    .border_b_1()
                    .border_color(t.divider)
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .when_some(d.severity, |el, s| el.child(sev_badge(&t, s)))
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .text_size(px(16.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(d.title.clone()),
                                    ),
                            )
                            .child(div().text_size(px(12.)).text_color(t.text_muted).child(d.subtitle.clone())),
                    )
                    .child(
                        div()
                            .id("drawer-close")
                            .size(px(30.))
                            .rounded(px(6.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .cursor_pointer()
                            .hover(move |s| s.bg(t.card_hover))
                            .tooltip(tooltip("关闭 (Esc)"))
                            .child(icon("x", 16., t.text_muted))
                            .on_click(cx.listener(|this, _, _, cx| this.close_detail(cx))),
                    ),
            )
            .children(mark_bar)
            .child(
                div()
                    .id("drawer-body")
                    .flex_1()
                    .min_h(px(0.))
                    .overflow_y_scroll()
                    .px_5()
                    .py_3()
                    .children(d.fields.iter().map(|(k, v)| {
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .py(px(8.))
                            .border_b_1()
                            .border_color(t.divider)
                            .child(div().text_size(px(12.)).text_color(t.text_faint).child(k.clone()))
                            .child(div().text_size(px(13.)).text_color(t.text).child(v.clone()))
                    }))
                    .children(extra),
            )
            .child(
                div()
                    .flex_none()
                    .flex()
                    .flex_wrap()
                    .justify_end()
                    .gap_2()
                    .px_5()
                    .py_3()
                    .border_t_1()
                    .border_color(t.divider)
                    .children(actions)
                    .child(small_button(&t, "copy-detail", "copy", "复制全部信息").on_click(cx.listener(
                        move |_, _, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(text.clone())),
                    ))),
            )
    }

    /// 研判标签 + 备注输入。
    fn render_mark_bar(&mut self, t: &Theme, cx: &mut Context<Self>) -> gpui::AnyElement {
        let current = self.current_mark().and_then(|m| m.tag);
        div()
            .flex_none()
            .flex()
            .flex_col()
            .gap_2()
            .px_5()
            .py_3()
            .border_b_1()
            .border_color(t.divider)
            .bg(t.header_bg)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(icon("tag", 14., t.text_faint))
                    .child(div().text_size(px(12.)).text_color(t.text_muted).child("研判"))
                    .children(MarkTag::ALL.into_iter().enumerate().map(|(i, tag)| {
                        let on = current == Some(tag);
                        let color = mark_color(t, Some(tag));
                        let hover = t.card_hover;
                        div()
                            .id(("mark-tag", i))
                            .flex_none()
                            .h(px(26.))
                            .px(px(10.))
                            .flex()
                            .items_center()
                            .gap_1()
                            .rounded(px(13.))
                            .border_1()
                            .border_color(if on { color } else { t.border })
                            .bg(if on { color.opacity(0.14) } else { t.card })
                            .text_color(if on { color } else { t.text_muted })
                            .text_size(px(12.))
                            .cursor_pointer()
                            .when(!on, move |d| d.hover(move |s| s.bg(hover)))
                            .child(dot(color, 7.))
                            .child(tag.label())
                            .on_click(cx.listener(move |this, _, _, cx| this.set_mark_tag(tag, cx)))
                    })),
            )
            .child(self.note_input.clone())
            .into_any_element()
    }

    fn render_detail_extra(&mut self, extra: &DetailExtra, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        match extra {
            DetailExtra::None => None,
            DetailExtra::Modules(pid) => Some(self.render_modules(*pid, cx)),
            DetailExtra::Preview(path) => Some(self.render_preview(path.clone(), cx)),
        }
    }

    fn on_close_detail(&mut self, _: &CloseDetail, _: &mut Window, cx: &mut Context<Self>) {
        if self.confirm.take().is_some() || self.menu.take().is_some() {
            cx.notify();
        } else if self.detail.is_some() {
            self.close_detail(cx);
        }
    }

    fn on_select_prev(&mut self, _: &SelectPrev, _: &mut Window, cx: &mut Context<Self>) {
        self.step_selection(-1, cx);
    }

    fn on_select_next(&mut self, _: &SelectNext, _: &mut Window, cx: &mut Context<Self>) {
        self.step_selection(1, cx);
    }

    fn on_copy_selected(&mut self, _: &CopySelected, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(d) = &self.detail {
            let msg = format!("已复制 {}", d.title);
            cx.write_to_clipboard(ClipboardItem::new_string(d.to_text()));
            self.toast(msg, true, cx);
        }
    }

    fn on_focus_search(&mut self, _: &FocusSearch, window: &mut Window, cx: &mut Context<Self>) {
        self.focus_search(window, cx);
    }
}

/// 判断窗口是否运行在软件渲染器上（如没有显卡驱动时的 Microsoft Basic Render Driver）。
/// 环境变量 LWI_SOFTWARE_RENDER=1 可强制按软件渲染处理，便于测试。
fn detect_software_render(window: &Window) -> Option<String> {
    if std::env::var_os("LWI_SOFTWARE_RENDER").is_some() {
        return Some("LWI_SOFTWARE_RENDER".into());
    }
    let specs = window.gpu_specs()?;
    let basic = specs.device_name.contains("Basic Render") || specs.driver_name.contains("0x1414");
    (specs.is_software_emulated || basic).then_some(specs.device_name)
}

fn fresh_stages() -> Vec<StageLog> {
    Stage::ALL
        .iter()
        .map(|s| StageLog { stage: *s, status: StageStatus::Pending, started: None, elapsed_ms: 0, summary: String::new() })
        .collect()
}

fn relaunch_as_admin(cx: &mut gpui::App) {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, PCWSTR, w};
    let Ok(exe) = std::env::current_exe() else { return };
    let exe = HSTRING::from(exe.as_os_str());
    let r = unsafe { ShellExecuteW(None, w!("runas"), &exe, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
    if r.0 as isize > 32 {
        cx.quit();
    }
}

pub fn open_in_explorer(path: &std::path::Path) {
    let _ = std::process::Command::new("explorer.exe").arg(path).spawn();
}

impl Render for AppView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let page: AnyElement = match self.page {
            Page::Overview => self.render_overview(cx).into_any_element(),
            Page::Baseline => self.render_baseline(cx).into_any_element(),
            Page::Timeline => self.render_timeline(cx).into_any_element(),
            Page::Process => self.render_processes(cx).into_any_element(),
            Page::Network => self.render_network(cx).into_any_element(),
            Page::Persistence => self.render_persistence(cx).into_any_element(),
            Page::Account => self.render_accounts(cx).into_any_element(),
            Page::EventLog => self.render_events(cx).into_any_element(),
            Page::File => self.render_files(cx).into_any_element(),
            Page::Registry => self.render_registry(cx).into_any_element(),
            Page::FileManager => self.render_file_manager(cx).into_any_element(),
            Page::Export => self.render_export(cx).into_any_element(),
            Page::Settings => self.render_settings(cx).into_any_element(),
        };
        let drawer = self.detail.clone().map(|d| self.render_drawer(d, cx).into_any_element());
        let menu = self.render_menu(window, cx);
        let confirm = self.render_confirm(cx);
        let toast = self.render_toast(cx);
        div()
            .relative()
            .size_full()
            .track_focus(&self.focus_handle)
            .key_context(CONTEXT)
            .on_action(cx.listener(Self::on_close_detail))
            .on_action(cx.listener(Self::on_select_prev))
            .on_action(cx.listener(Self::on_select_next))
            .on_action(cx.listener(Self::on_copy_selected))
            .on_action(cx.listener(Self::on_focus_search))
            .flex()
            .flex_col()
            .bg(t.bg)
            .text_color(t.text)
            .font_family("Microsoft YaHei UI")
            .child(self.render_titlebar(window, cx))
            .child(
                div()
                    .relative()
                    .flex()
                    .flex_1()
                    .min_h(px(0.))
                    .child(self.render_sidebar(cx))
                    .child(div().flex_1().min_w(px(0.)).h_full().child(page))
                    .children(drawer),
            )
            .children(menu)
            .children(confirm)
            .children(toast)
    }
}
