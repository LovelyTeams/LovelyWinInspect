//! 文件管理页：目录树 + 文件列表、递归搜索、隔离区。文件详情中的预览见 `extras`。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gpui::{
    AnyElement, ClickEvent, Context, Entity, FontWeight, IntoElement, ParentElement, Styled, Task, UniformListScrollHandle,
    div, prelude::*, px, uniform_list,
};

use super::app::{AppView, Detail, DetailExtra, Page};
use super::components::*;
use super::input::{InputEvent, TextInput};
use super::listkit::{ListId, SortVal, refine};
use super::menu::{MenuAct, MenuItem, copy_item, file_items, mi};
use crate::actions::{self, QuarantineEntry};
use crate::collect::fsbrowse::{self, FsEntry, SearchCriteria, SearchProgress};
use crate::theme::{Theme, theme};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FsMode {
    Browse,
    Search,
    Quarantine,
}

/// 搜索的扩展名预设。
pub const EXT_PRESETS: &[(&str, &[&str])] = &[
    ("不限类型", &[]),
    ("可执行文件", fsbrowse::EXEC_EXTS),
    ("脚本", fsbrowse::SCRIPT_EXTS),
    ("Web 脚本", fsbrowse::WEB_EXTS),
    ("文档", fsbrowse::DOC_EXTS),
    ("压缩包", fsbrowse::ARCHIVE_EXTS),
];

pub const DAY_PRESETS: &[(&str, Option<u32>)] = &[("不限时间", None), ("1 天内", Some(1)), ("3 天内", Some(3)), ("7 天内", Some(7)), ("30 天内", Some(30))];

pub const SIZE_PRESETS: &[(&str, Option<u64>)] = &[("不限大小", None), ("≥ 1 MB", Some(1 << 20)), ("≥ 50 MB", Some(50 << 20))];

pub struct FsState {
    pub ready: bool,
    /// None 表示“此电脑”（盘符列表）
    pub dir: Option<PathBuf>,
    pub entries: Vec<FsEntry>,
    pub error: Option<String>,
    pub show_hidden: bool,
    pub back: Vec<Option<PathBuf>>,
    pub mode: FsMode,
    pub path_input: Option<Entity<TextInput>>,
    pub tree_expanded: HashSet<PathBuf>,
    pub tree_cache: HashMap<PathBuf, Vec<PathBuf>>,
    pub tree_scroll: UniformListScrollHandle,
    pub drives: Vec<FsEntry>,
    pub quick: Vec<(&'static str, PathBuf)>,
    // 递归搜索
    pub search_open: bool,
    pub search_input: Option<Entity<TextInput>>,
    pub ext_preset: usize,
    pub day_preset: usize,
    pub size_preset: usize,
    pub search_root: Option<PathBuf>,
    pub progress: Option<Arc<SearchProgress>>,
    pub search_done: Arc<AtomicBool>,
    pub search_task: Option<Task<()>>,
    pub results: Vec<FsEntry>,
    pub scanned: usize,
    // 隔离区
    pub quarantine: Vec<QuarantineEntry>,
    /// 导航完成后要选中的文件
    pub pending_select: Option<String>,
}

impl Default for FsState {
    fn default() -> Self {
        Self {
            ready: false,
            dir: None,
            entries: Vec::new(),
            error: None,
            show_hidden: true,
            back: Vec::new(),
            mode: FsMode::Browse,
            path_input: None,
            tree_expanded: HashSet::new(),
            tree_cache: HashMap::new(),
            tree_scroll: UniformListScrollHandle::new(),
            drives: Vec::new(),
            quick: Vec::new(),
            search_open: false,
            search_input: None,
            ext_preset: 1,
            day_preset: 0,
            size_preset: 0,
            search_root: None,
            progress: None,
            search_done: Arc::new(AtomicBool::new(true)),
            search_task: None,
            results: Vec::new(),
            scanned: 0,
            quarantine: Vec::new(),
            pending_select: None,
        }
    }
}

const FS_COLS: &[Col] = &[
    flex_col("名称"),
    col("修改时间", 150.),
    col("创建时间", 150.),
    col("大小", 90.),
    col("属性", 52.),
    col("提示", 220.),
];

const SEARCH_COLS: &[Col] = &[
    col("名称", 220.),
    flex_col("所在目录"),
    col("修改时间", 150.),
    col("大小", 90.),
    col("属性", 52.),
    col("提示", 200.),
];

const Q_COLS: &[Col] = &[flex_col("原路径"), col("大小", 90.), col("隔离时间", 150.), col("SHA256", 220.)];

fn fs_key(e: &FsEntry, col: usize, search: bool) -> SortVal {
    // 浏览模式下目录始终在前
    let dir_first = |v: SortVal| match v {
        SortVal::S(s) if !search => SortVal::S(format!("{}{}", if e.is_dir { '0' } else { '1' }, s)),
        other => other,
    };
    match (search, col) {
        (false, 0) | (true, 0) => dir_first(SortVal::s(&e.name)),
        (true, 1) => SortVal::s(&e.parent()),
        (false, 1) | (true, 2) => SortVal::t(e.modified),
        (false, 2) => SortVal::t(e.created),
        (false, 3) | (true, 3) => SortVal::N(e.size as i64),
        (false, 4) | (true, 4) => SortVal::S(e.attr_text()),
        _ => SortVal::S(String::new()),
    }
}

impl AppView {
    /// 首次进入文件管理页时初始化输入框与盘符。
    fn fs_init(&mut self, cx: &mut Context<Self>) {
        if self.fs.ready {
            return;
        }
        self.fs.ready = true;
        self.fs.drives = fsbrowse::drives();
        self.fs.quick = fsbrowse::quick_locations();
        self.fs.quarantine = actions::quarantine_list();
        let path_input = cx.new(|cx| TextInput::new("输入路径后回车，如 C:\\ProgramData", cx).with_icon("folder"));
        let sub = cx.subscribe(&path_input, |this, input, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Submit) {
                let text = input.read(cx).text().trim().trim_matches('"').to_string();
                if text.is_empty() {
                    this.fs_navigate(None, true, cx);
                } else {
                    this.browse_to_file(&crate::collect::util::expand_env(&text), cx);
                }
            }
        });
        self.subscriptions.push(sub);
        let search_input = cx.new(|cx| TextInput::new("文件名关键字，支持 * 和 ?，回车开始搜索", cx).with_icon("search"));
        let sub = cx.subscribe(&search_input, |this, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Submit) {
                this.start_fs_search(cx);
            }
        });
        self.subscriptions.push(sub);
        self.fs.path_input = Some(path_input);
        self.fs.search_input = Some(search_input);
        self.fs_reload(cx);
    }

    /// 当前列表的数据源（浏览或搜索结果）。
    fn fs_items(&self) -> &Vec<FsEntry> {
        if self.fs.mode == FsMode::Search { &self.fs.results } else { &self.fs.entries }
    }

    fn fs_entry(&self, i: usize) -> Option<&FsEntry> {
        self.fs_items().get(i)
    }

    /// 进入目录。`push` 为 true 时记录到后退历史。
    pub fn fs_navigate(&mut self, dir: Option<PathBuf>, push: bool, cx: &mut Context<Self>) {
        if push && self.fs.dir != dir {
            let prev = self.fs.dir.clone();
            self.fs.back.push(prev);
            if self.fs.back.len() > 100 {
                self.fs.back.remove(0);
            }
        }
        self.fs.dir = dir;
        self.fs.mode = FsMode::Browse;
        self.detail = None;
        self.selected = None;
        self.scrolls.entry(ListId::Fs).or_default().scroll_to_item(0, gpui::ScrollStrategy::Top);
        self.fs_reload(cx);
        // 展开目录树中的祖先
        if let Some(d) = self.fs.dir.clone() {
            for a in d.ancestors() {
                let a = a.to_path_buf();
                if !self.fs.tree_cache.contains_key(&a) {
                    let kids = fsbrowse::sub_dirs(&a, self.fs.show_hidden);
                    self.fs.tree_cache.insert(a.clone(), kids);
                }
                self.fs.tree_expanded.insert(a);
            }
        }
        cx.notify();
    }

    fn fs_reload(&mut self, cx: &mut Context<Self>) {
        self.previews.clear();
        let text = self.fs.dir.as_ref().map(|d| d.display().to_string()).unwrap_or_default();
        if let Some(input) = self.fs.path_input.clone() {
            input.update(cx, |i, cx| i.set_text(text, cx));
        }
        match &self.fs.dir {
            None => {
                self.fs.drives = fsbrowse::drives();
                self.fs.entries = self.fs.drives.clone();
                self.fs.error = None;
            }
            Some(d) => match fsbrowse::list_dir(d, self.fs.show_hidden) {
                Ok(v) => {
                    self.fs.entries = v;
                    self.fs.error = None;
                }
                Err(e) => {
                    self.fs.entries.clear();
                    self.fs.error = Some(e);
                }
            },
        }
        if let Some(target) = self.fs.pending_select.take() {
            let target = target.to_lowercase();
            if let Some(i) = self.fs.entries.iter().position(|e| e.path.to_lowercase() == target) {
                // 选中目标；默认排序下下标即行号
                self.scrolls.entry(ListId::Fs).or_default().scroll_to_item(i, gpui::ScrollStrategy::Center);
                self.open_item(ListId::Fs, i, cx);
            }
        }
    }

    /// 处置动作后刷新当前视图。
    pub fn fs_refresh(&mut self, cx: &mut Context<Self>) {
        self.previews.clear();
        if !self.fs.ready {
            return;
        }
        self.fs.quarantine = actions::quarantine_list();
        match self.fs.mode {
            FsMode::Search => self.fs.results.retain(|e| Path::new(&e.path).exists()),
            _ => self.fs_reload(cx),
        }
        cx.notify();
    }

    /// 打开文件管理页并定位到某个文件或目录。
    pub fn browse_to_file(&mut self, path: &str, cx: &mut Context<Self>) {
        self.fs_init(cx);
        self.page = Page::FileManager;
        let p = PathBuf::from(path);
        if p.is_dir() {
            self.fs_navigate(Some(p), true, cx);
        } else if let Some(parent) = p.parent().filter(|d| d.is_dir()) {
            self.fs.pending_select = Some(path.to_string());
            self.fs_navigate(Some(parent.to_path_buf()), true, cx);
        } else {
            self.toast(format!("路径不存在：{path}"), false, cx);
        }
    }

    fn fs_back(&mut self, cx: &mut Context<Self>) {
        if let Some(prev) = self.fs.back.pop() {
            self.fs_navigate(prev, false, cx);
        }
    }

    fn fs_up(&mut self, cx: &mut Context<Self>) {
        let parent = self.fs.dir.as_ref().and_then(|d| d.parent().map(Path::to_path_buf));
        if self.fs.dir.is_some() {
            self.fs_navigate(parent, true, cx);
        }
    }

    /// 行点击：目录双击进入，其余打开详情。
    pub fn on_fs_click(&mut self, i: usize, ev: &ClickEvent, cx: &mut Context<Self>) {
        let dir = self.fs_entry(i).filter(|e| e.is_dir).map(|e| PathBuf::from(&e.path));
        match dir {
            Some(d) if ev.click_count() >= 2 => self.fs_navigate(Some(d), true, cx),
            _ => self.open_item(ListId::Fs, i, cx),
        }
    }

    pub fn fs_mark_key(&self, i: usize) -> Option<String> {
        let e = self.fs_entry(i)?;
        (!e.is_dir).then(|| format!("fs|{}", e.path.to_lowercase()))
    }

    pub fn fs_menu(&self, i: usize) -> Vec<MenuItem> {
        let Some(e) = self.fs_entry(i) else { return Vec::new() };
        let mut v = Vec::new();
        if e.is_dir {
            v.push(mi("folder-open", "进入目录", MenuAct::FsOpenDir(e.path.clone())));
            v.push(mi("external-link", "在资源管理器中打开", MenuAct::OpenFolder(e.path.clone())));
            v.extend(copy_item("copy", "路径", &e.path));
            v.push(mi("search", "在此目录中搜索", MenuAct::FsSearchHere(e.path.clone())));
        } else {
            v.extend(file_items(&e.path).into_iter().filter(|m| !matches!(m.act, MenuAct::BrowseTo(_))));
            v.push(mi("archive", "隔离文件", MenuAct::Quarantine(e.path.clone())));
        }
        if e.hidden() && self.fs.dir.is_some() {
            v.push(mi("eye-off", "恢复隐藏/系统属性", MenuAct::ClearHidden(e.path.clone())));
        }
        v
    }

    pub fn fs_detail(&self, i: usize) -> Option<Detail> {
        let e = self.fs_entry(i)?;
        let recent = Some(crate::collect::util::days_ago(self.lookback));
        let hints = e.hints(recent);
        let kind = if self.fs.dir.is_none() {
            e.note.clone()
        } else if e.is_dir {
            "文件夹".to_string()
        } else {
            let ext = e.ext();
            if ext.is_empty() { "文件".into() } else { format!("{} 文件", ext.to_uppercase()) }
        };
        let d = Detail::new(e.name.clone(), e.parent(), None)
            .field("研判提示", if hints.is_empty() { String::new() } else { hints.join("；") })
            .field("路径", e.path.clone())
            .field("类型", kind)
            .field("大小", if e.is_dir { String::new() } else { format!("{}（{} 字节）", fmt_size(e.size), e.size) })
            .field("创建时间", fmt_time(e.created))
            .field("修改时间", fmt_time(e.modified))
            .field("访问时间", fmt_time(e.accessed))
            .field("属性", fsbrowse::attr_label(e.attrs));
        Some(if e.is_dir { d } else { d.extra(DetailExtra::Preview(e.path.clone())) })
    }

    pub fn quarantine_menu(&self, i: usize) -> Vec<MenuItem> {
        let Some(q) = self.fs.quarantine.get(i) else { return Vec::new() };
        let mut v = vec![mi("rotate-ccw", "还原到原位置", MenuAct::RestoreQuarantine(q.id.clone(), q.original.clone()))];
        v.extend(copy_item("copy", "原路径", &q.original));
        v.extend(copy_item("key", "SHA256", &q.sha256));
        v
    }

    pub fn quarantine_detail(&self, i: usize) -> Option<Detail> {
        let q = self.fs.quarantine.get(i)?;
        let name = Path::new(&q.original).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| q.original.clone());
        Some(
            Detail::new(name, "隔离区", None)
                .field("原路径", q.original.clone())
                .field("大小", format!("{}（{} 字节）", fmt_size(q.size), q.size))
                .field("SHA256", q.sha256.clone())
                .field("隔离时间", fmt_time(Some(q.time)))
                .field("原属性", if q.attributes == u32::MAX { "-".into() } else { fsbrowse::attr_label(q.attributes) })
                .field("隔离文件", actions::quarantine_dir().join(format!("{}.lwiq", q.id)).display().to_string())
                .field("说明", "隔离文件按字节异或 0xA5 保存，不能直接运行；还原时会校验 SHA256。"),
        )
    }

    // ---------------------------------------------------------------- 搜索

    fn criteria(&self, cx: &gpui::App) -> SearchCriteria {
        let name = self.fs.search_input.as_ref().map(|i| i.read(cx).text().trim().to_lowercase()).unwrap_or_default();
        SearchCriteria {
            name,
            exts: EXT_PRESETS[self.fs.ext_preset].1.to_vec(),
            since: DAY_PRESETS[self.fs.day_preset].1.map(crate::collect::util::days_ago),
            min_size: SIZE_PRESETS[self.fs.size_preset].1,
            include_dirs: false,
        }
    }

    pub fn start_fs_search(&mut self, cx: &mut Context<Self>) {
        let Some(root) = self.fs.dir.clone() else {
            self.toast("请先进入要搜索的目录（如 C:\\）", false, cx);
            return;
        };
        self.stop_fs_search();
        let crit = self.criteria(cx);
        if crit.name.is_empty() && crit.exts.is_empty() && crit.since.is_none() && crit.min_size.is_none() {
            self.toast("请至少设置一个搜索条件", false, cx);
            return;
        }
        let progress = Arc::new(SearchProgress::default());
        let done = Arc::new(AtomicBool::new(false));
        self.fs.progress = Some(progress.clone());
        self.fs.search_done = done.clone();
        self.fs.search_root = Some(root.clone());
        self.fs.results.clear();
        self.fs.scanned = 0;
        self.fs.mode = FsMode::Search;
        self.detail = None;
        self.selected = None;
        let bg = {
            let progress = progress.clone();
            let done = done.clone();
            cx.background_executor().spawn(async move {
                fsbrowse::search(&root, &crit, &progress);
                done.store(true, Ordering::Release);
            })
        };
        bg.detach();
        // 前台定时拉取进度
        self.fs.search_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_millis(300)).await;
                let finished = done.load(Ordering::Acquire);
                let ok = this.update(cx, |this, cx| {
                    if let Some(p) = &this.fs.progress {
                        this.fs.scanned = p.scanned.load(Ordering::Relaxed);
                        if let Ok(r) = p.results.lock()
                            && r.len() != this.fs.results.len()
                        {
                            this.fs.results = r.clone();
                        }
                    }
                    cx.notify();
                });
                if finished || ok.is_err() {
                    break;
                }
            }
        }));
        cx.notify();
    }

    fn stop_fs_search(&mut self) {
        if let Some(p) = &self.fs.progress {
            p.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn searching(&self) -> bool {
        !self.fs.search_done.load(Ordering::Acquire)
    }

    // ---------------------------------------------------------------- 渲染

    pub fn render_file_manager(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        self.fs_init(cx);
        let t = theme(cx);
        let query = self.query(Page::FileManager, cx);
        let mode = self.fs.mode;
        let recent = Some(crate::collect::util::days_ago(self.lookback));

        let table: AnyElement = match mode {
            FsMode::Quarantine => {
                let idx = refine(
                    (0..self.fs.quarantine.len()).rev().collect(),
                    &self.fs.quarantine,
                    &query,
                    self.sort_of(ListId::Quarantine),
                    |q| format!("{} {}", q.original, q.sha256),
                    |q, c| match c {
                        0 => SortVal::s(&q.original),
                        1 => SortVal::N(q.size as i64),
                        2 => SortVal::t(Some(q.time)),
                        _ => SortVal::s(&q.sha256),
                    },
                );
                self.virtual_table(&t, ListId::Quarantine, Q_COLS, Rc::new(idx), "隔离区为空", cx, |this, i, ix, t, _cx| {
                    let q = &this.fs.quarantine[i];
                    table_row(
                        t,
                        ("q", ix),
                        Q_COLS,
                        vec![
                            div()
                                .w_full()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(icon("archive", 14., t.orange))
                                .child(div().flex_1().min_w_0().truncate().child(q.original.clone()))
                                .into_any_element(),
                            muted_cell(t, fmt_size(q.size)),
                            muted_cell(t, fmt_time(Some(q.time))),
                            mono_cell(t, q.sha256.clone()),
                        ],
                    )
                })
                .into_any_element()
            }
            FsMode::Browse | FsMode::Search => {
                let search = mode == FsMode::Search;
                let cols = if search { SEARCH_COLS } else { FS_COLS };
                let items = self.fs_items();
                let idx = refine(
                    (0..items.len()).collect(),
                    items,
                    &query,
                    self.sort_of(ListId::Fs),
                    |e| format!("{} {}", e.name, e.note),
                    move |e, c| fs_key(e, c, search),
                );
                let empty = if search {
                    if self.searching() { "正在搜索…" } else { "没有找到符合条件的文件" }
                } else if self.fs.error.is_some() {
                    "无法读取该目录"
                } else {
                    "空目录"
                };
                self.virtual_table(&t, ListId::Fs, cols, Rc::new(idx), empty, cx, move |this, i, ix, t, _cx| {
                    let items = if search { &this.fs.results } else { &this.fs.entries };
                    let e = &items[i];
                    let hints = e.hints(recent);
                    let name = div()
                        .w_full()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(if this.fs.dir.is_none() && !search {
                            icon("hard-drive", 15., t.text_muted)
                        } else if e.is_dir {
                            icon("folder", 15., t.orange)
                        } else {
                            icon("file", 15., if hints.is_empty() { t.text_faint } else { t.red })
                        })
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_color(if e.hidden() { t.text_muted } else { t.text })
                                .when(!e.hidden(), |d| d.font_weight(FontWeight::MEDIUM))
                                .child(if e.note.is_empty() { e.name.clone() } else { format!("{}  {}", e.name, e.note) }),
                        )
                        .into_any_element();
                    let hint_cell = if hints.is_empty() {
                        muted_cell(t, "")
                    } else {
                        div().w_full().truncate().text_size(px(12.)).text_color(t.red).child(hints.join("；")).into_any_element()
                    };
                    let size = if e.is_dir { String::new() } else { fmt_size(e.size) };
                    let cells = if search {
                        vec![
                            name,
                            muted_cell(t, e.parent()),
                            muted_cell(t, fmt_time(e.modified)),
                            muted_cell(t, size),
                            mono_cell(t, e.attr_text()),
                            hint_cell,
                        ]
                    } else {
                        vec![
                            name,
                            muted_cell(t, fmt_time(e.modified)),
                            muted_cell(t, fmt_time(e.created)),
                            muted_cell(t, size),
                            mono_cell(t, e.attr_text()),
                            hint_cell,
                        ]
                    };
                    table_row(t, ("fs", ix), cols, cells)
                })
                .into_any_element()
            }
        };

        let search_box = self.search_box(Page::FileManager, cx);
        let toolbar = self.render_fs_toolbar(&t, cx);
        let panel = self.fs.search_open.then(|| self.render_search_panel(&t, cx));
        let status = self.render_fs_status(&t);
        let sidebar = self.render_fs_sidebar(&t, cx);

        div()
            .size_full()
            .p(px(20.))
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_4()
                    .child(div().flex_1().min_w_0().child(page_title(&t, "文件管理", "浏览隐藏文件与备用数据流、递归搜索可疑文件、预览内容与 PE 信息，并支持隔离与还原")))
                    .child(search_box),
            )
            .child(toolbar)
            .children(panel)
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h(px(0.))
                    .gap(px(12.))
                    .child(sidebar)
                    .child(div().flex_1().min_w(px(0.)).h_full().flex().flex_col().gap(px(8.)).child(table).child(status)),
            )
    }

    fn render_fs_toolbar(&mut self, t: &Theme, cx: &mut Context<Self>) -> gpui::Div {
        let icon_btn = |id: &'static str, name: &'static str, tip: &'static str, enabled: bool| {
            let hover = t.card_hover;
            div()
                .id(id)
                .flex_none()
                .size(px(30.))
                .flex()
                .items_center()
                .justify_center()
                .rounded(px(6.))
                .border_1()
                .border_color(t.border)
                .bg(t.card)
                .when(enabled, move |d| d.cursor_pointer().hover(move |s| s.bg(hover)))
                .child(icon(name, 15., if enabled { t.text_muted } else { t.border }))
                .tooltip(tooltip(tip))
        };
        let can_back = !self.fs.back.is_empty();
        let can_up = self.fs.dir.is_some();
        let mode = self.fs.mode;
        let q = self.fs.quarantine.len();
        div()
            .flex()
            .items_center()
            .gap_2()
            .child(icon_btn("fs-back", "arrow-left", "后退", can_back).on_click(cx.listener(|this, _, _, cx| this.fs_back(cx))))
            .child(icon_btn("fs-up", "arrow-up", "上一级", can_up).on_click(cx.listener(|this, _, _, cx| this.fs_up(cx))))
            .child(icon_btn("fs-refresh", "refresh", "刷新", true).on_click(cx.listener(|this, _, _, cx| {
                this.fs.mode = FsMode::Browse;
                this.fs_reload(cx);
                cx.notify();
            })))
            .child(div().flex_1().min_w_0().children(self.fs.path_input.clone()))
            .child(chip(t, "fs-hidden", "显示隐藏/系统文件", self.fs.show_hidden).on_click(cx.listener(|this, _, _, cx| {
                this.fs.show_hidden = !this.fs.show_hidden;
                this.fs.tree_cache.clear();
                this.fs_reload(cx);
                cx.notify();
            })))
            .child(chip(t, "fs-search", "递归搜索", self.fs.search_open).on_click(cx.listener(|this, _, window, cx| {
                this.fs.search_open = !this.fs.search_open;
                if this.fs.search_open
                    && let Some(i) = &this.fs.search_input
                {
                    i.read(cx).focus(window);
                }
                cx.notify();
            })))
            .when(mode == FsMode::Search, |d| {
                d.child(chip(t, "fs-browse", "返回目录", false).on_click(cx.listener(|this, _, _, cx| {
                    this.stop_fs_search();
                    this.fs.mode = FsMode::Browse;
                    this.detail = None;
                    this.selected = None;
                    cx.notify();
                })))
            })
            .child(chip(t, "fs-quarantine", format!("隔离区 ({q})"), mode == FsMode::Quarantine).on_click(cx.listener(|this, _, _, cx| {
                this.fs.quarantine = actions::quarantine_list();
                this.fs.mode = if this.fs.mode == FsMode::Quarantine { FsMode::Browse } else { FsMode::Quarantine };
                this.detail = None;
                this.selected = None;
                cx.notify();
            })))
    }

    fn render_search_panel(&mut self, t: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let running = self.searching();
        let root = self.fs.dir.as_ref().map(|d| d.display().to_string()).unwrap_or_else(|| "（请先进入一个目录）".into());
        let row = |label: &'static str| div().flex().flex_wrap().items_center().gap_2().child(div().w(px(56.)).flex_none().text_size(px(12.)).text_color(t.text_muted).child(label));
        card(t)
            .p(px(14.))
            .flex()
            .flex_col()
            .gap(px(10.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().w(px(56.)).flex_none().text_size(px(12.)).text_color(t.text_muted).child("文件名"))
                    .child(div().flex_1().min_w_0().children(self.fs.search_input.clone()))
                    .child(if running {
                        small_button(t, "fs-stop", "circle-stop", "停止").on_click(cx.listener(|this, _, _, cx| {
                            this.stop_fs_search();
                            cx.notify();
                        }))
                    } else {
                        small_button(t, "fs-go", "search", "开始搜索").on_click(cx.listener(|this, _, _, cx| this.start_fs_search(cx)))
                    }),
            )
            .child(row("类型").children(EXT_PRESETS.iter().enumerate().map(|(i, (label, exts))| {
                chip(t, ("fs-ext", i), *label, self.fs.ext_preset == i)
                    .when(!exts.is_empty(), |d| d.tooltip(tooltip(exts.join(" "))))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.fs.ext_preset = i;
                        cx.notify();
                    }))
            })))
            .child(
                row("修改/创建")
                    .children(DAY_PRESETS.iter().enumerate().map(|(i, (label, _))| {
                        chip(t, ("fs-day", i), *label, self.fs.day_preset == i).on_click(cx.listener(move |this, _, _, cx| {
                            this.fs.day_preset = i;
                            cx.notify();
                        }))
                    }))
                    .child(div().w(px(1.)).h(px(18.)).bg(t.border).mx_1())
                    .children(SIZE_PRESETS.iter().enumerate().map(|(i, (label, _))| {
                        chip(t, ("fs-size", i), *label, self.fs.size_preset == i).on_click(cx.listener(move |this, _, _, cx| {
                            this.fs.size_preset = i;
                            cx.notify();
                        }))
                    })),
            )
            .child(div().text_size(px(12.)).text_color(t.text_faint).child(format!("在 {root} 下递归搜索（包含隐藏文件，不跟随目录联接，最多 {} 条结果）", fsbrowse::MAX_RESULTS)))
            .into_any_element()
    }

    fn render_fs_status(&self, t: &Theme) -> AnyElement {
        let text = match self.fs.mode {
            FsMode::Browse => match &self.fs.error {
                Some(e) => e.clone(),
                None => {
                    let dirs = self.fs.entries.iter().filter(|e| e.is_dir).count();
                    let hidden = self.fs.entries.iter().filter(|e| e.hidden()).count();
                    format!("{} 个文件夹，{} 个文件{}", dirs, self.fs.entries.len() - dirs, if hidden > 0 { format!("（隐藏/系统 {hidden} 个）") } else { String::new() })
                }
            },
            FsMode::Search => {
                let root = self.fs.search_root.as_ref().map(|d| d.display().to_string()).unwrap_or_default();
                format!(
                    "{}：已扫描 {} 项，找到 {} 个 · {}",
                    if self.searching() { "正在搜索" } else { "搜索完成" },
                    self.fs.scanned,
                    self.fs.results.len(),
                    root
                )
            }
            FsMode::Quarantine => format!("隔离区位置：{}", actions::quarantine_dir().display()),
        };
        div()
            .flex()
            .items_center()
            .gap_2()
            .text_size(px(12.))
            .text_color(if self.fs.error.is_some() && self.fs.mode == FsMode::Browse { t.red } else { t.text_muted })
            .when(self.fs.mode == FsMode::Search && self.searching(), |d| d.child(spinner("fs-spin", 12., t.primary)))
            .child(text)
            .into_any_element()
    }

    /// 左侧：快速位置 + 目录树。
    fn render_fs_sidebar(&mut self, t: &Theme, cx: &mut Context<Self>) -> AnyElement {
        // 展平目录树
        let mut rows: Vec<(PathBuf, u16, bool)> = Vec::new();
        fn walk(p: &Path, depth: u16, fs: &FsState, rows: &mut Vec<(PathBuf, u16, bool)>) {
            let expanded = fs.tree_expanded.contains(p);
            rows.push((p.to_path_buf(), depth, expanded));
            if expanded && let Some(kids) = fs.tree_cache.get(p) {
                for k in kids {
                    walk(k, depth + 1, fs, rows);
                }
            }
        }
        for d in &self.fs.drives {
            walk(Path::new(&d.path), 0, &self.fs, &mut rows);
        }
        let current = self.fs.dir.clone();
        let rows = Rc::new(rows);
        let n = rows.len();
        let hover = t.card_hover;
        let quick: Vec<AnyElement> = std::iter::once(("此电脑", None))
            .chain(self.fs.quick.iter().map(|(l, p)| (*l, Some(p.clone()))))
            .enumerate()
            .map(|(i, (label, path))| {
                let active = self.fs.mode == FsMode::Browse && current == path;
                div()
                    .id(("fs-quick", i))
                    .h(px(28.))
                    .px(px(8.))
                    .flex()
                    .items_center()
                    .gap_2()
                    .rounded(px(6.))
                    .cursor_pointer()
                    .text_size(px(12.5))
                    .when(active, |d| d.bg(t.primary_soft).text_color(t.primary))
                    .when(!active, move |d| d.hover(move |s| s.bg(hover)))
                    .child(icon(if path.is_none() { "monitor" } else { "folder" }, 14., if active { t.primary } else { t.text_faint }))
                    .child(div().flex_1().min_w_0().truncate().child(label))
                    .when_some(path.clone(), |d, p| d.tooltip(tooltip(p.display().to_string())))
                    .on_click(cx.listener(move |this, _, _, cx| this.fs_navigate(path.clone(), true, cx)))
                    .into_any_element()
            })
            .collect();
        let tree = uniform_list(
            "fs-tree",
            n,
            cx.processor(move |this, range: std::ops::Range<usize>, _window, cx| {
                let t = theme(cx);
                let current = this.fs.dir.clone();
                range
                    .map(|ix| {
                        let (path, depth, expanded) = rows[ix].clone();
                        let active = current.as_deref() == Some(path.as_path()) && this.fs.mode == FsMode::Browse;
                        let has_kids = this.fs.tree_cache.get(&path).is_none_or(|k| !k.is_empty());
                        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string());
                        let toggle_path = path.clone();
                        let nav_path = path.clone();
                        let hover = t.card_hover;
                        div()
                            .id(("fs-tree-row", ix))
                            .h(px(26.))
                            .pl(px(4. + depth as f32 * 14.))
                            .pr(px(6.))
                            .flex()
                            .items_center()
                            .gap_1()
                            .rounded(px(5.))
                            .cursor_pointer()
                            .text_size(px(12.5))
                            .when(active, |d| d.bg(t.primary_soft).text_color(t.primary))
                            .when(!active, move |d| d.hover(move |s| s.bg(hover)))
                            .child(
                                div()
                                    .id(("fs-tree-toggle", ix))
                                    .flex_none()
                                    .size(px(16.))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .when(has_kids, |d| d.child(icon(if expanded { "chevron-down" } else { "chevron-right" }, 12., t.text_faint)))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        cx.stop_propagation();
                                        if !this.fs.tree_expanded.remove(&toggle_path) {
                                            if !this.fs.tree_cache.contains_key(&toggle_path) {
                                                let kids = fsbrowse::sub_dirs(&toggle_path, this.fs.show_hidden);
                                                this.fs.tree_cache.insert(toggle_path.clone(), kids);
                                            }
                                            this.fs.tree_expanded.insert(toggle_path.clone());
                                        }
                                        cx.notify();
                                    })),
                            )
                            .child(icon(if depth == 0 { "hard-drive" } else { "folder" }, 13., if active { t.primary } else { t.orange }))
                            .child(div().flex_1().min_w_0().truncate().child(name))
                            .on_click(cx.listener(move |this, _, _, cx| this.fs_navigate(Some(nav_path.clone()), true, cx)))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(self.fs.tree_scroll.clone())
        .flex_1()
        .min_h(px(0.));
        card(t)
            .w(px(250.))
            .flex_none()
            .h_full()
            .p(px(8.))
            .flex()
            .flex_col()
            .gap(px(2.))
            .child(div().px(px(8.)).pb(px(4.)).text_size(px(12.)).text_color(t.text_faint).child("快速位置"))
            .children(quick)
            .child(div().h(px(1.)).bg(t.divider).my(px(6.)))
            .child(div().px(px(8.)).pb(px(4.)).text_size(px(12.)).text_color(t.text_faint).child("目录树"))
            .child(tree)
            .into_any_element()
    }
}
