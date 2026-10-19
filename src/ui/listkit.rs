//! 列表通用能力：关键字搜索、表头排序、选中高亮、键盘切换记录、研判标记。
//!
//! 各列表页只负责“筛选出哪些记录、每列显示什么”，点击、右键、选中、标记由
//! [`AppView::virtual_table`] 统一处理。

use std::rc::Rc;

use gpui::{
    AnyElement, App, Context, Entity, IntoElement, ParentElement, ScrollStrategy, Stateful, Styled, Window, div,
    prelude::*, px, uniform_list,
};

use super::app::{AppView, Page};
use super::components::*;
use super::input::{InputEvent, TextInput};
use crate::model::{Mark, MarkTag};
use crate::theme::{Theme, theme};

/// 可选中、可排序的列表。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ListId {
    Proc,
    Net,
    Dns,
    Arp,
    Persist,
    Event,
    File,
    Reg,
    Fs,
    Quarantine,
    Finding,
    Timeline,
}

impl ListId {
    fn element_id(self) -> &'static str {
        match self {
            ListId::Proc => "list-proc",
            ListId::Net => "list-net",
            ListId::Dns => "list-dns",
            ListId::Arp => "list-arp",
            ListId::Persist => "list-persist",
            ListId::Event => "list-event",
            ListId::File => "list-file",
            ListId::Reg => "list-reg",
            ListId::Fs => "list-fs",
            ListId::Quarantine => "list-quarantine",
            ListId::Finding => "list-finding",
            ListId::Timeline => "list-timeline",
        }
    }
}

/// 排序键：数字优先按数值比较，文本按小写比较。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SortVal {
    N(i64),
    S(String),
}

impl SortVal {
    pub fn s(s: &str) -> SortVal {
        SortVal::S(s.to_lowercase())
    }

    pub fn t(t: Option<crate::model::Time>) -> SortVal {
        SortVal::N(t.map(|t| t.timestamp()).unwrap_or(i64::MIN))
    }
}

/// 关键字匹配：空格分隔的每个词都要出现在 haystack 中（不区分大小写）。
pub fn matches_query(haystack: &str, query: &str) -> bool {
    let hay = haystack.to_lowercase();
    query.split_whitespace().all(|w| hay.contains(&w.to_lowercase()))
}

/// 在筛选结果上应用搜索与排序。
pub fn refine<T>(
    idx: Vec<usize>,
    items: &[T],
    query: &str,
    sort: Option<(usize, bool)>,
    hay: impl Fn(&T) -> String,
    key: impl Fn(&T, usize) -> SortVal,
) -> Vec<usize> {
    let mut idx = idx;
    if !query.trim().is_empty() {
        idx.retain(|&i| matches_query(&hay(&items[i]), query));
    }
    if let Some((col, desc)) = sort {
        idx.sort_by_cached_key(|&i| key(&items[i], col));
        if desc {
            idx.reverse();
        }
    }
    idx
}

pub fn mark_color(t: &Theme, tag: Option<MarkTag>) -> gpui::Hsla {
    match tag {
        Some(MarkTag::Malicious) => t.red,
        Some(MarkTag::Suspicious) => t.orange,
        Some(MarkTag::FalsePositive) => t.text_faint,
        Some(MarkTag::Handled) => t.green,
        None => t.blue,
    }
}

impl AppView {
    // ---------------------------------------------------------------- 搜索

    /// 页面的搜索框（首次使用时创建）。
    pub fn search_input(&mut self, page: Page, cx: &mut Context<Self>) -> Entity<TextInput> {
        if let Some(e) = self.searches.get(&page) {
            return e.clone();
        }
        let e = cx.new(|cx| TextInput::new("搜索，空格分隔多个关键字  Ctrl+F", cx).with_icon("search"));
        let sub = cx.subscribe(&e, |this, _, ev: &InputEvent, cx| {
            if matches!(ev, InputEvent::Changed) {
                this.selected = None;
                cx.notify();
            }
        });
        self.subscriptions.push(sub);
        self.searches.insert(page, e.clone());
        e
    }

    pub fn search_box(&mut self, page: Page, cx: &mut Context<Self>) -> AnyElement {
        div().w(px(300.)).flex_none().child(self.search_input(page, cx)).into_any_element()
    }

    pub fn query(&self, page: Page, cx: &App) -> String {
        self.searches.get(&page).map(|e| e.read(cx).text().trim().to_string()).unwrap_or_default()
    }

    pub fn sort_of(&self, list: ListId) -> Option<(usize, bool)> {
        self.sorts.get(&list).copied()
    }

    /// 点击表头：升序 → 降序 → 取消排序。
    fn toggle_sort(&mut self, list: ListId, col: usize, cx: &mut Context<Self>) {
        // 进程树按父子关系排列，列序号也与列表视图不同，不参与排序
        if list == ListId::Proc && self.proc_tree {
            return;
        }
        match self.sorts.get(&list).copied() {
            Some((c, false)) if c == col => {
                self.sorts.insert(list, (col, true));
            }
            Some((c, true)) if c == col => {
                self.sorts.remove(&list);
            }
            _ => {
                self.sorts.insert(list, (col, false));
            }
        }
        cx.notify();
    }

    fn sort_header(&self, t: &Theme, list: ListId, cols: &'static [Col], cx: &mut Context<Self>) -> gpui::Div {
        let sort = self.sort_of(list);
        let hover = t.text;
        div()
            .flex()
            .flex_none()
            .items_center()
            .h(px(36.))
            .px(px(12.))
            .gap(px(12.))
            .bg(t.header_bg)
            .border_b_1()
            .border_color(t.divider)
            .text_size(px(12.))
            .text_color(t.text_muted)
            .children(cols.iter().enumerate().map(|(i, c)| {
                let active = sort.filter(|(col, _)| *col == i);
                let cell = div()
                    .id(("sort-h", i))
                    .flex()
                    .items_center()
                    .gap(px(2.))
                    .overflow_hidden()
                    .cursor_pointer()
                    .hover(move |s| s.text_color(hover))
                    .when(active.is_some(), |d| d.text_color(t.primary))
                    .child(div().truncate().child(c.title))
                    .when_some(active, |d, (_, desc)| d.child(icon(if desc { "chevron-down" } else { "chevron-up" }, 12., t.primary)))
                    .tooltip(tooltip("点击排序：升序 / 降序 / 取消"))
                    .on_click(cx.listener(move |this, _, _, cx| this.toggle_sort(list, i, cx)));
                match c.width {
                    Some(w) => cell.w(px(w)).flex_none(),
                    None => cell.flex_1().min_w(px(80.)),
                }
            }))
    }

    // ---------------------------------------------------------------- 表格

    /// 带表头的虚拟滚动表格。`row` 只负责渲染各列；点击打开详情、右键菜单、选中高亮与
    /// 标记色条在这里统一处理。
    pub fn virtual_table<F>(
        &mut self,
        t: &Theme,
        list: ListId,
        cols: &'static [Col],
        rows: Rc<Vec<usize>>,
        empty_text: &str,
        cx: &mut Context<Self>,
        row: F,
    ) -> gpui::Div
    where
        F: Fn(&mut AppView, usize, usize, &Theme, &mut Context<AppView>) -> Stateful<gpui::Div> + 'static,
    {
        self.nav = Some((list, rows.clone()));
        let scroll = self.scrolls.entry(list).or_default().clone();
        let n = rows.len();
        let body: AnyElement = if n == 0 {
            empty_state(t, "check-circle", empty_text.to_string()).into_any_element()
        } else {
            uniform_list(
                list.element_id(),
                n,
                cx.processor(move |this, range: std::ops::Range<usize>, _window, cx| {
                    let t = theme(cx);
                    range
                        .map(|ix| {
                            let i = rows[ix];
                            let selected = this.selected == Some((list, i));
                            let tag = this.mark_key(list, i).and_then(|k| this.marks.get(&k)).map(|m| m.tag);
                            row(this, i, ix, &t, cx)
                                .relative()
                                .when(selected, |d| d.bg(t.primary_soft))
                                .when_some(tag, |d, tag| {
                                    d.child(div().absolute().left_0().top(px(7.)).bottom(px(7.)).w(px(3.)).rounded(px(2.)).bg(mark_color(&t, tag)))
                                })
                                .on_click(cx.listener(move |this, ev: &gpui::ClickEvent, _, cx| {
                                    if list == ListId::Fs {
                                        this.on_fs_click(i, ev, cx);
                                    } else {
                                        this.open_item(list, i, cx);
                                    }
                                }))
                                .on_mouse_down(
                                    gpui::MouseButton::Right,
                                    cx.listener(move |this, ev: &gpui::MouseDownEvent, _, cx| {
                                        let items = this.item_menu(list, i);
                                        this.open_menu(ev.position, items, cx);
                                    }),
                                )
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(scroll)
            .flex_1()
            .min_h(px(0.))
            .into_any_element()
        };
        card(t)
            .flex_1()
            .min_h(px(0.))
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(self.sort_header(t, list, cols, cx))
            .child(body)
    }

    // ---------------------------------------------------------------- 选中与键盘

    /// 打开某条记录的详情并选中它。
    pub fn open_item(&mut self, list: ListId, i: usize, cx: &mut Context<Self>) {
        let Some(d) = self.item_detail(list, i) else { return };
        self.selected = Some((list, i));
        self.show(d, cx);
    }

    /// 处置动作改变了菜单内容（如封禁后变为“解除封禁”）时重建当前详情。
    pub fn refresh_open_detail(&mut self) {
        let Some((list, i)) = self.selected else { return };
        if let Some(d) = self.item_detail(list, i) {
            self.detail = Some(d);
        }
    }

    /// 上下方向键在当前列表中切换记录。
    pub fn step_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        let Some((list, rows)) = self.nav.clone() else { return };
        if rows.is_empty() {
            return;
        }
        let pos = match self.selected {
            Some((l, i)) if l == list => rows.iter().position(|&r| r == i),
            _ => None,
        };
        let next = match pos {
            Some(p) => (p as isize + delta).clamp(0, rows.len() as isize - 1) as usize,
            None if delta > 0 => 0,
            None => rows.len() - 1,
        };
        if let Some(h) = self.scrolls.get(&list) {
            h.scroll_to_item(next, ScrollStrategy::Top);
        }
        self.open_item(list, rows[next], cx);
    }

    pub fn focus_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let page = self.page;
        if let Some(e) = self.searches.get(&page) {
            e.read(cx).focus(window);
        }
    }

    // ---------------------------------------------------------------- 研判标记

    pub fn set_mark_tag(&mut self, tag: MarkTag, cx: &mut Context<Self>) {
        let Some((key, category, object)) = self.detail.as_ref().and_then(|d| d.mark.clone()) else { return };
        let entry = self.marks.entry(key.clone()).or_insert_with(|| Mark {
            key: key.clone(),
            category,
            object,
            tag: None,
            note: String::new(),
            time: chrono::Local::now(),
        });
        entry.tag = if entry.tag == Some(tag) { None } else { Some(tag) };
        entry.time = chrono::Local::now();
        self.prune_mark(&key);
        cx.notify();
    }

    pub fn set_mark_note(&mut self, note: String, cx: &mut Context<Self>) {
        let Some((key, category, object)) = self.detail.as_ref().and_then(|d| d.mark.clone()) else { return };
        let entry = self.marks.entry(key.clone()).or_insert_with(|| Mark {
            key: key.clone(),
            category,
            object,
            tag: None,
            note: String::new(),
            time: chrono::Local::now(),
        });
        entry.note = note;
        entry.time = chrono::Local::now();
        self.prune_mark(&key);
        cx.notify();
    }

    /// 既无标签也无备注的标记没有意义，直接删除。
    fn prune_mark(&mut self, key: &str) {
        if self.marks.get(key).is_some_and(|m| m.tag.is_none() && m.note.trim().is_empty()) {
            self.marks.remove(key);
        }
    }

    pub fn current_mark(&self) -> Option<&Mark> {
        let (key, _, _) = self.detail.as_ref()?.mark.as_ref()?;
        self.marks.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_matches_all_terms_case_insensitive() {
        assert!(matches_query("Powershell.exe C:\\Windows", "power WINDOWS"));
        assert!(!matches_query("cmd.exe", "power"));
        assert!(matches_query("anything", "   "));
    }

    #[test]
    fn refine_filters_and_sorts() {
        let items = vec![("b", 2), ("a", 3), ("c", 1)];
        let idx = refine((0..3).collect(), &items, "", Some((1, false)), |x| x.0.to_string(), |x, _| SortVal::N(x.1));
        assert_eq!(idx, vec![2, 0, 1]);
        let idx = refine((0..3).collect(), &items, "", Some((0, true)), |x| x.0.to_string(), |x, _| SortVal::s(x.0));
        assert_eq!(idx, vec![2, 0, 1]);
        let idx = refine((0..3).collect(), &items, "A", None, |x| x.0.to_string(), |_, _| SortVal::N(0));
        assert_eq!(idx, vec![1]);
    }

    #[test]
    fn sortval_orders_missing_time_first() {
        assert!(SortVal::t(None) < SortVal::t(Some(chrono::Local::now())));
    }
}
