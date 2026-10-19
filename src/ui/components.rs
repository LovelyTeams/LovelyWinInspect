//! 通用 UI 组件：卡片、徽标、表格行、筛选标签、按钮、提示框等。

use std::time::Duration;

use gpui::{
    Animation, AnimationExt, AnyElement, AnyView, App, Div, ElementId, FontWeight, Hsla, IntoElement,
    ParentElement, Render, SharedString, Stateful, Styled, Svg, Transformation, Window, div,
    percentage, prelude::*, px, svg,
};

use crate::assets::icon_path;
use crate::model::{CheckStatus, Severity, SignState};
use crate::theme::Theme;

pub fn icon(name: &str, size: f32, color: Hsla) -> Svg {
    svg().path(icon_path(name)).size(px(size)).flex_none().text_color(color)
}

pub fn spinner(id: impl Into<ElementId>, size: f32, color: Hsla) -> impl IntoElement {
    icon("loader", size, color).with_animation(
        id,
        Animation::new(Duration::from_millis(900)).repeat(),
        |s, delta| s.with_transformation(Transformation::rotate(percentage(delta))),
    )
}

pub fn card(t: &Theme) -> Div {
    div()
        .bg(t.card)
        .border_1()
        .border_color(t.border)
        .rounded(px(10.))
}

pub fn badge(text: impl Into<SharedString>, fg: Hsla, bg: Hsla) -> Div {
    div()
        .flex_none()
        .h(px(22.))
        .px(px(9.))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(11.))
        .bg(bg)
        .text_color(fg)
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .child(text.into())
}

pub fn sev_badge(t: &Theme, s: Severity) -> Div {
    let (fg, bg) = t.severity(s);
    badge(s.label(), fg, bg).min_w(px(40.))
}

pub fn status_badge(t: &Theme, s: CheckStatus) -> Div {
    let (fg, bg) = t.status(s);
    badge(s.label(), fg, bg)
}

pub fn sign_badge(t: &Theme, s: SignState) -> Div {
    let (fg, bg) = match s {
        SignState::Signed => (t.green, t.green_soft),
        SignState::Unsigned => (t.red, t.red_soft),
        SignState::Missing => (t.orange, t.orange_soft),
        SignState::NotChecked => (t.text_faint, t.gray_soft),
    };
    badge(s.label(), fg, bg)
}

pub fn dot(color: Hsla, size: f32) -> Div {
    div().flex_none().size(px(size)).rounded_full().bg(color)
}

pub fn section_header(t: &Theme, title: &str) -> Div {
    div()
        .flex()
        .items_center()
        .justify_between()
        .child(
            div()
                .text_size(px(16.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.text)
                .child(title.to_string()),
        )
}

pub fn page_title(t: &Theme, title: &str, subtitle: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(2.))
        .child(
            div()
                .text_size(px(20.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(t.text)
                .child(title.to_string()),
        )
        .child(div().text_size(px(13.)).text_color(t.text_muted).child(subtitle.to_string()))
}

pub fn empty_state(t: &Theme, icon_name: &str, text: impl Into<SharedString>) -> Div {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_3()
        .py(px(48.))
        .child(icon(icon_name, 36., t.text_faint))
        .child(div().text_size(px(13.)).text_color(t.text_muted).child(text.into()))
}

// ---------------------------------------------------------------- 表格

#[derive(Clone, Copy)]
pub struct Col {
    pub title: &'static str,
    /// None = 自适应剩余宽度
    pub width: Option<f32>,
}

pub const fn col(title: &'static str, width: f32) -> Col {
    Col { title, width: Some(width) }
}

pub const fn flex_col(title: &'static str) -> Col {
    Col { title, width: None }
}

fn sized(c: &Col, d: Div) -> Div {
    match c.width {
        Some(w) => d.w(px(w)).flex_none(),
        None => d.flex_1().min_w(px(80.)),
    }
}

pub const ROW_H: f32 = 40.;

pub fn table_header(t: &Theme, cols: &[Col]) -> Div {
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
        .children(cols.iter().map(|c| sized(c, div()).truncate().child(c.title)))
}

pub fn table_row(t: &Theme, id: impl Into<ElementId>, cols: &[Col], cells: Vec<AnyElement>) -> Stateful<Div> {
    let hover = t.card_hover;
    div()
        .id(id)
        .w_full()
        .flex_none()
        .flex()
        .items_center()
        .h(px(ROW_H))
        .px(px(12.))
        .gap(px(12.))
        .border_b_1()
        .border_color(t.divider)
        .text_size(px(13.))
        .text_color(t.text)
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .children(
            cols.iter()
                .zip(cells)
                .map(|(c, cell)| sized(c, div()).overflow_hidden().flex().items_center().child(cell)),
        )
}

/// 单行展示：去掉换行/制表符并限制长度，避免多行文本撑破表格。
pub fn one_line(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(400)
        .collect();
    if s.chars().count() > 400 {
        out.push('…');
    }
    out
}

pub fn text_cell(s: impl Into<SharedString>) -> AnyElement {
    let s: SharedString = s.into();
    div().w_full().truncate().child(one_line(&s)).into_any_element()
}

pub fn muted_cell(t: &Theme, s: impl Into<SharedString>) -> AnyElement {
    let s: SharedString = s.into();
    div()
        .w_full()
        .truncate()
        .text_color(t.text_muted)
        .text_size(px(12.5))
        .child(one_line(&s))
        .into_any_element()
}

pub fn mono_cell(t: &Theme, s: impl Into<SharedString>) -> AnyElement {
    let s: SharedString = s.into();
    div()
        .w_full()
        .truncate()
        .text_color(t.text_muted)
        .text_size(px(12.))
        .font_family("Consolas")
        .child(one_line(&s))
        .into_any_element()
}

// ---------------------------------------------------------------- 按钮与标签

pub fn chip(t: &Theme, id: impl Into<ElementId>, label: impl Into<SharedString>, active: bool) -> Stateful<Div> {
    let (fg, bg, border) = if active {
        (t.primary, t.primary_soft, t.primary)
    } else {
        (t.text_muted, t.card, t.border)
    };
    let hover = t.card_hover;
    div()
        .id(id)
        .flex_none()
        .h(px(28.))
        .px(px(12.))
        .flex()
        .items_center()
        .gap_1()
        .rounded(px(14.))
        .border_1()
        .border_color(border)
        .bg(bg)
        .text_color(fg)
        .text_size(px(12.5))
        .cursor_pointer()
        .when(!active, move |d| d.hover(move |s| s.bg(hover)))
        .child(label.into())
}

pub fn primary_button(t: &Theme, id: impl Into<ElementId>, icon_name: &str, label: impl Into<SharedString>) -> Stateful<Div> {
    let hover = t.primary.opacity(0.88);
    div()
        .id(id)
        .flex_none()
        .h(px(38.))
        .px(px(18.))
        .flex()
        .items_center()
        .gap_2()
        .rounded(px(8.))
        .bg(t.primary)
        .text_color(t.on_primary)
        .text_size(px(14.))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(icon(icon_name, 16., t.on_primary))
        .child(label.into())
}

pub fn outline_button(t: &Theme, id: impl Into<ElementId>, icon_name: &str, label: impl Into<SharedString>) -> Stateful<Div> {
    let hover = t.primary_soft;
    div()
        .id(id)
        .flex_none()
        .h(px(38.))
        .px(px(16.))
        .flex()
        .items_center()
        .gap_2()
        .rounded(px(8.))
        .border_1()
        .border_color(t.primary)
        .bg(t.card)
        .text_color(t.primary)
        .text_size(px(14.))
        .font_weight(FontWeight::MEDIUM)
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(icon(icon_name, 16., t.primary))
        .child(label.into())
}

pub fn small_button(t: &Theme, id: impl Into<ElementId>, icon_name: &str, label: impl Into<SharedString>) -> Stateful<Div> {
    let hover = t.card_hover;
    div()
        .id(id)
        .flex_none()
        .h(px(28.))
        .px(px(10.))
        .flex()
        .items_center()
        .gap_1()
        .rounded(px(6.))
        .border_1()
        .border_color(t.border)
        .bg(t.card)
        .text_color(t.text)
        .text_size(px(12.5))
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(icon(icon_name, 14., t.text_muted))
        .child(label.into())
}

pub fn checkbox(t: &Theme, id: impl Into<ElementId>, checked: bool, label: impl Into<SharedString>, desc: impl Into<SharedString>) -> Stateful<Div> {
    let hover = t.card_hover;
    div()
        .id(id)
        .flex()
        .items_start()
        .gap_3()
        .p_3()
        .rounded(px(8.))
        .border_1()
        .border_color(if checked { t.primary } else { t.border })
        .bg(if checked { t.primary_soft } else { t.card })
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(
            div()
                .mt(px(2.))
                .size(px(16.))
                .flex_none()
                .rounded(px(4.))
                .border_1()
                .border_color(if checked { t.primary } else { t.text_faint })
                .bg(if checked { t.primary } else { t.card })
                .flex()
                .items_center()
                .justify_center()
                .when(checked, |d| d.child(icon("check", 12., t.on_primary))),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap_1()
                .child(div().text_size(px(14.)).font_weight(FontWeight::MEDIUM).text_color(t.text).child(label.into()))
                .child(div().text_size(px(12.)).text_color(t.text_muted).child(desc.into())),
        )
}

pub fn kv_row(t: &Theme, icon_name: &str, key: &str, value: impl IntoElement) -> Div {
    div()
        .flex()
        .items_start()
        .gap_3()
        .py(px(7.))
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .w(px(96.))
                .flex_none()
                .child(icon(icon_name, 15., t.text_faint))
                .child(div().text_size(px(13.)).text_color(t.text_muted).child(key.to_string())),
        )
        .child(div().flex_1().min_w_0().overflow_hidden().text_size(px(13.)).text_color(t.text).child(value))
}

pub fn progress_bar(t: &Theme, ratio: f32, color: Hsla) -> Div {
    let ratio = ratio.clamp(0.0, 1.0);
    div()
        .h(px(6.))
        .w_full()
        .rounded(px(3.))
        .bg(t.gray_soft)
        .child(div().h_full().rounded(px(3.)).bg(color).w(gpui::relative(ratio)))
}

/// 橙色提示条（如审计配置不完整）。
pub fn notice(t: &Theme, title: &str, items: &[String]) -> Div {
    div()
        .flex()
        .items_start()
        .gap_2()
        .px(px(14.))
        .py(px(10.))
        .rounded(px(8.))
        .bg(t.orange_soft)
        .text_color(t.orange)
        .text_size(px(12.5))
        .child(icon("alert", 15., t.orange).mt(px(1.)))
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(2.))
                .child(div().font_weight(FontWeight::MEDIUM).child(title.to_string()))
                .child(div().child(items.join("；"))),
        )
}

// ---------------------------------------------------------------- Tooltip

pub struct TooltipView(pub SharedString);

impl Render for TooltipView {
    fn render(&mut self, _window: &mut Window, cx: &mut gpui::Context<Self>) -> impl IntoElement {
        let t = crate::theme::theme(cx);
        div()
            .font_family("Microsoft YaHei UI")
            .px(px(10.))
            .py(px(5.))
            .rounded(px(6.))
            .bg(if t.dark { t.header_bg } else { t.text })
            .text_color(if t.dark { t.text } else { t.card })
            .text_size(px(12.))
            .child(self.0.clone())
    }
}

pub fn tooltip(text: impl Into<SharedString>) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    let text: SharedString = text.into();
    move |_window, cx| cx.new(|_| TooltipView(text.clone())).into()
}

// ---------------------------------------------------------------- 格式化

pub fn fmt_time(t: Option<crate::model::Time>) -> String {
    t.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_else(|| "-".into())
}

pub fn fmt_size(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} GB", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

/// 开关控件。
pub fn switch(t: &Theme, id: impl Into<ElementId>, on: bool) -> Stateful<Div> {
    div()
        .id(id)
        .flex_none()
        .w(px(38.))
        .h(px(22.))
        .p(px(3.))
        .rounded(px(11.))
        .cursor_pointer()
        .bg(if on { t.primary } else { t.border })
        .flex()
        .items_center()
        .when(on, |d| d.justify_end())
        .child(div().size(px(16.)).rounded_full().bg(t.card))
}
