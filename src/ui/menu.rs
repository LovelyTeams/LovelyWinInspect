//! 右键菜单、二次确认对话框与操作提示。
//!
//! 只读动作直接执行；会修改系统状态的动作先弹出确认框，执行结果写入操作日志。

use std::time::Duration;

use gpui::{Context, FontWeight, IntoElement, ParentElement, Pixels, Point, Styled, Window, div, prelude::*, px};

use super::app::AppView;
use super::components::*;
use crate::actions;
use crate::theme::theme;

/// 一条右键菜单动作。
#[derive(Clone, Debug)]
pub enum MenuAct {
    Copy(&'static str, String),
    OpenFolder(String),
    OpenRegedit(String),
    HashFile(String),
    KillProcess(u32, String),
    ClearHidden(String),
    /// report.persistence 中的下标
    DisableStartup(usize),
}

impl MenuAct {
    /// 需要二次确认的动作返回 (标题, 说明)。
    fn confirm_text(&self, this: &AppView) -> Option<(String, String)> {
        match self {
            MenuAct::KillProcess(pid, name) => Some((
                format!("结束进程 {name}？"),
                format!(
                    "将立即结束 PID {pid} 的进程。若它是业务程序或系统组件，可能导致服务中断或数据丢失。\n\
                     建议先记录其路径、命令行与哈希，确认为恶意后再结束。"
                ),
            )),
            MenuAct::ClearHidden(path) => Some((
                "恢复隐藏文件？".into(),
                format!("将去掉该文件的隐藏/系统属性，使其在资源管理器中可见：\n{path}\n\n这会修改文件属性，请确认已记录原始状态。"),
            )),
            MenuAct::DisableStartup(i) => this.report.persistence.get(*i).map(|it| {
                (
                    format!("禁用启动项 {}？", it.name),
                    format!(
                        "类型：{}\n命令：{}\n\n将阻止其开机自启（不会删除文件或配置）。若为正常业务程序，禁用后相关功能会失效。",
                        it.kind.label(),
                        if it.command.is_empty() { "-" } else { &it.command }
                    ),
                )
            }),
            _ => None,
        }
    }

    fn is_danger(&self) -> bool {
        matches!(self, MenuAct::KillProcess(..) | MenuAct::DisableStartup(_) | MenuAct::ClearHidden(_))
    }
}

#[derive(Clone)]
pub struct MenuItem {
    pub label: String,
    pub icon: &'static str,
    pub act: MenuAct,
}

pub fn mi(icon: &'static str, label: impl Into<String>, act: MenuAct) -> MenuItem {
    MenuItem { label: label.into(), icon, act }
}

pub struct ContextMenu {
    pub pos: Point<Pixels>,
    pub items: Vec<MenuItem>,
}

pub struct Confirm {
    pub title: String,
    pub body: String,
    pub act: MenuAct,
}

impl AppView {
    pub fn open_menu(&mut self, pos: Point<Pixels>, items: Vec<MenuItem>, cx: &mut Context<Self>) {
        if items.is_empty() {
            return;
        }
        self.menu = Some(ContextMenu { pos, items });
        cx.notify();
    }

    pub fn close_menu(&mut self, cx: &mut Context<Self>) {
        if self.menu.take().is_some() {
            cx.notify();
        }
    }

    fn toast(&mut self, msg: impl Into<String>, ok: bool, cx: &mut Context<Self>) {
        self.toast = Some((msg.into(), ok));
        // 几秒后自动消失
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(6)).await;
            let _ = this.update(cx, |this, cx| {
                this.toast = None;
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn run_act(&mut self, act: MenuAct, cx: &mut Context<Self>) {
        let res: Result<String, String> = match &act {
            MenuAct::Copy(what, text) => {
                if text.trim().is_empty() {
                    Err("内容为空".into())
                } else {
                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(text.clone()));
                    Ok(format!("已复制{what}"))
                }
            }
            MenuAct::OpenFolder(path) => {
                if path.trim().is_empty() {
                    Err("没有可定位的路径".into())
                } else {
                    actions::reveal_in_explorer(path);
                    Ok("已在资源管理器中打开".into())
                }
            }
            MenuAct::OpenRegedit(loc) => actions::open_regedit(loc),
            MenuAct::HashFile(path) => match actions::sha256(path) {
                Ok(h) => {
                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(h.clone()));
                    Ok(format!("SHA256 已复制：{h}"))
                }
                Err(e) => Err(e),
            },
            MenuAct::KillProcess(pid, name) => actions::kill_process(*pid, name),
            MenuAct::ClearHidden(path) => actions::clear_hidden(path),
            MenuAct::DisableStartup(i) => match self.report.persistence.get(*i) {
                Some(it) => actions::disable_startup(it),
                None => Err("启动项已失效，请重新排查".into()),
            },
        };
        match res {
            Ok(msg) => self.toast(msg, true, cx),
            Err(e) => self.toast(e, false, cx),
        }
    }

    fn on_menu_click(&mut self, act: MenuAct, cx: &mut Context<Self>) {
        self.menu = None;
        match act.confirm_text(self) {
            Some((title, body)) => {
                self.confirm = Some(Confirm { title, body, act });
                cx.notify();
            }
            None => self.run_act(act, cx),
        }
    }

    pub fn render_menu(&mut self, window: &Window, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let m = self.menu.as_ref()?;
        let t = theme(cx);
        // 贴近窗口右/下边缘时向内收，避免菜单被裁切
        let width = 252f32;
        let height = m.items.len() as f32 * 32. + 10.;
        let view = window.viewport_size();
        let x = f32::from(m.pos.x).min((f32::from(view.width) - width - 8.).max(8.));
        let y = f32::from(m.pos.y).min((f32::from(view.height) - height - 8.).max(8.));
        let items: Vec<gpui::AnyElement> = m
            .items
            .iter()
            .enumerate()
            .map(|(i, it)| {
                let act = it.act.clone();
                let danger = act.is_danger();
                let fg = if danger { t.red } else { t.text };
                let hover = if danger { t.red_soft } else { t.card_hover };
                div()
                    .id(("menu-item", i))
                    .h(px(30.))
                    .px(px(10.))
                    .flex()
                    .items_center()
                    .gap_2()
                    .rounded(px(5.))
                    .cursor_pointer()
                    .text_size(px(13.))
                    .text_color(fg)
                    .hover(move |s| s.bg(hover))
                    .child(icon(it.icon, 14., fg))
                    .child(div().flex_1().min_w_0().truncate().child(it.label.clone()))
                    .on_click(cx.listener(move |this, _, _, cx| this.on_menu_click(act.clone(), cx)))
                    .into_any_element()
            })
            .collect();
        Some(
            div()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .child(
                    div()
                        .id("menu-backdrop")
                        .absolute()
                        .top_0()
                        .left_0()
                        .size_full()
                        .on_click(cx.listener(|this, _, _, cx| this.close_menu(cx)))
                        .on_mouse_down(gpui::MouseButton::Right, cx.listener(|this, _, _, cx| this.close_menu(cx))),
                )
                .child(
                    div()
                        .occlude()
                        .absolute()
                        .left(px(x))
                        .top(px(y))
                        .w(px(width))
                        .p(px(5.))
                        .rounded(px(8.))
                        .border_1()
                        .border_color(t.border)
                        .bg(t.card)
                        .shadow_lg()
                        .flex()
                        .flex_col()
                        .gap(px(1.))
                        .children(items),
                )
                .into_any_element(),
        )
    }

    pub fn render_confirm(&mut self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let c = self.confirm.as_ref()?;
        let t = theme(cx);
        let (title, body, act) = (c.title.clone(), c.body.clone(), c.act.clone());
        Some(
            div()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .id("confirm-backdrop")
                        .absolute()
                        .top_0()
                        .left_0()
                        .size_full()
                        .bg(t.overlay)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.confirm = None;
                            cx.notify();
                        })),
                )
                .child(
                    div()
                        .occlude()
                        .w(px(460.))
                        .p(px(20.))
                        .rounded(px(12.))
                        .bg(t.card)
                        .border_1()
                        .border_color(t.border)
                        .shadow_lg()
                        .flex()
                        .flex_col()
                        .gap(px(12.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(icon("alert", 18., t.red))
                                .child(div().text_size(px(16.)).font_weight(FontWeight::SEMIBOLD).child(title)),
                        )
                        .children(body.lines().map(|l| {
                            div().text_size(px(13.)).text_color(t.text_muted).child(l.to_string())
                        }))
                        .child(
                            div()
                                .flex()
                                .justify_end()
                                .gap_2()
                                .pt(px(4.))
                                .child(small_button(&t, "confirm-no", "x", "取消").h(px(32.)).px(px(14.)).on_click(cx.listener(|this, _, _, cx| {
                                    this.confirm = None;
                                    cx.notify();
                                })))
                                .child(
                                    div()
                                        .id("confirm-yes")
                                        .h(px(32.))
                                        .px(px(16.))
                                        .flex()
                                        .items_center()
                                        .gap_1()
                                        .rounded(px(6.))
                                        .bg(t.red)
                                        .text_color(t.on_primary)
                                        .text_size(px(13.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .cursor_pointer()
                                        .child("确认执行")
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.confirm = None;
                                            this.run_act(act.clone(), cx);
                                        })),
                                ),
                        ),
                )
                .into_any_element(),
        )
    }

    pub fn render_toast(&mut self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let (msg, ok) = self.toast.clone()?;
        let t = theme(cx);
        let (fg, bg) = if ok { (t.green, t.green_soft) } else { (t.red, t.red_soft) };
        Some(
            div()
                .absolute()
                .bottom(px(20.))
                .right(px(20.))
                .max_w(px(520.))
                .px(px(14.))
                .py(px(10.))
                .rounded(px(8.))
                .bg(bg)
                .border_1()
                .border_color(fg)
                .shadow_lg()
                .flex()
                .items_start()
                .gap_2()
                .child(icon(if ok { "check-circle" } else { "x-circle" }, 16., fg))
                .child(div().flex_1().min_w_0().text_size(px(13.)).text_color(fg).child(msg))
                .into_any_element(),
        )
    }
}

// ---------------------------------------------------------------- 各面板菜单

use crate::model::{ConnInfo, FileArtifact, PersistItem, ProcessInfo, RegItem};

fn copy_item(icon: &'static str, what: &'static str, text: &str) -> Option<MenuItem> {
    (!text.trim().is_empty()).then(|| mi(icon, format!("复制{what}"), MenuAct::Copy(what, text.to_string())))
}

fn file_items(path: &str) -> Vec<MenuItem> {
    let mut v = Vec::new();
    if path.trim().is_empty() {
        return v;
    }
    v.push(mi("folder-open", "打开文件所在位置", MenuAct::OpenFolder(path.into())));
    if let Some(c) = copy_item("copy", "路径", path) {
        v.push(c);
    }
    if std::path::Path::new(path).is_file() {
        v.push(mi("key", "计算并复制 SHA256", MenuAct::HashFile(path.into())));
    }
    v
}

pub fn process_menu(p: &ProcessInfo) -> Vec<MenuItem> {
    let mut v = file_items(&p.path);
    if let Some(c) = copy_item("terminal", "命令行", &p.cmdline) {
        v.push(c);
    }
    if p.pid > 4 {
        v.push(mi("x-circle", format!("结束进程 (PID {})", p.pid), MenuAct::KillProcess(p.pid, p.name.clone())));
    }
    v
}

pub fn conn_menu(c: &ConnInfo) -> Vec<MenuItem> {
    let mut v = Vec::new();
    if !c.remote_addr.is_empty() {
        v.push(mi("globe", "复制远程地址", MenuAct::Copy("远程地址", format!("{}:{}", c.remote_addr, c.remote_port))));
    }
    if !c.domain.trim().is_empty() {
        v.push(mi("copy", "复制域名", MenuAct::Copy("域名", c.domain.clone())));
    }
    v.extend(file_items(&c.path));
    if c.pid > 4 && !c.process.is_empty() {
        v.push(mi("x-circle", format!("结束进程 {} (PID {})", c.process, c.pid), MenuAct::KillProcess(c.pid, c.process.clone())));
    }
    v
}

pub fn persist_menu(index: usize, it: &PersistItem) -> Vec<MenuItem> {
    let mut v = Vec::new();
    if it.location.to_ascii_uppercase().starts_with("HK") {
        v.push(mi("database", "在注册表编辑器中定位", MenuAct::OpenRegedit(it.location.clone())));
    }
    v.extend(file_items(&it.image));
    if let Some(c) = copy_item("terminal", "命令", &it.command) {
        v.push(c);
    }
    if crate::actions::can_disable(it.kind) && it.enabled {
        v.push(mi("eye-off", "禁用该启动项", MenuAct::DisableStartup(index)));
    }
    v
}

pub fn file_menu(f: &FileArtifact) -> Vec<MenuItem> {
    let mut v = file_items(&f.path);
    if std::path::Path::new(&f.path).is_file() {
        v.push(mi("eye-off", "恢复隐藏/系统属性", MenuAct::ClearHidden(f.path.clone())));
    }
    if let Some(c) = copy_item("copy", "SHA256", &f.sha256) {
        v.push(c);
    }
    v
}

pub fn reg_menu(r: &RegItem) -> Vec<MenuItem> {
    let mut v = Vec::new();
    if r.location.to_ascii_uppercase().starts_with("HK") {
        v.push(mi("database", "在注册表编辑器中定位", MenuAct::OpenRegedit(r.location.clone())));
    }
    if let Some(c) = copy_item("copy", "名称", &r.name) {
        v.push(c);
    }
    if let Some(c) = copy_item("copy", "值", &r.value) {
        v.push(c);
    }
    if let Some(c) = copy_item("copy", "注册表位置", &r.location) {
        v.push(c);
    }
    // 值本身是路径时提供定位
    let maybe_path = if r.value.contains(':') { r.value.clone() } else { String::new() };
    if std::path::Path::new(&maybe_path).is_file() {
        v.push(mi("folder-open", "打开文件所在位置", MenuAct::OpenFolder(maybe_path)));
    }
    v
}
