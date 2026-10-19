//! 详情抽屉中按需加载的内容：文件预览（文本 / 十六进制 / PE 信息）与进程模块列表。

use std::sync::Arc;

use gpui::{AnyElement, Context, FontWeight, IntoElement, ParentElement, Styled, div, prelude::*, px};

use super::app::{AppView, DetailExtra};
use super::components::*;
use super::menu::file_items;
use crate::collect::fsbrowse::{self, ModuleInfo, Preview};
use crate::collect::util::is_system_dir;
use crate::model::SignState;
use crate::theme::{Theme, theme};

pub enum Loadable<T> {
    Loading,
    Ready(Arc<T>),
    Failed(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PreviewTab {
    Info,
    Text,
    Hex,
    Pe,
}

fn section(t: &Theme, title: &str) -> gpui::Div {
    div()
        .pt(px(14.))
        .pb(px(6.))
        .flex()
        .items_center()
        .gap_2()
        .text_size(px(13.))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(t.text)
        .child(title.to_string())
}

fn kv(t: &Theme, k: &str, v: impl Into<String>) -> gpui::Div {
    div()
        .flex()
        .gap_3()
        .py(px(3.))
        .text_size(px(12.5))
        .child(div().w(px(96.)).flex_none().text_color(t.text_faint).child(k.to_string()))
        .child(div().flex_1().min_w_0().text_color(t.text).child(v.into()))
}

impl AppView {
    /// 打开详情时触发：文件预览自动在后台加载。
    pub fn on_detail_opened(&mut self, cx: &mut Context<Self>) {
        self.preview_tab = None;
        if let Some(DetailExtra::Preview(path)) = self.detail.as_ref().map(|d| d.extra.clone()) {
            self.load_preview(path, cx);
        }
    }

    fn load_preview(&mut self, path: String, cx: &mut Context<Self>) {
        if self.previews.contains_key(&path) {
            return;
        }
        if self.previews.len() > 64 {
            self.previews.clear();
        }
        self.previews.insert(path.clone(), Loadable::Loading);
        cx.spawn(async move |this, cx| {
            let p = path.clone();
            let preview = cx.background_executor().spawn(async move { fsbrowse::load_preview(&p) }).await;
            let _ = this.update(cx, |this, cx| {
                this.previews.insert(path, Loadable::Ready(Arc::new(preview)));
                cx.notify();
            });
        })
        .detach();
    }

    fn load_modules(&mut self, pid: u32, cx: &mut Context<Self>) {
        self.modules.insert(pid, Loadable::Loading);
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = cx.background_executor().spawn(async move { fsbrowse::process_modules(pid) }).await;
            let _ = this.update(cx, |this, cx| {
                this.modules.insert(
                    pid,
                    match res {
                        Ok(v) => Loadable::Ready(Arc::new(v)),
                        Err(e) => Loadable::Failed(e),
                    },
                );
                cx.notify();
            });
        })
        .detach();
    }

    // ---------------------------------------------------------------- 模块

    pub fn render_modules(&mut self, pid: u32, cx: &mut Context<Self>) -> AnyElement {
        let t = theme(cx);
        let state = self.modules.get(&pid);
        let loading = matches!(state, Some(Loadable::Loading));
        let header = section(&t, "加载的模块")
            .child(div().flex_1())
            .child(if loading {
                spinner("mod-spin", 14., t.primary).into_any_element()
            } else {
                small_button(&t, "mod-load", if state.is_some() { "refresh" } else { "layers" }, if state.is_some() { "重新加载" } else { "加载模块列表" })
                    .on_click(cx.listener(move |this, _, _, cx| this.load_modules(pid, cx)))
                    .into_any_element()
            });
        let body: AnyElement = match state {
            None => div().text_size(px(12.)).text_color(t.text_muted).child("列出进程加载的 DLL 并校验签名，可发现 DLL 劫持与注入（需要几秒钟）。").into_any_element(),
            Some(Loadable::Loading) => div().text_size(px(12.)).text_color(t.text_muted).child("正在枚举模块并校验签名…").into_any_element(),
            Some(Loadable::Failed(e)) => div().text_size(px(12.)).text_color(t.red).child(e.clone()).into_any_element(),
            Some(Loadable::Ready(mods)) => {
                let mods = mods.clone();
                let unsigned = mods.iter().filter(|m| m.sign != SignState::Signed).count();
                let foreign = mods.iter().filter(|m| !is_system_dir(&m.path)).count();
                div()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .pb(px(6.))
                            .text_size(px(12.))
                            .text_color(if unsigned > 0 { t.orange } else { t.text_muted })
                            .child(format!("共 {} 个模块，未签名 {} 个，非系统目录 {} 个（右键可定位、计算哈希）", mods.len(), unsigned, foreign)),
                    )
                    .children(mods.iter().enumerate().map(|(i, m)| self.module_row(&t, i, m, cx)))
                    .into_any_element()
            }
        };
        div().flex().flex_col().child(header).child(body).into_any_element()
    }

    fn module_row(&self, t: &Theme, i: usize, m: &ModuleInfo, cx: &mut Context<Self>) -> AnyElement {
        let path = m.path.clone();
        let name = std::path::Path::new(&m.path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let dir = std::path::Path::new(&m.path).parent().map(|p| p.display().to_string()).unwrap_or_default();
        let hover = t.card_hover;
        div()
            .id(("module", i))
            .flex()
            .items_center()
            .gap_2()
            .py(px(4.))
            .px(px(4.))
            .rounded(px(5.))
            .hover(move |s| s.bg(hover))
            .child(sign_badge(t, m.sign))
            .child(div().w(px(150.)).flex_none().truncate().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).child(name))
            .child(div().flex_1().min_w_0().truncate().text_size(px(12.)).text_color(if is_system_dir(&m.path) { t.text_faint } else { t.orange }).child(dir))
            .tooltip(tooltip(format!("{}\n基址 0x{:X} · 大小 {}", m.path, m.base, fmt_size(m.size as u64))))
            .on_mouse_down(
                gpui::MouseButton::Right,
                cx.listener(move |this, ev: &gpui::MouseDownEvent, _, cx| {
                    let items = file_items(&path);
                    this.open_menu(ev.position, items, cx);
                }),
            )
            .into_any_element()
    }

    // ---------------------------------------------------------------- 文件预览

    pub fn render_preview(&mut self, path: String, cx: &mut Context<Self>) -> AnyElement {
        let t = theme(cx);
        let p = match self.previews.get(&path) {
            None | Some(Loadable::Loading) => {
                return div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .pt(px(14.))
                    .text_size(px(12.))
                    .text_color(t.text_muted)
                    .child(spinner("prev-spin", 13., t.primary))
                    .child("正在读取文件、计算哈希与签名…")
                    .into_any_element();
            }
            Some(Loadable::Failed(e)) => return div().pt(px(14.)).text_color(t.red).child(e.clone()).into_any_element(),
            Some(Loadable::Ready(p)) => p.clone(),
        };
        if let Some(e) = &p.error {
            return div().pt(px(14.)).text_size(px(12.5)).text_color(t.red).child(e.clone()).into_any_element();
        }
        let default_tab = if p.pe.is_some() {
            PreviewTab::Pe
        } else if p.text.is_some() {
            PreviewTab::Text
        } else {
            PreviewTab::Hex
        };
        let tab = self.preview_tab.unwrap_or(default_tab);
        let mut tabs = vec![(PreviewTab::Info, "概要")];
        if p.pe.is_some() {
            tabs.push((PreviewTab::Pe, "PE 信息"));
        }
        if p.text.is_some() {
            tabs.push((PreviewTab::Text, "文本"));
        }
        tabs.push((PreviewTab::Hex, "十六进制"));
        let tab_bar = div().flex().items_center().gap_2().pt(px(14.)).pb(px(8.)).children(tabs.into_iter().enumerate().map(|(i, (tb, label))| {
            chip(&t, ("prev-tab", i), label, tab == tb).on_click(cx.listener(move |this, _, _, cx| {
                this.preview_tab = Some(tb);
                cx.notify();
            }))
        }));
        let body = match tab {
            PreviewTab::Info => self.preview_info(&t, &p),
            PreviewTab::Pe => self.preview_pe(&t, &p),
            PreviewTab::Text => div()
                .p(px(10.))
                .rounded(px(6.))
                .bg(t.header_bg)
                .font_family("Consolas")
                .text_size(px(12.))
                .text_color(t.text)
                .child(p.text.as_deref().unwrap_or("").chars().take(20_000).collect::<String>())
                .into_any_element(),
            PreviewTab::Hex => div()
                .p(px(10.))
                .rounded(px(6.))
                .bg(t.header_bg)
                .font_family("Consolas")
                .text_size(px(11.5))
                .text_color(t.text)
                .children(p.head.chunks(16).enumerate().map(|(i, c)| div().child(fsbrowse::hex_line(i * 16, c))))
                .when(p.size as usize > p.head.len(), |d| d.child(div().pt(px(6.)).text_color(t.text_faint).child(format!("…仅显示前 {} 字节", p.head.len()))))
                .into_any_element(),
        };
        div().flex().flex_col().child(section(&t, "文件内容")).child(tab_bar).child(body).into_any_element()
    }

    fn preview_info(&self, t: &Theme, p: &Preview) -> AnyElement {
        div()
            .flex()
            .flex_col()
            .child(kv(t, "SHA256", if p.sha256.is_empty() { "（文件过大或无法读取）".to_string() } else { p.sha256.clone() }))
            .child(kv(t, "大小", format!("{}（{} 字节）", fmt_size(p.size), p.size)))
            .when(p.pe.is_some(), |d| d.child(kv(t, "数字签名", p.sign.label())))
            .child(kv(t, "备用数据流", if p.streams.is_empty() { "无".to_string() } else { p.streams.join("\n") }))
            .into_any_element()
    }

    fn preview_pe(&self, t: &Theme, p: &Preview) -> AnyElement {
        let Some(pe) = &p.pe else { return div().into_any_element() };
        let sensitive = pe.sensitive_imports();
        let packed = pe.high_entropy_sections();
        let kind = if pe.is_driver {
            "驱动程序"
        } else if pe.is_dll {
            "动态链接库 (DLL)"
        } else {
            "可执行程序"
        };
        let mut warn = Vec::new();
        if p.sign != SignState::Signed {
            warn.push(format!("签名：{}", p.sign.label()));
        }
        if !packed.is_empty() {
            warn.push(format!("高熵节 {}（可能加壳/加密）", packed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if pe.overlay > 4096 {
            warn.push(format!("文件末尾附加数据 {}", fmt_size(pe.overlay)));
        }
        // 微软等厂商的可复现构建把时间戳字段写成哈希值，已签名文件出现“未来时间”属正常
        let future = pe.timestamp.is_some_and(|ts| ts > chrono::Local::now() + chrono::Duration::days(1));
        if future && p.sign != SignState::Signed {
            warn.push("编译时间晚于当前时间（时间戳可能被伪造）".into());
        }
        let stamp = if future && p.sign == SignState::Signed {
            format!("{}（可复现构建的哈希值，非真实时间）", fmt_time(pe.timestamp))
        } else {
            fmt_time(pe.timestamp)
        };
        div()
            .flex()
            .flex_col()
            .when(!warn.is_empty(), |d| d.child(notice(t, "需关注", &warn)).child(div().h(px(8.))))
            .child(kv(t, "类型", format!("{kind} · {} {} · {}{}", if pe.is_64 { "PE32+" } else { "PE32" }, pe.machine, pe.subsystem, if pe.dotnet { " · .NET" } else { "" })))
            .child(kv(t, "编译时间", stamp))
            .child(kv(t, "入口点", format!("0x{:X}（基址 0x{:X}）", pe.entry_point, pe.image_base)))
            .child(kv(t, "签名数据", if pe.has_signature_blob { "内嵌签名".to_string() } else { "无内嵌签名（可能为编录签名）".to_string() }))
            .child(section(t, "节表"))
            .children(pe.sections.iter().map(|s| {
                div()
                    .flex()
                    .gap_3()
                    .py(px(2.))
                    .text_size(px(12.))
                    .font_family("Consolas")
                    .child(div().w(px(80.)).flex_none().child(s.name.clone()))
                    .child(div().w(px(150.)).flex_none().text_color(t.text_muted).child(format!("{} / {}", fmt_size(s.raw_size as u64), fmt_size(s.virtual_size as u64))))
                    .child(div().w(px(60.)).flex_none().text_color(t.text_muted).child(format!("{}{}", if s.executable { "X" } else { "-" }, if s.writable { "W" } else { "-" })))
                    .child(div().text_color(if s.entropy > 7.2 && s.raw_size >= 1024 { t.red } else { t.text_muted }).child(format!("熵 {:.2}", s.entropy)))
            }))
            .child(section(t, &format!("导入表（{} 个 DLL）", pe.imports.len())))
            .when(!sensitive.is_empty(), |d| {
                d.child(
                    div()
                        .flex()
                        .flex_wrap()
                        .gap_1()
                        .pb(px(6.))
                        .child(div().text_size(px(12.)).text_color(t.orange).child("敏感 API："))
                        .children(sensitive.iter().map(|f| badge(f.clone(), t.orange, t.orange_soft))),
                )
            })
            .children(pe.imports.iter().map(|(dll, funcs)| {
                let shown: Vec<&str> = funcs.iter().take(40).map(String::as_str).collect();
                div()
                    .py(px(3.))
                    .text_size(px(12.))
                    .child(div().font_weight(FontWeight::MEDIUM).child(format!("{dll}（{}）", funcs.len())))
                    .child(div().text_color(t.text_muted).child(format!("{}{}", shown.join(", "), if funcs.len() > 40 { " …" } else { "" })))
            }))
            .into_any_element()
    }
}
