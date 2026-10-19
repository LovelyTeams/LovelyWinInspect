//! 设置页：常规、导出、版本更新、数据与关于。

use gpui::{AnyElement, Context, FontWeight, IntoElement, ParentElement, PathPromptOptions, Styled, div, prelude::*, px};

use super::app::{AppView, open_in_explorer, resolve_theme};
use super::components::*;
use crate::report::default_root;
use crate::settings::{Settings, ThemeMode, config_dir};
use crate::theme::{Theme, theme};
use crate::update;

fn section(t: &Theme, icon_name: &str, title: &str) -> gpui::Div {
    card(t).p(px(18.)).flex().flex_col().child(
        div()
            .flex()
            .items_center()
            .gap_2()
            .pb(px(6.))
            .child(icon(icon_name, 17., t.primary))
            .child(div().text_size(px(15.)).font_weight(FontWeight::SEMIBOLD).child(title.to_string())),
    )
}

/// 左侧标题 + 说明，右侧控件。
fn row(t: &Theme, title: &str, desc: &str, control: impl IntoElement) -> gpui::Div {
    div()
        .flex()
        .items_center()
        .gap_4()
        .py(px(12.))
        .border_t_1()
        .border_color(t.divider)
        .child(
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .flex_col()
                .gap(px(2.))
                .child(div().text_size(px(14.)).child(title.to_string()))
                .when(!desc.is_empty(), |d| d.child(div().text_size(px(12.)).text_color(t.text_muted).child(desc.to_string()))),
        )
        .child(div().flex_none().flex().items_center().gap_2().child(control))
}

impl AppView {
    pub fn render_settings(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let s = self.settings.clone();

        // ============================================================ 常规
        let general = section(&t, "settings", "常规")
            .child(row(
                &t,
                "启动后自动排查",
                "打开程序后立即开始采集；关闭后需在总览页手动点击“快速排查”",
                switch(&t, "set-autoscan", s.auto_scan).on_click(cx.listener(|this, _, _, cx| {
                    this.settings.auto_scan = !this.settings.auto_scan;
                    this.save_settings();
                    cx.notify();
                })),
            ))
            .child(row(
                &t,
                "默认回溯天数",
                "日志与文件痕迹的默认时间范围，下次排查时生效",
                div().flex().gap_2().children([7u32, 30, 90, 180].map(|d| {
                    chip(&t, ("set-days", d as usize), format!("{d} 天"), s.lookback_days == d).on_click(cx.listener(move |this, _, _, cx| {
                        this.settings.lookback_days = d;
                        this.lookback = d;
                        this.save_settings();
                        cx.notify();
                    }))
                })),
            ))
            .child(row(
                &t,
                "界面主题",
                "“跟随系统”会随 Windows 的浅色/深色模式自动切换",
                div().flex().gap_2().children(ThemeMode::ALL.iter().enumerate().map(|(i, (mode, label))| {
                    let mode = *mode;
                    chip(&t, ("set-theme", i), *label, s.theme == mode).on_click(cx.listener(move |this, _, window, cx| {
                        this.settings.theme = mode;
                        this.save_settings();
                        cx.set_global(resolve_theme(mode, window));
                        window.refresh();
                        cx.notify();
                    }))
                })),
            ));

        // ============================================================ 导出
        let root = s.export_root().unwrap_or_else(default_root);
        let root_for_open = root.clone();
        let o = self.export.opts;
        let export_toggles: [(&'static str, &'static str, bool, fn(&mut AppView)); 5] = [
            ("ex-d-html", "HTML", o.html, |a| a.export.opts.html = !a.export.opts.html),
            ("ex-d-json", "JSON", o.json, |a| a.export.opts.json = !a.export.opts.json),
            ("ex-d-csv", "CSV", o.csv, |a| a.export.opts.csv = !a.export.opts.csv),
            ("ex-d-evtx", "原始日志", o.evtx, |a| a.export.opts.evtx = !a.export.opts.evtx),
            ("ex-d-evi", "文本证据", o.evidence, |a| a.export.opts.evidence = !a.export.opts.evidence),
        ];
        let export = section(&t, "download", "导出")
            .child(row(
                &t,
                "导出目录",
                &root.display().to_string(),
                div()
                    .flex()
                    .gap_2()
                    .child(small_button(&t, "set-dir-change", "folder", "更改…").on_click(cx.listener(|_, _, _, cx| {
                        let rx = cx.prompt_for_paths(PathPromptOptions {
                            files: false,
                            directories: true,
                            multiple: false,
                            prompt: Some("选择导出目录".into()),
                        });
                        cx.spawn(async move |this, cx| {
                            if let Ok(Ok(Some(paths))) = rx.await {
                                if let Some(p) = paths.into_iter().next() {
                                    let _ = this.update(cx, |this, cx| {
                                        this.settings.export_dir = Some(p.display().to_string());
                                        this.save_settings();
                                        cx.notify();
                                    });
                                }
                            }
                        })
                        .detach();
                    })))
                    .child(small_button(&t, "set-dir-open", "folder-open", "打开").on_click(move |_, _, _| {
                        let _ = std::fs::create_dir_all(&root_for_open);
                        open_in_explorer(&root_for_open);
                    }))
                    .when(s.export_dir.is_some(), |d| {
                        d.child(small_button(&t, "set-dir-reset", "refresh", "恢复默认").on_click(cx.listener(|this, _, _, cx| {
                            this.settings.export_dir = None;
                            this.save_settings();
                            cx.notify();
                        })))
                    }),
            ))
            .child(row(
                &t,
                "默认导出内容",
                "导出页默认勾选的内容",
                div().flex().gap_2().children(export_toggles.into_iter().map(|(id, label, on, f)| {
                    chip(&t, id, label, on).on_click(cx.listener(move |this, _, _, cx| {
                        f(this);
                        this.settings.export = this.export.opts;
                        this.save_settings();
                        cx.notify();
                    }))
                })),
            ));

        // ============================================================ 版本更新
        let repo = update::repo();
        let current = update::current_version();
        let status: AnyElement = if self.update.checking {
            div()
                .flex()
                .items_center()
                .gap_2()
                .text_size(px(13.))
                .text_color(t.primary)
                .child(spinner("upd-spin", 15., t.primary))
                .child("正在连接 GitHub 检查更新…")
                .into_any_element()
        } else if let Some(err) = &self.update.error {
            div()
                .flex()
                .items_center()
                .gap_2()
                .text_size(px(13.))
                .text_color(t.red)
                .child(icon("x-circle", 15., t.red))
                .child(err.clone())
                .into_any_element()
        } else if let Some(info) = self.update.latest.clone() {
            if update::is_newer(&info.version(), current) {
                self.release_card(&t, info, cx).into_any_element()
            } else {
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(13.))
                    .text_color(t.green)
                    .child(icon("check-circle", 15., t.green))
                    .child(format!("已是最新版本（GitHub 最新发布 {}）", info.tag))
                    .into_any_element()
            }
        } else {
            div()
                .text_size(px(13.))
                .text_color(t.text_muted)
                .child(match &s.last_update_check {
                    Some(at) => format!("上次检查：{at}"),
                    None => "尚未检查更新".to_string(),
                })
                .into_any_element()
        };
        let updates = section(&t, "arrow-up", "版本更新")
            .child(row(
                &t,
                &format!("当前版本 v{current}"),
                &match &repo {
                    Some(r) => format!("更新源：github.com/{r}/releases（直连 GitHub）"),
                    None => "未配置更新仓库：请在 Cargo.toml 的 repository 字段填写 GitHub 仓库地址".to_string(),
                },
                div()
                    .flex()
                    .gap_2()
                    .when_some(repo.clone(), |d, r| {
                        d.child(small_button(&t, "upd-page", "external-link", "发布页").on_click(move |_, _, cx| cx.open_url(&update::releases_page(&r))))
                    })
                    .when(repo.is_some() && !self.update.checking, |d| {
                        d.child(primary_button(&t, "upd-check", "refresh", "检查更新").h(px(30.)).px(px(12.)).text_size(px(13.)).on_click(cx.listener(|this, _, _, cx| this.check_update(true, cx))))
                    }),
            ))
            .child(div().py(px(10.)).border_t_1().border_color(t.divider).child(status))
            .child(row(
                &t,
                "启动时自动检查更新",
                "每次启动时在后台查询一次 GitHub Releases，有新版本时在标题栏提示",
                switch(&t, "set-autoupd", s.auto_check_update).on_click(cx.listener(|this, _, _, cx| {
                    this.settings.auto_check_update = !this.settings.auto_check_update;
                    this.save_settings();
                    cx.notify();
                })),
            ))
            .child(row(
                &t,
                "包含预发布版本",
                "开启后也会提示标记为 Pre-release 的测试版本",
                switch(&t, "set-pre", s.include_prerelease).on_click(cx.listener(|this, _, _, cx| {
                    this.settings.include_prerelease = !this.settings.include_prerelease;
                    this.save_settings();
                    cx.notify();
                })),
            ));

        // ============================================================ 数据与关于
        let cfg = config_dir();
        let cfg_open = cfg.clone();
        let data = section(&t, "hard-drive", "数据")
            .child(row(
                &t,
                "配置文件",
                &cfg.join("settings.json").display().to_string(),
                small_button(&t, "set-cfg-open", "folder-open", "打开").on_click(move |_, _, _| {
                    let _ = std::fs::create_dir_all(&cfg_open);
                    open_in_explorer(&cfg_open);
                }),
            ))
            .child(row(
                &t,
                "恢复默认设置",
                "将以上所有设置恢复为初始值",
                small_button(&t, "set-reset", "refresh", "恢复默认").on_click(cx.listener(|this, _, window, cx| {
                    this.settings = Settings::default();
                    this.lookback = this.settings.lookback_days;
                    this.export.opts = this.settings.export;
                    this.save_settings();
                    cx.set_global(resolve_theme(this.settings.theme, window));
                    window.refresh();
                    cx.notify();
                })),
            ));

        let link = |id: &'static str, label: &'static str, url: Option<String>| {
            let enabled = url.is_some();
            div()
                .id(id)
                .flex()
                .items_center()
                .gap_1()
                .text_size(px(13.))
                .text_color(if enabled { t.primary } else { t.text_faint })
                .when(enabled, |d| d.cursor_pointer())
                .child(label)
                .child(icon("external-link", 12., if enabled { t.primary } else { t.text_faint }))
                .on_click(move |_, _, cx| {
                    if let Some(u) = &url {
                        cx.open_url(u);
                    }
                })
        };
        let home = repo.as_ref().map(|r| format!("https://github.com/{r}"));
        let about = section(&t, "info", "关于").child(
            div()
                .flex()
                .items_center()
                .gap_4()
                .pt(px(10.))
                .border_t_1()
                .border_color(t.divider)
                .child(match crate::assets::logo_image() {
                    Some(img) => gpui::img(img).size(px(56.)).rounded(px(12.)).into_any_element(),
                    None => icon("shield", 40., t.primary).into_any_element(),
                })
                .child(
                    div()
                        .flex_1()
                        .flex()
                        .flex_col()
                        .gap(px(4.))
                        .child(div().text_size(px(16.)).font_weight(FontWeight::SEMIBOLD).child(format!("LovelyWinInspect v{current}")))
                        .child(div().text_size(px(12.5)).text_color(t.text_muted).child("Windows 安全基线核查与应急响应工作台 · Rust + GPUI"))
                        .child(div().text_size(px(12.5)).text_color(t.text_muted).child("开源许可证：GNU AGPL-3.0"))
                        .child(
                            div()
                                .flex()
                                .gap_4()
                                .pt(px(4.))
                                .child(link("about-home", "项目主页", home.clone()))
                                .child(link("about-issues", "问题反馈", home.as_ref().map(|h| format!("{h}/issues"))))
                                .child(link("about-license", "许可证", Some("https://www.gnu.org/licenses/agpl-3.0.html".into()))),
                        ),
                ),
        );

        div().id("page-settings").size_full().overflow_y_scroll().child(
            div()
                .w_full()
                .flex_none()
                .p(px(20.))
                .flex()
                .flex_col()
                .gap(px(16.))
                .child(page_title(&t, "设置", "常用偏好、导出选项与版本更新"))
                .child(general)
                .child(export)
                .child(updates)
                .child(data)
                .child(about),
        )
    }

    fn release_card(&self, t: &Theme, info: update::ReleaseInfo, cx: &mut Context<Self>) -> impl IntoElement {
        let url = info.url.clone();
        let version = info.version();
        let skipped = self.settings.skipped_version.as_deref() == Some(version.as_str());
        let notes: String = info.notes.chars().take(1500).collect();
        let exe_assets: Vec<String> = info
            .assets
            .iter()
            .map(|(n, size)| format!("{n}（{}）", fmt_size(*size)))
            .collect();
        div()
            .flex()
            .flex_col()
            .gap_2()
            .p(px(14.))
            .rounded(px(8.))
            .border_1()
            .border_color(t.primary)
            .bg(t.primary_soft)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(icon("arrow-up", 16., t.primary))
                    .child(div().text_size(px(14.)).font_weight(FontWeight::SEMIBOLD).text_color(t.primary).child(format!(
                        "发现新版本 {}{}",
                        info.tag,
                        if info.prerelease { "（预发布）" } else { "" }
                    )))
                    .child(div().text_size(px(12.)).text_color(t.text_muted).child(format!("发布于 {}", info.published)))
                    .when(skipped, |d| d.child(badge("已忽略", t.text_muted, t.gray_soft))),
            )
            .when(!info.name.is_empty() && info.name != info.tag, |d| d.child(div().text_size(px(13.)).font_weight(FontWeight::MEDIUM).child(info.name.clone())))
            .when(!notes.trim().is_empty(), |d| {
                d.child(
                    div()
                        .id("release-notes")
                        .max_h(px(180.))
                        .overflow_y_scroll()
                        .p(px(10.))
                        .rounded(px(6.))
                        .bg(t.card)
                        .text_size(px(12.5))
                        .text_color(t.text)
                        .children(notes.lines().map(|l| div().child(l.to_string()))),
                )
            })
            .when(!exe_assets.is_empty(), |d| d.child(div().text_size(px(12.)).text_color(t.text_muted).child(format!("附件：{}", exe_assets.join("、")))))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .pt(px(4.))
                    .child(primary_button(t, "upd-download", "download", "前往 GitHub 下载").h(px(32.)).px(px(14.)).text_size(px(13.)).on_click(move |_, _, cx| cx.open_url(&url)))
                    .when(!skipped, |d| {
                        d.child(small_button(t, "upd-skip", "eye-off", "忽略此版本").h(px(32.)).on_click(cx.listener(move |this, _, _, cx| {
                            this.settings.skipped_version = Some(version.clone());
                            this.save_settings();
                            cx.notify();
                        })))
                    }),
            )
            .child(div().text_size(px(11.5)).text_color(t.text_faint).child("下载后请先校验发布页提供的 SHA256，再替换旧版本程序。"))
    }
}
