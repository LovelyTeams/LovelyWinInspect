//! 总览页：主机头部、统计卡片、调查发现、主机信息、证据采集时间线。

use gpui::{AnyElement, Context, FontWeight, Hsla, IntoElement, ParentElement, Styled, div, prelude::*, px};

use super::app::{AppView, Detail, Page};
use super::components::*;
use crate::model::*;
use crate::theme::{Theme, theme};

pub fn category_icon(c: Category) -> &'static str {
    match c {
        Category::Process => "cpu",
        Category::Network => "globe",
        Category::Persistence => "rocket",
        Category::Account => "user",
        Category::EventLog => "list",
        Category::File => "file-text",
        Category::Baseline => "shield-check",
    }
}

pub fn finding_detail(f: &Finding) -> Detail {
    Detail::new(f.title.clone(), format!("{} · {}", f.category.label(), f.object), Some(f.severity))
        .field("对象", f.object.clone())
        .field("时间", fmt_time(f.time))
        .field("路径 / 目标", f.target.clone())
        .field("详情", f.detail.clone())
        .field(
            "ATT&CK",
            match f.tactic {
                Some(t) => format!("{} ({}) {}", t.label(), t.attack_id(), f.technique),
                None => f.technique.clone(),
            },
        )
        .field("处置建议", f.advice.clone())
}

pub const FINDING_COLS: &[Col] = &[
    col("时间", 150.),
    col("类型", 76.),
    col("对象", 170.),
    flex_col("详情"),
    col("风险等级", 70.),
    col("路径 / 目标", 230.),
];

pub fn finding_cells(t: &Theme, f: &Finding) -> Vec<AnyElement> {
    vec![
        muted_cell(t, fmt_time(f.time)),
        div()
            .flex()
            .items_center()
            .gap_1()
            .child(icon(category_icon(f.category), 15., t.primary))
            .child(div().text_size(px(12.5)).text_color(t.text_muted).child(f.category.label()))
            .into_any_element(),
        text_cell(f.object.clone()),
        text_cell(f.title.clone()),
        sev_badge(t, f.severity).into_any_element(),
        muted_cell(t, f.target.clone()),
    ]
}

impl AppView {
    pub fn render_overview(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let h = &r.host;

        // ---------------- 头部
        let os_line = if h.os_name.is_empty() {
            "正在读取系统信息…".to_string()
        } else {
            format!("{}    {} ({})    {}", h.os_name, h.os_version, h.build, h.arch)
        };
        let net_line = format!(
            "{}   |   {}   |   运行时间 {}",
            if h.ip.is_empty() { "-" } else { &h.ip },
            if h.domain.is_empty() { "-" } else { &h.domain },
            if h.uptime_secs > 0 { fmt_uptime(h.uptime_secs) } else { "-".into() }
        );
        let lookback_chips = [7u32, 30, 90].map(|d| {
            chip(&t, ("lookback", d as usize), format!("{d} 天"), self.lookback == d)
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.lookback = d;
                    cx.notify();
                }))
        });
        let scan_btn = if self.scanning {
            div()
                .flex_none()
                .h(px(38.))
                .px(px(18.))
                .flex()
                .items_center()
                .gap_2()
                .rounded(px(8.))
                .bg(t.primary.opacity(0.75))
                .text_color(t.on_primary)
                .text_size(px(14.))
                .child(spinner("scan-spin", 16., t.on_primary))
                .child("排查中…")
                .into_any_element()
        } else {
            primary_button(&t, "scan", "search", if self.has_report { "重新排查" } else { "快速排查" })
                .on_click(cx.listener(|this, _, _, cx| this.start_scan(cx)))
                .into_any_element()
        };
        let header = card(&t)
            .p(px(20.))
            .flex()
            .items_center()
            .gap(px(20.))
            .child(
                div()
                    .size(px(76.))
                    .flex_none()
                    .rounded(px(14.))
                    .bg(t.primary_soft)
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(icon("monitor", 42., t.primary)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .text_size(px(26.))
                                    .font_weight(FontWeight::BOLD)
                                    .child(if h.hostname.is_empty() { "本机".to_string() } else { h.hostname.clone() }),
                            )
                            .child(if self.is_admin {
                                badge("管理员", t.green, t.green_soft)
                            } else {
                                badge("非管理员", t.orange, t.orange_soft)
                            }),
                    )
                    .child(div().text_size(px(14.)).text_color(t.text_muted).child(os_line))
                    .child(div().text_size(px(13.)).text_color(t.text_faint).child(net_line)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().text_size(px(12.)).text_color(t.text_faint).child("回溯"))
                    .children(lookback_chips),
            )
            .child(scan_btn)
            .child(
                outline_button(&t, "goto-export", "file-text", "导出报告")
                    .on_click(cx.listener(|this, _, _, cx| this.go(Page::Export, cx))),
            );

        // ---------------- 统计卡片
        let crit = r.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = r.findings.iter().filter(|f| f.severity == Severity::High).count();
        let med = r.findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let fails = r.baseline.iter().filter(|b| b.status == CheckStatus::Fail).count();
        let sus_persist = r.persistence.iter().filter(|p| p.risk >= Severity::Medium).count();
        let ext = r.connections.iter().filter(|c| c.external && c.state != "LISTEN").count();
        let ext_sus = r.connections.iter().filter(|c| c.external && c.risk >= Severity::Medium).count();
        let score = r.baseline_score();
        let stats = div()
            .flex()
            .gap(px(16.))
            .child(self.stat_card(&t, 0, "activity", t.red, t.red_soft, "高危发现", (crit + high).to_string(), format!("严重 {crit} · 高 {high} · 中 {med}"), "需优先处置的入侵线索", Page::Timeline, cx))
            .child(self.stat_card(&t, 1, "shield-check", t.green, t.green_soft, "基线合规率", score.map(|s| format!("{s}%")).unwrap_or("-".into()), format!("不符合 {fails} 项"), "账户 / 审计 / 安全选项 / 网络 / 防护", Page::Baseline, cx))
            .child(self.stat_card(&t, 2, "rocket", t.orange, t.orange_soft, "可疑持久化", sus_persist.to_string(), format!("共 {} 个启动项", r.persistence.len()), "自启动、服务、计划任务等", Page::Persistence, cx))
            .child(self.stat_card(&t, 3, "globe", t.blue, t.blue_soft, "外联连接", ext.to_string(), format!("可疑 {ext_sus} 条"), "与公网地址通信的连接", Page::Network, cx));

        // ---------------- 调查发现
        let top: Vec<(usize, &Finding)> = r.findings.iter().enumerate().take(9).collect();
        let rows: Vec<AnyElement> = top
            .iter()
            .map(|(i, f)| {
                let i = *i;
                table_row(&t, ("ov-finding", i), FINDING_COLS, finding_cells(&t, f))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let d = finding_detail(&this.report.findings[i]);
                        this.show(d, cx);
                    }))
                    .into_any_element()
            })
            .collect();
        let findings = card(&t)
            .flex_1()
            .min_w_0()
            .flex()
            .flex_col()
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px(px(18.))
                    .py(px(14.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().text_size(px(16.)).font_weight(FontWeight::SEMIBOLD).child("调查发现"))
                            .child(badge(r.findings.len().to_string(), t.text_muted, t.gray_soft)),
                    )
                    .child(
                        div()
                            .id("all-findings")
                            .flex()
                            .items_center()
                            .gap_1()
                            .text_size(px(13.))
                            .text_color(t.primary)
                            .cursor_pointer()
                            .child("查看全部")
                            .child(icon("chevron-right", 14., t.primary))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.tl_show_findings = true;
                                this.go(Page::Timeline, cx);
                            })),
                    ),
            )
            .child(table_header(&t, FINDING_COLS))
            .children(rows)
            .when(r.findings.is_empty(), |d| {
                d.child(empty_state(
                    &t,
                    if self.scanning { "loader" } else { "check-circle" },
                    if self.scanning { "正在采集与研判，请稍候…" } else { "未发现可疑线索" },
                ))
            });

        // ---------------- 主机信息
        let av_ok = h.av_realtime.unwrap_or(false);
        let host_info = card(&t)
            .w(px(340.))
            .flex_none()
            .p(px(18.))
            .flex()
            .flex_col()
            .child(div().text_size(px(16.)).font_weight(FontWeight::SEMIBOLD).mb_2().child("主机信息"))
            .child(kv_row(&t, "monitor", "主机名", or_dash(&h.hostname)))
            .child(kv_row(&t, "hard-drive", "操作系统", if h.os_name.is_empty() { "-".into() } else { format!("{} {} ({})", h.os_name, h.os_version, h.build) }))
            .child(kv_row(&t, "cpu", "系统类型", or_dash(&h.arch)))
            .child(kv_row(&t, "globe", "IP 地址", or_dash(&h.ip)))
            .child(kv_row(&t, "network", "MAC 地址", or_dash(&h.mac)))
            .child(kv_row(&t, "share", if h.is_domain { "所属域" } else { "所属工作组" }, or_dash(&h.domain)))
            .child(kv_row(
                &t,
                "user",
                "当前用户",
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().min_w_0().truncate().child(or_dash(h.current_user.rsplit('\\').next().unwrap_or(""))))
                    .when(self.is_admin, |d| d.child(badge("管理员", t.primary, t.primary_soft))),
            ))
            .child(kv_row(&t, "calendar", "启动时间", fmt_time(h.boot_time)))
            .child(kv_row(&t, "clock", "运行时间", if h.uptime_secs > 0 { fmt_uptime(h.uptime_secs) } else { "-".into() }))
            .child(kv_row(
                &t,
                "shield",
                "安全软件",
                div()
                    .flex()
                    .items_start()
                    .gap_2()
                    .child(icon(if av_ok { "check-circle" } else { "x-circle" }, 15., if av_ok { t.green } else { t.red }))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .child(or_dash(&h.av_product))
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(if av_ok { t.text_muted } else { t.red })
                                    .child(if h.av_product.is_empty() { "" } else if av_ok { "(实时保护已启用)" } else { "(实时保护未启用)" }),
                            ),
                    ),
            ))
            .child(kv_row(&t, "calendar", "系统安装", fmt_time(h.install_date)))
            .child(kv_row(&t, "clock", "最后采集", fmt_time(r.finished)));

        div()
            .id("page-overview")
            .size_full()
            .overflow_y_scroll()
            .child(
                div()
                    .w_full()
                    .flex_none()
                    .p(px(20.))
                    .flex()
                    .flex_col()
                    .gap(px(16.))
            .child(header)
            .child(stats)
            .child(div().flex().gap(px(16.)).items_start().child(findings).child(host_info))
            .child(self.stage_timeline(&t)))
    }

    #[allow(clippy::too_many_arguments)]
    fn stat_card(
        &self,
        t: &Theme,
        ix: usize,
        icon_name: &str,
        fg: Hsla,
        bg: Hsla,
        title: &str,
        value: String,
        sub: String,
        desc: &str,
        page: Page,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let hover = t.card_hover;
        card(t)
            .id(("stat", ix))
            .flex_1()
            .min_w_0()
            .p(px(18.))
            .flex()
            .gap(px(16.))
            .cursor_pointer()
            .hover(move |s| s.bg(hover))
            .on_click(cx.listener(move |this, _, _, cx| this.go(page, cx)))
            .child(
                div()
                    .size(px(54.))
                    .flex_none()
                    .rounded(px(12.))
                    .bg(bg)
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(icon(icon_name, 26., fg)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .flex_col()
                    .gap(px(4.))
                    .child(div().text_size(px(14.)).font_weight(FontWeight::MEDIUM).child(title.to_string()))
                    .child(
                        div()
                            .flex()
                            .items_end()
                            .gap_2()
                            .child(div().text_size(px(28.)).font_weight(FontWeight::BOLD).line_height(px(34.)).child(value))
                            .child(div().pb(px(5.)).text_size(px(12.)).text_color(fg).child(sub)),
                    )
                    .child(div().truncate().text_size(px(12.)).text_color(t.text_faint).child(desc.to_string())),
            )
    }

    fn stage_timeline(&self, t: &Theme) -> impl IntoElement {
        let icons = ["monitor", "cpu", "globe", "rocket", "users", "list", "folder", "shield-check", "route"];
        let n = self.stages.len();
        let mut items: Vec<AnyElement> = Vec::new();
        for (i, s) in self.stages.iter().enumerate() {
            let (circle_bg, circle_fg) = match s.status {
                StageStatus::Done => (t.green_soft, t.green),
                StageStatus::Running => (t.primary_soft, t.primary),
                StageStatus::Pending => (t.gray_soft, t.text_faint),
            };
            let glyph: AnyElement = match s.status {
                StageStatus::Running => spinner(("stage-spin", i), 18., circle_fg).into_any_element(),
                StageStatus::Done if i == n - 1 => icon("check-circle", 18., circle_fg).into_any_element(),
                _ => icon(icons[i % icons.len()], 18., circle_fg).into_any_element(),
            };
            items.push(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .size(px(38.))
                            .flex_none()
                            .rounded_full()
                            .bg(circle_bg)
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(glyph),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .text_size(px(11.5))
                                    .text_color(t.text_faint)
                                    .child(s.started.map(|t| t.format("%H:%M:%S").to_string()).unwrap_or_else(|| "--:--:--".into())),
                            )
                            .child(div().truncate().text_size(px(13.)).font_weight(FontWeight::MEDIUM).child(s.stage.label()))
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(11.5))
                                    .text_color(t.text_muted)
                                    .child(match s.status {
                                        StageStatus::Done => format!("{} · {:.1}s", s.summary, s.elapsed_ms as f64 / 1000.0),
                                        StageStatus::Running => "采集中…".to_string(),
                                        StageStatus::Pending => "等待中".to_string(),
                                    }),
                            ),
                    )
                    .into_any_element(),
            );
            if i + 1 < n {
                items.push(div().flex_none().child(icon("chevron-right", 14., t.text_faint)).into_any_element());
            }
        }
        card(t)
            .p(px(18.))
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(div().text_size(px(16.)).font_weight(FontWeight::SEMIBOLD).child("证据采集时间线"))
            .child(div().flex().items_center().gap(px(6.)).children(items))
    }
}

pub fn fmt_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d} 天 {h} 小时")
    } else if h > 0 {
        format!("{h} 小时 {m} 分")
    } else {
        format!("{m} 分钟")
    }
}

fn or_dash(s: &str) -> String {
    if s.is_empty() { "-".into() } else { s.to_string() }
}
