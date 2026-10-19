//! 入侵还原页：ATT&CK 阶段、攻击时间线与全部调查发现。

use std::collections::HashMap;
use std::rc::Rc;

use gpui::{AnyElement, Context, FontWeight, IntoElement, ParentElement, Styled, div, prelude::*, px};

use super::app::{AppView, Detail, Page};
use super::components::*;
use super::listkit::{ListId, SortVal, refine};
use super::overview::{FINDING_COLS, finding_cells};
use crate::analysis::tactic_summary;
use crate::model::*;
use crate::theme::theme;

pub fn tactic_icon(t: Tactic) -> &'static str {
    match t {
        Tactic::InitialAccess => "log-in",
        Tactic::Execution => "terminal",
        Tactic::Persistence => "rocket",
        Tactic::PrivilegeEscalation => "zap",
        Tactic::DefenseEvasion => "eye-off",
        Tactic::CredentialAccess => "key",
        Tactic::Discovery => "compass",
        Tactic::LateralMovement => "arrows",
        Tactic::CommandAndControl => "radio",
        Tactic::Impact => "flame",
    }
}

const TL_COLS: &[Col] = &[
    col("时间", 150.),
    col("来源", 150.),
    flex_col("事件"),
    col("战术阶段", 90.),
    col("风险", 60.),
];

pub fn timeline_detail(e: &TimelineEvent) -> Detail {
    Detail::new(e.title.clone(), e.source.clone(), Some(e.severity))
        .field("时间", e.time.format("%Y-%m-%d %H:%M:%S").to_string())
        .field("来源", e.source.clone())
        .field("战术阶段", e.tactic.map(|t| format!("{} ({})", t.label(), t.attack_id())).unwrap_or_default())
        .field("详情", e.detail.clone())
}

impl AppView {
    pub fn render_timeline(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();

        // ---------------- ATT&CK 阶段条
        let summary = tactic_summary(&r);
        let tactic_cards: Vec<AnyElement> = summary
            .iter()
            .enumerate()
            .map(|(i, (tac, n, max))| {
                let tac = *tac;
                let hit = *n > 0 || *max >= Severity::Medium;
                let (fg, bg) = if hit { t.severity(*max) } else { (t.text_faint, t.gray_soft) };
                let active = self.f_tactic == Some(tac);
                let hover = t.card_hover;
                card(&t)
                    .id(("tactic", i))
                    .flex_1()
                    .min_w_0()
                    .py(px(10.))
                    .px(px(8.))
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap(px(6.))
                    .cursor_pointer()
                    .when(active, |d| d.border_color(t.primary).bg(t.primary_soft))
                    .when(!active, move |d| d.hover(move |s| s.bg(hover)))
                    .tooltip(tooltip(format!("{} {} · 点击筛选", tac.attack_id(), tac.label())))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.f_tactic = if this.f_tactic == Some(tac) { None } else { Some(tac) };
                        cx.notify();
                    }))
                    .child(
                        div()
                            .size(px(34.))
                            .rounded_full()
                            .bg(bg)
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(icon(tactic_icon(tac), 17., fg)),
                    )
                    .child(div().truncate().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).child(tac.label()))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(if hit { fg } else { t.text_faint })
                            .child(if *n > 0 { format!("{n} 条线索") } else if hit { "有相关事件".into() } else { "未发现".into() }),
                    )
                    .into_any_element()
            })
            .collect();
        let mut chain: Vec<AnyElement> = Vec::new();
        for (i, c) in tactic_cards.into_iter().enumerate() {
            if i > 0 {
                chain.push(div().flex_none().child(icon("chevron-right", 12., t.text_faint)).into_any_element());
            }
            chain.push(c);
        }

        // ---------------- 研判摘要
        let sus: Vec<&TimelineEvent> = r.timeline.iter().filter(|e| e.severity >= Severity::Medium).collect();
        let first = sus.iter().map(|e| e.time).min();
        let last = sus.iter().map(|e| e.time).max();
        let mut ip_stat: HashMap<&str, (usize, usize)> = HashMap::new();
        for e in &r.events {
            if e.source_ip.is_empty() || (e.event_id != 4624 && e.event_id != 4625 && e.event_id != 1149) {
                continue;
            }
            let ent = ip_stat.entry(e.source_ip.as_str()).or_default();
            if e.event_id == 4625 { ent.1 += 1 } else { ent.0 += 1 }
        }
        let mut ips: Vec<(&str, (usize, usize))> = ip_stat.into_iter().collect();
        ips.sort_by_key(|(_, (ok, fail))| std::cmp::Reverse(fail * 10 + ok));
        let ip_text = if ips.is_empty() {
            "无".to_string()
        } else {
            ips.iter().take(3).map(|(ip, (ok, fail))| format!("{ip} (成功{ok}/失败{fail})")).collect::<Vec<_>>().join("  ")
        };
        let mut users: Vec<&str> = r
            .events
            .iter()
            .filter(|e| e.event_id == 4624 && e.severity >= Severity::Info && !e.user.is_empty())
            .map(|e| e.user.as_str())
            .collect();
        users.sort();
        users.dedup();
        let info_cell = |label: &str, value: String, icon_name: &str| {
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .items_center()
                .gap_3()
                .child(div().size(px(36.)).flex_none().rounded(px(8.)).bg(t.primary_soft).flex().items_center().justify_center().child(icon(icon_name, 18., t.primary)))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .flex_col()
                        .child(div().text_size(px(12.)).text_color(t.text_muted).child(label.to_string()))
                        .child(div().truncate().text_size(px(14.)).font_weight(FontWeight::MEDIUM).child(value)),
                )
        };
        let summary_card = card(&t)
            .p(px(16.))
            .flex()
            .gap(px(20.))
            .child(info_cell("首次可疑活动", first.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("-".into()), "clock"))
            .child(info_cell("最近可疑活动", last.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("-".into()), "clock"))
            .child(info_cell("登录来源 IP", ip_text, "globe"))
            .child(info_cell("成功登录账户", if users.is_empty() { "无".into() } else { users.iter().take(4).cloned().collect::<Vec<_>>().join(", ") }, "user"));

        // ---------------- 视图切换 + 筛选
        let tac = self.f_tactic;
        let min = self.f_tl_min;
        let query = self.query(Page::Timeline, cx);
        let tl_rows: Rc<Vec<usize>> = Rc::new(refine(
            r.timeline
                .iter()
                .enumerate()
                .filter(|(_, e)| e.severity >= min && tac.map(|x| e.tactic == Some(x)).unwrap_or(true))
                .map(|(i, _)| i)
                .collect(),
            &r.timeline,
            &query,
            self.sort_of(ListId::Timeline),
            |e| format!("{} {} {} {}", e.source, e.title, e.detail, e.tactic.map(|t| t.label()).unwrap_or("")),
            |e, c| match c {
                0 => SortVal::N(e.time.timestamp()),
                1 => SortVal::s(&e.source),
                2 => SortVal::s(&e.title),
                3 => SortVal::s(e.tactic.map(|t| t.label()).unwrap_or("")),
                _ => SortVal::N(e.severity as i64),
            },
        ));
        let f_rows: Rc<Vec<usize>> = Rc::new(refine(
            r.findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.severity >= min && tac.map(|x| f.tactic == Some(x)).unwrap_or(true))
                .map(|(i, _)| i)
                .collect(),
            &r.findings,
            &query,
            self.sort_of(ListId::Finding),
            |f| format!("{} {} {} {} {} {}", f.category.label(), f.object, f.title, f.detail, f.target, f.technique),
            |f, c| match c {
                0 => SortVal::t(f.time),
                1 => SortVal::s(f.category.label()),
                2 => SortVal::s(&f.object),
                3 => SortVal::s(&f.title),
                4 => SortVal::N(f.severity as i64),
                _ => SortVal::s(&f.target),
            },
        ));
        let show_f = self.tl_show_findings;
        let toolbar = div()
            .flex()
            .items_center()
            .gap_2()
            .child(
                chip(&t, "tl-view-tl", format!("攻击时间线 ({})", tl_rows.len()), !show_f).on_click(cx.listener(|this, _, _, cx| {
                    this.tl_show_findings = false;
                    cx.notify();
                })),
            )
            .child(
                chip(&t, "tl-view-f", format!("全部发现 ({})", f_rows.len()), show_f).on_click(cx.listener(|this, _, _, cx| {
                    this.tl_show_findings = true;
                    cx.notify();
                })),
            )
            .child(div().w(px(1.)).h(px(18.)).bg(t.border).mx_2())
            .children([(Severity::Info, "全部等级"), (Severity::Low, "低及以上"), (Severity::Medium, "中及以上"), (Severity::High, "高及以上")].into_iter().enumerate().map(
                |(i, (s, label))| {
                    chip(&t, ("tl-sev", i), label, min == s).on_click(cx.listener(move |this, _, _, cx| {
                        this.f_tl_min = s;
                        cx.notify();
                    }))
                },
            ))
            .child(div().flex_1())
            .when_some(tac, |d, x| {
                d.child(
                    small_button(&t, "tl-clear-tactic", "x", format!("清除阶段筛选：{}", x.label())).on_click(cx.listener(|this, _, _, cx| {
                        this.f_tactic = None;
                        cx.notify();
                    })),
                )
            });

        let list = if show_f {
            self.virtual_table(&t, ListId::Finding, FINDING_COLS, f_rows, "没有符合条件的发现", cx, |this, i, ix, t, _cx| {
                let f = &this.report.findings[i];
                table_row(t, ("tlf", ix), FINDING_COLS, finding_cells(t, f))
            })
            .into_any_element()
        } else {
            self.virtual_table(&t, ListId::Timeline, TL_COLS, tl_rows, "在回溯周期内没有符合条件的事件", cx, |this, i, ix, t, _cx| {
                let e = &this.report.timeline[i];
                let (fg, _) = t.severity(e.severity);
                table_row(
                    t,
                    ("tle", ix),
                    TL_COLS,
                    vec![
                        div().flex().items_center().gap_2().child(dot(fg, 8.)).child(muted_cell(t, e.time.format("%Y-%m-%d %H:%M:%S").to_string())).into_any_element(),
                        muted_cell(t, e.source.clone()),
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .gap_2()
                            .overflow_hidden()
                            .child(div().flex_none().max_w(px(420.)).truncate().font_weight(FontWeight::MEDIUM).child(one_line(&e.title)))
                            .child(div().flex_1().min_w_0().truncate().text_size(px(12.)).text_color(t.text_faint).child(one_line(&e.detail)))
                            .into_any_element(),
                        muted_cell(t, e.tactic.map(|x| x.label()).unwrap_or("-")),
                        sev_badge(t, e.severity).into_any_element(),
                    ],
                )
            })
            .into_any_element()
        };

        let search = self.search_box(Page::Timeline, cx);
        div()
            .size_full()
            .p(px(20.))
            .flex()
            .flex_col()
            .gap(px(14.))
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap_4()
                    .child(div().flex_1().min_w_0().child(page_title(&t, "入侵还原", &format!("汇聚日志、持久化、文件与进程痕迹，按 ATT&CK 战术阶段还原近 {} 天的入侵过程", r.lookback_days.max(self.lookback)))))
                    .child(search),
            )
            .when(!r.log_gaps.is_empty(), |d| d.child(notice(&t, "审计/日志配置不完整，以下来源的事件可能缺失，时间线结论仅供参考", &r.log_gaps)))
            .child(div().flex().items_center().gap(px(4.)).children(chain))
            .child(summary_card)
            .child(toolbar)
            .child(list)
    }
}
