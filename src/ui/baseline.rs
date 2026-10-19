//! 基线核查页。

use gpui::{AnyElement, Context, FontWeight, IntoElement, ParentElement, Styled, div, prelude::*, px};

use super::app::{AppView, Detail};
use super::components::*;
use crate::model::*;
use crate::theme::theme;

const GROUPS: &[&str] = &["账户策略", "审计策略", "日志配置", "安全选项", "网络与服务", "系统防护"];

const COLS: &[Col] = &[
    col("编号", 70.),
    flex_col("检查项"),
    col("分类", 90.),
    col("期望值", 190.),
    col("当前值", 240.),
    col("结果", 90.),
    col("风险", 60.),
];

pub fn baseline_detail(b: &BaselineCheck) -> Detail {
    Detail::new(b.title.clone(), format!("{} · {}", b.id, b.group), Some(b.severity))
        .field("核查结果", b.status.label())
        .field("期望值", b.expected.clone())
        .field("当前值", b.actual.clone())
        .field("加固建议", b.advice.clone())
}

impl AppView {
    pub fn render_baseline(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let total = r.baseline.len();
        let count = |s: CheckStatus| r.baseline.iter().filter(|b| b.status == s).count();
        let (pass, fail, warn, unknown) = (count(CheckStatus::Pass), count(CheckStatus::Fail), count(CheckStatus::Warn), count(CheckStatus::Unknown));
        let score = r.baseline_score();

        let score_color = match score {
            Some(s) if s >= 80 => t.green,
            Some(s) if s >= 60 => t.orange,
            Some(_) => t.red,
            None => t.text_faint,
        };
        let summary = card(&t)
            .p(px(20.))
            .flex()
            .items_center()
            .gap(px(28.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .w(px(200.))
                    .child(div().text_size(px(13.)).text_color(t.text_muted).child("基线合规率"))
                    .child(
                        div()
                            .text_size(px(40.))
                            .font_weight(FontWeight::BOLD)
                            .text_color(score_color)
                            .child(score.map(|s| format!("{s}%")).unwrap_or("-".into())),
                    )
                    .child(progress_bar(&t, score.unwrap_or(0) as f32 / 100.0, score_color)),
            )
            .child(div().w(px(1.)).h(px(70.)).bg(t.divider))
            .children([
                (CheckStatus::Pass, pass),
                (CheckStatus::Fail, fail),
                (CheckStatus::Warn, warn),
                (CheckStatus::Unknown, unknown),
            ]
            .into_iter()
            .map(|(s, n)| {
                let (fg, _) = t.status(s);
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(div().flex().items_center().gap_2().child(dot(fg, 8.)).child(div().text_size(px(13.)).text_color(t.text_muted).child(s.label())))
                    .child(div().text_size(px(26.)).font_weight(FontWeight::SEMIBOLD).child(n.to_string()))
            }))
            .child(div().flex_1())
            .child(div().text_size(px(12.)).text_color(t.text_faint).child(format!("共 {total} 项检查 · 参考等保 2.0 / CIS 基线")));

        // 分组进度卡
        let group_cards: Vec<AnyElement> = GROUPS
            .iter()
            .enumerate()
            .map(|(i, g)| {
                let items: Vec<&BaselineCheck> = r.baseline.iter().filter(|b| b.group == *g).collect();
                let judged = items.iter().filter(|b| b.status != CheckStatus::Unknown).count();
                let ok = items.iter().filter(|b| b.status == CheckStatus::Pass).count();
                let bad = items.iter().filter(|b| b.status == CheckStatus::Fail).count();
                let ratio = if judged == 0 { 0.0 } else { ok as f32 / judged as f32 };
                let color = if bad > 0 { t.red } else if ok < judged { t.orange } else { t.green };
                let active = self.f_baseline_group.as_deref() == Some(*g);
                let hover = t.card_hover;
                let group = g.to_string();
                card(&t)
                    .id(("bg-group", i))
                    .flex_1()
                    .min_w_0()
                    .p(px(14.))
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .cursor_pointer()
                    .when(active, |d| d.border_color(t.primary).bg(t.primary_soft))
                    .when(!active, move |d| d.hover(move |s| s.bg(hover)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.f_baseline_group = if this.f_baseline_group.as_deref() == Some(group.as_str()) { None } else { Some(group.clone()) };
                        cx.notify();
                    }))
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .child(div().text_size(px(13.)).font_weight(FontWeight::MEDIUM).child(g.to_string()))
                            .child(div().text_size(px(12.)).text_color(t.text_muted).child(format!("{ok}/{}", items.len()))),
                    )
                    .child(progress_bar(&t, ratio, color))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(if bad > 0 { t.red } else { t.text_faint })
                            .child(if bad > 0 { format!("{bad} 项不符合") } else { "无不符合项".to_string() }),
                    )
                    .into_any_element()
            })
            .collect();

        let rows: Vec<AnyElement> = r
            .baseline
            .iter()
            .enumerate()
            .filter(|(_, b)| self.f_baseline_group.as_deref().map(|g| b.group == g).unwrap_or(true))
            .filter(|(_, b)| !self.f_baseline_issues || b.status != CheckStatus::Pass)
            .map(|(i, b)| {
                let (fg, _) = t.severity(b.severity);
                table_row(
                    &t,
                    ("bl", i),
                    COLS,
                    vec![
                        mono_cell(&t, b.id.clone()),
                        text_cell(b.title.clone()),
                        muted_cell(&t, b.group.clone()),
                        muted_cell(&t, b.expected.clone()),
                        text_cell(b.actual.clone()),
                        status_badge(&t, b.status).into_any_element(),
                        div().text_size(px(12.)).text_color(fg).child(b.severity.label()).into_any_element(),
                    ],
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    let d = baseline_detail(&this.report.baseline[i]);
                    this.show(d, cx);
                }))
                .into_any_element()
            })
            .collect();
        let empty = rows.is_empty();

        div()
            .id("page-baseline")
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
            .child(page_title(&t, "安全基线核查", "检查账户策略、审计策略、安全选项、网络服务与系统防护配置，给出加固建议"))
            .child(summary)
            .child(div().flex().gap(px(12.)).children(group_cards))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        chip(&t, "bl-all", "全部分类", self.f_baseline_group.is_none())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.f_baseline_group = None;
                                cx.notify();
                            })),
                    )
                    .child(
                        chip(&t, "bl-issues", format!("仅看问题项 ({})", fail + warn), self.f_baseline_issues)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.f_baseline_issues = !this.f_baseline_issues;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                card(&t)
                    .overflow_hidden()
                    .flex()
                    .flex_col()
                    .child(table_header(&t, COLS))
                    .children(rows)
                    .when(empty, |d| {
                        d.child(empty_state(&t, if self.scanning { "loader" } else { "check-circle" }, if self.scanning { "基线核查将在采集后进行…" } else { "没有符合条件的检查项" }))
                    }),
            ))
    }
}
