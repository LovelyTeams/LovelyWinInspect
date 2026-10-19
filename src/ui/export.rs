//! 证据导出页。

use gpui::{AnyElement, Context, FontWeight, IntoElement, ParentElement, Styled, div, prelude::*, px};

use super::app::{AppView, open_in_explorer};
use super::components::*;
use crate::report::default_root;
use crate::theme::theme;

impl AppView {
    pub fn render_export(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let o = self.export.opts;
        let opt = |id: &'static str, checked: bool, label: &str, desc: &str, cx: &mut Context<Self>, f: fn(&mut AppView)| {
            checkbox(&t, id, checked, label.to_string(), desc.to_string())
                .flex_1()
                .min_w_0()
                .on_click(cx.listener(move |this, _, _, cx| {
                    f(this);
                    this.settings.export = this.export.opts;
                    this.save_settings();
                    cx.notify();
                }))
        };
        let options = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(opt("ex-html", o.html, "HTML 报告", "图文并茂的应急响应报告，可直接发给客户或领导", cx, |a| a.export.opts.html = !a.export.opts.html))
                    .child(opt("ex-json", o.json, "JSON 数据", "完整结构化采集结果，便于二次分析与平台导入", cx, |a| a.export.opts.json = !a.export.opts.json))
                    .child(opt("ex-csv", o.csv, "CSV 表格", "发现、基线、时间线、进程、连接等明细（Excel 可直接打开）", cx, |a| a.export.opts.csv = !a.export.opts.csv)),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .child(opt("ex-evtx", o.evtx, "原始日志 (.evtx)", "导出 Security/System/PowerShell/RDP/Defender 等原始日志，体积可能较大", cx, |a| a.export.opts.evtx = !a.export.opts.evtx))
                    .child(opt("ex-evi", o.evidence, "文本证据", "hosts、PowerShell 历史、非微软计划任务 XML、进程与连接快照", cx, |a| a.export.opts.evidence = !a.export.opts.evidence))
                    .child(div().flex_1()),
            );

        let can_export = self.has_report && !self.scanning && !self.export.running;
        let action: AnyElement = if self.export.running {
            div()
                .flex()
                .items_center()
                .gap_2()
                .h(px(38.))
                .px(px(18.))
                .rounded(px(8.))
                .bg(t.primary_soft)
                .text_color(t.primary)
                .child(spinner("ex-spin", 16., t.primary))
                .child("正在导出…")
                .into_any_element()
        } else if can_export {
            primary_button(&t, "do-export", "download", "开始导出")
                .on_click(cx.listener(|this, _, _, cx| this.start_export(cx)))
                .into_any_element()
        } else {
            div()
                .h(px(38.))
                .px(px(18.))
                .flex()
                .items_center()
                .rounded(px(8.))
                .bg(t.gray_soft)
                .text_color(t.text_faint)
                .child(if self.scanning { "等待采集完成…" } else { "请先执行排查" })
                .into_any_element()
        };

        let result: Option<AnyElement> = if let Some((dir, files, warnings)) = &self.export.result {
            let dir2 = dir.clone();
            let total: u64 = files.iter().map(|f| f.1).sum();
            Some(
                card(&t)
                    .p(px(18.))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(icon("check-circle", 20., t.green))
                            .child(div().text_size(px(15.)).font_weight(FontWeight::SEMIBOLD).child(format!("导出完成：{} 个文件，共 {}", files.len(), fmt_size(total))))
                            .child(div().flex_1())
                            .child(small_button(&t, "open-dir", "folder-open", "打开目录").on_click(move |_, _, _| open_in_explorer(&dir2))),
                    )
                    .child(mono_cell(&t, dir.display().to_string()))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .children(files.iter().take(40).map(|(name, size)| {
                                div()
                                    .flex()
                                    .justify_between()
                                    .py(px(4.))
                                    .border_b_1()
                                    .border_color(t.divider)
                                    .text_size(px(12.5))
                                    .child(div().text_color(t.text).child(name.clone()))
                                    .child(div().text_color(t.text_muted).child(fmt_size(*size)))
                            })),
                    )
                    .when(!warnings.is_empty(), |d| {
                        d.child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .p_3()
                                .rounded(px(8.))
                                .bg(t.orange_soft)
                                .text_size(px(12.))
                                .text_color(t.orange)
                                .child("部分内容未能导出：")
                                .children(warnings.iter().take(10).map(|w| div().child(w.clone()))),
                        )
                    })
                    .into_any_element(),
            )
        } else {
            self.export.error.as_ref().map(|e| {
                card(&t)
                    .p(px(18.))
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_color(t.red)
                    .child(icon("x-circle", 18., t.red))
                    .child(format!("导出失败：{e}"))
                    .into_any_element()
            })
        };

        let errors = &self.report.errors;
        let manifest_note = "导出完成后自动生成 manifest_sha256.txt，记录所有证据文件的 SHA256，用于证据完整性校验。";

        div()
            .id("page-export")
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
            .child(page_title(&t, "证据导出", "将本次排查结果与原始证据打包导出，便于留存、复核与出具报告"))
            .child(
                card(&t)
                    .p(px(18.))
                    .flex()
                    .flex_col()
                    .gap(px(14.))
                    .child(section_header(&t, "导出内容"))
                    .child(options)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(icon("folder", 16., t.text_muted))
                            .child(div().text_size(px(13.)).text_color(t.text_muted).child("输出目录"))
                            .child(mono_cell(&t, format!("{}\\<主机名>_<时间>", self.settings.export_root().unwrap_or_else(default_root).display())))
                            .child(div().flex_1())
                            .child(action),
                    )
                    .child(div().text_size(px(12.)).text_color(t.text_faint).child(manifest_note)),
            )
            .children(result)
            .when(!errors.is_empty(), |d| {
                d.child(
                    card(&t)
                        .p(px(18.))
                        .flex()
                        .flex_col()
                        .gap_2()
                        .child(section_header(&t, "采集告警"))
                        .children(errors.iter().take(30).map(|e| div().text_size(px(12.5)).text_color(t.text_muted).child(e.clone()))),
                )
            }))
    }
}
