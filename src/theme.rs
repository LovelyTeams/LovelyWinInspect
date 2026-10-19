//! 主题配色（浅色 / 深色）。

use gpui::{App, Global, Hsla, rgb};

use crate::model::{CheckStatus, Severity};

#[derive(Clone, Copy)]
pub struct Theme {
    pub dark: bool,
    pub bg: Hsla,
    pub sidebar: Hsla,
    pub titlebar: Hsla,
    pub card: Hsla,
    pub card_hover: Hsla,
    pub border: Hsla,
    pub divider: Hsla,
    pub header_bg: Hsla,
    pub text: Hsla,
    pub text_muted: Hsla,
    pub text_faint: Hsla,
    pub primary: Hsla,
    pub primary_soft: Hsla,
    pub on_primary: Hsla,
    pub red: Hsla,
    pub red_soft: Hsla,
    pub orange: Hsla,
    pub orange_soft: Hsla,
    pub blue: Hsla,
    pub blue_soft: Hsla,
    pub green: Hsla,
    pub green_soft: Hsla,
    pub gray_soft: Hsla,
    pub purple: Hsla,
    pub purple_soft: Hsla,
    pub overlay: Hsla,
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

impl Theme {
    pub fn light() -> Self {
        Self {
            dark: false,
            bg: c(0xF4F6FA),
            sidebar: c(0xFFFFFF),
            titlebar: c(0xF4F6FA),
            card: c(0xFFFFFF),
            card_hover: c(0xF5F8FF),
            border: c(0xE4E8F0),
            divider: c(0xEEF1F6),
            header_bg: c(0xF7F8FB),
            text: c(0x1F2329),
            text_muted: c(0x646A73),
            text_faint: c(0x8F959E),
            primary: c(0x1F6FEB),
            primary_soft: c(0xE8F0FE),
            on_primary: c(0xFFFFFF),
            red: c(0xE5484D),
            red_soft: c(0xFDECEC),
            orange: c(0xE8730C),
            orange_soft: c(0xFFF1E0),
            blue: c(0x3370FF),
            blue_soft: c(0xE6EEFF),
            green: c(0x2EA043),
            green_soft: c(0xE3F6E8),
            gray_soft: c(0xEFF1F5),
            purple: c(0x7C4DFF),
            purple_soft: c(0xEFE9FF),
            overlay: gpui::hsla(0.0, 0.0, 0.0, 0.25),
        }
    }

    pub fn dark() -> Self {
        Self {
            dark: true,
            bg: c(0x14161B),
            sidebar: c(0x1B1E24),
            titlebar: c(0x14161B),
            card: c(0x1E2128),
            card_hover: c(0x252A33),
            border: c(0x2D323C),
            divider: c(0x282C35),
            header_bg: c(0x232731),
            text: c(0xE6E8EC),
            text_muted: c(0xA2A8B3),
            text_faint: c(0x737A86),
            primary: c(0x4C8DFF),
            primary_soft: c(0x1D2B45),
            on_primary: c(0xFFFFFF),
            red: c(0xFF6B6F),
            red_soft: c(0x3A2023),
            orange: c(0xFF9F43),
            orange_soft: c(0x3A2A18),
            blue: c(0x6E9BFF),
            blue_soft: c(0x1E2A44),
            green: c(0x4CC66B),
            green_soft: c(0x1B3324),
            gray_soft: c(0x2A2E37),
            purple: c(0xA88BFF),
            purple_soft: c(0x2A2341),
            overlay: gpui::hsla(0.0, 0.0, 0.0, 0.5),
        }
    }

    /// 风险等级对应 (前景色, 背景色)
    pub fn severity(&self, s: Severity) -> (Hsla, Hsla) {
        match s {
            Severity::Critical => (self.purple, self.purple_soft),
            Severity::High => (self.red, self.red_soft),
            Severity::Medium => (self.orange, self.orange_soft),
            Severity::Low => (self.blue, self.blue_soft),
            Severity::Info => (self.text_muted, self.gray_soft),
        }
    }

    pub fn status(&self, s: CheckStatus) -> (Hsla, Hsla) {
        match s {
            CheckStatus::Pass => (self.green, self.green_soft),
            CheckStatus::Fail => (self.red, self.red_soft),
            CheckStatus::Warn => (self.orange, self.orange_soft),
            CheckStatus::Unknown => (self.text_muted, self.gray_soft),
        }
    }
}

impl Global for Theme {}

pub fn theme(cx: &App) -> Theme {
    *cx.global::<Theme>()
}
