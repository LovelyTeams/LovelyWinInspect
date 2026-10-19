//! 用户设置：保存在 %APPDATA%\LovelyWinInspect\settings.json。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::report::ExportOptions;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThemeMode {
    #[default]
    Light,
    Dark,
    System,
}

impl ThemeMode {
    pub const ALL: [(ThemeMode, &'static str); 3] = [
        (ThemeMode::Light, "浅色"),
        (ThemeMode::Dark, "深色"),
        (ThemeMode::System, "跟随系统"),
    ];
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeMode,
    /// 默认回溯天数
    pub lookback_days: u32,
    /// 启动后自动开始排查
    pub auto_scan: bool,
    /// 自定义导出目录，None 表示默认位置
    pub export_dir: Option<String>,
    /// 导出页默认勾选的内容
    pub export: ExportOptions,
    /// 启动时自动检查更新
    pub auto_check_update: bool,
    /// 检查更新时包含预发布版本
    pub include_prerelease: bool,
    /// 用户选择忽略的版本
    pub skipped_version: Option<String>,
    /// 上次检查更新的时间
    pub last_update_check: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Light,
            lookback_days: 30,
            auto_scan: true,
            export_dir: None,
            export: ExportOptions::default(),
            auto_check_update: true,
            include_prerelease: false,
            skipped_version: None,
            last_update_check: None,
        }
    }
}

pub fn config_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("LovelyWinInspect")
}

fn config_file() -> PathBuf {
    config_dir().join("settings.json")
}

impl Settings {
    pub fn load() -> Self {
        std::fs::read_to_string(config_file())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(config_dir()).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(config_file(), json).map_err(|e| e.to_string())
    }

    pub fn export_root(&self) -> Option<PathBuf> {
        self.export_dir.as_ref().filter(|d| !d.trim().is_empty()).map(PathBuf::from)
    }
}
