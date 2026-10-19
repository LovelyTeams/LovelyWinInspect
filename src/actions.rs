//! 处置动作：应急响应中对本机执行的少量写操作。
//!
//! 采集部分始终只读；本模块是唯一会修改系统状态的地方。每次动作无论成败都会立即
//! 追加到 `%APPDATA%\LovelyWinInspect\actions.log`，并随证据包一起导出，便于复盘
//! 处置过程。所有破坏性动作在界面上都需要二次确认。

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::collect::util::wide;
use crate::settings::config_dir;

pub fn log_path() -> PathBuf {
    config_dir().join("actions.log")
}

/// 记录一次处置动作。`ok` 为 false 时说明动作失败。
fn record(action: &str, target: &str, ok: bool, detail: &str) {
    let mut line = String::new();
    let _ = writeln!(
        line,
        "{}\t{}\t{}\t{}\t{}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        action,
        target,
        if ok { "成功" } else { "失败" },
        detail.replace(['\r', '\n', '\t'], " ")
    );
    let path = log_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
    if ok {
        log::info!("处置动作 {action} -> {target}: {detail}");
    } else {
        log::warn!("处置动作 {action} -> {target} 失败: {detail}");
    }
}

fn done(action: &str, target: &str, r: Result<String, String>) -> Result<String, String> {
    match &r {
        Ok(msg) => record(action, target, true, msg),
        Err(e) => record(action, target, false, e),
    }
    r
}

// ---------------------------------------------------------------- 进程

/// 结束指定进程。成功返回提示文案。
pub fn kill_process(pid: u32, name: &str) -> Result<String, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    let target = format!("{name} ({pid})");
    if pid <= 4 {
        return done("结束进程", &target, Err("系统进程不可结束".into()));
    }
    let r = unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => {
                let out = match TerminateProcess(h, 1) {
                    Ok(()) => Ok(format!("已结束进程 {target}")),
                    Err(e) => Err(format!("结束失败：{}", e.message())),
                };
                let _ = CloseHandle(h);
                out
            }
            Err(e) => Err(format!("无法打开进程（可能是受保护进程或权限不足）：{}", e.message())),
        }
    };
    done("结束进程", &target, r)
}

// ---------------------------------------------------------------- 文件

/// 去掉文件的隐藏 / 系统属性，使其在资源管理器中正常可见。
pub fn clear_hidden(path: &str) -> Result<String, String> {
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_FLAGS_AND_ATTRIBUTES,
        GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SetFileAttributesW,
    };
    use windows::core::PCWSTR;
    let w = wide(path);
    let r = unsafe {
        let attrs = GetFileAttributesW(PCWSTR(w.as_ptr()));
        if attrs == INVALID_FILE_ATTRIBUTES {
            Err("文件不存在或无法读取属性".to_string())
        } else {
            let hidden = attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0;
            let system = attrs & FILE_ATTRIBUTE_SYSTEM.0 != 0;
            if !hidden && !system {
                Ok("该文件本就没有隐藏/系统属性".to_string())
            } else {
                let cleared = attrs & !FILE_ATTRIBUTE_HIDDEN.0 & !FILE_ATTRIBUTE_SYSTEM.0;
                match SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(cleared)) {
                    Ok(()) => Ok(format!(
                        "已去掉{}属性",
                        match (hidden, system) {
                            (true, true) => "隐藏和系统",
                            (true, false) => "隐藏",
                            _ => "系统",
                        }
                    )),
                    Err(e) => Err(format!("修改属性失败：{}", e.message())),
                }
            }
        }
    };
    done("恢复隐藏文件", path, r)
}

/// 在资源管理器中定位文件（不修改系统，不记录日志）。
pub fn reveal_in_explorer(path: &str) {
    let p = Path::new(path);
    if p.is_file() {
        let _ = std::process::Command::new("explorer.exe").arg(format!("/select,{path}")).spawn();
    } else {
        let dir = if p.is_dir() { p.to_path_buf() } else { p.parent().map(Path::to_path_buf).unwrap_or_default() };
        if dir.as_os_str().is_empty() {
            return;
        }
        let _ = std::process::Command::new("explorer.exe").arg(dir).spawn();
    }
}

// ---------------------------------------------------------------- 注册表

/// 把我们记录的位置（HKLM\... / HKU\<SID>\...）转为注册表编辑器能识别的完整路径。
fn full_reg_path(location: &str) -> Option<String> {
    let loc = location.split(" | ").next()?.trim();
    let (short, rest) = loc.split_once('\\')?;
    let hive = match short.to_ascii_uppercase().as_str() {
        "HKLM" => "HKEY_LOCAL_MACHINE",
        "HKCU" => "HKEY_CURRENT_USER",
        "HKU" => "HKEY_USERS",
        "HKCR" => "HKEY_CLASSES_ROOT",
        _ => return None,
    };
    // 采集时为了显示美观会把中间层级缩写成 "..."，这类路径无法直接定位
    if rest.contains("...") {
        return Some(format!("{hive}"));
    }
    Some(format!("{hive}\\{rest}"))
}

/// 在注册表编辑器中打开指定位置。
pub fn open_regedit(location: &str) -> Result<String, String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    let Some(full) = full_reg_path(location) else {
        return done("定位注册表", location, Err("无法解析注册表路径".into()));
    };
    let applet = r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    // 沿用系统现有的本地化前缀（如“计算机”/"Computer"）
    let prefix = hkcu
        .open_subkey_with_flags(applet, KEY_READ)
        .ok()
        .and_then(|k| k.get_value::<String, _>("LastKey").ok())
        .and_then(|v| v.split('\\').next().map(str::to_string))
        .filter(|p| !p.contains(':') && !p.starts_with("HKEY_"))
        .unwrap_or_else(|| "计算机".to_string());
    let r = (|| -> Result<String, String> {
        let (key, _) = hkcu.create_subkey(applet).map_err(|e| e.to_string())?;
        key.set_value("LastKey", &format!("{prefix}\\{full}")).map_err(|e| e.to_string())?;
        std::process::Command::new("regedit.exe").spawn().map_err(|e| e.to_string())?;
        Ok(format!("已在注册表编辑器中打开 {full}"))
    })();
    done("定位注册表", &full, r)
}

// ---------------------------------------------------------------- 启动项

/// 可被本工具禁用的启动项类型。
pub fn can_disable(kind: crate::model::PersistKind) -> bool {
    use crate::model::PersistKind as K;
    matches!(kind, K::RunKey | K::ScheduledTask | K::Service)
}

/// 禁用启动项。Run 键使用与任务管理器相同的 StartupApproved 机制（可在任务管理器中恢复），
/// 计划任务与服务通过系统自带命令禁用，均不删除任何数据。
pub fn disable_startup(item: &crate::model::PersistItem) -> Result<String, String> {
    use crate::model::PersistKind as K;
    let target = format!("{} [{}]", item.name, item.kind.label());
    let r = match item.kind {
        K::RunKey => disable_run_key(item),
        K::ScheduledTask => {
            let name = item.name.clone();
            run_tool("schtasks.exe", &["/change", "/tn", &name, "/disable"])
                .map(|_| format!("已禁用计划任务 {name}（可用 schtasks /change /tn \"{name}\" /enable 恢复）"))
        }
        K::Service => {
            let name = item.name.clone();
            run_tool("sc.exe", &["config", &name, "start=", "disabled"])
                .map(|_| format!("服务 {name} 已设为禁用启动（当前实例仍在运行，重启后不再自启）"))
        }
        _ => Err("该类型暂不支持一键禁用，请手动处置".into()),
    };
    done("禁用启动项", &target, r)
}

fn run_tool(program: &str, args: &[&str]) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("无法执行 {program}：{e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let msg = String::from_utf8_lossy(&out.stderr);
        let msg = if msg.trim().is_empty() { String::from_utf8_lossy(&out.stdout).into_owned() } else { msg.into_owned() };
        Err(format!("{program} 返回错误：{}", msg.trim()))
    }
}

/// 写入 StartupApproved：首字节 bit0 置 1 表示禁用，与任务管理器一致。
fn disable_run_key(item: &crate::model::PersistItem) -> Result<String, String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let loc = item.location.to_ascii_uppercase();
    let is_hklm = loc.starts_with("HKLM");
    let sub = if loc.contains("WOW6432NODE") { "Run32" } else { "Run" };
    let (root, base) = if is_hklm {
        (HKEY_LOCAL_MACHINE, format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sub}"))
    } else {
        (HKEY_CURRENT_USER, format!(r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sub}"))
    };
    if !is_hklm && !item.location.to_ascii_uppercase().contains("HKU") && !item.location.to_ascii_uppercase().contains("HKCU") {
        return Err("无法判断该启动项所属配置单元".into());
    }
    let hive = RegKey::predef(root);
    let (key, _) = hive.create_subkey(&base).map_err(|e| format!("无法打开 StartupApproved：{e}"))?;
    // 12 字节：首字节 0x03 = 已禁用，其后 8 字节为禁用时间（留零即可）
    let data = winreg::RegValue { bytes: std::borrow::Cow::Owned(vec![3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), vtype: winreg::enums::REG_BINARY };
    key.set_raw_value(&item.name, &data).map_err(|e| format!("写入失败：{e}"))?;
    Ok(format!("已禁用自启动项 {}（可在任务管理器“启动”选项卡中恢复）", item.name))
}

// ---------------------------------------------------------------- 哈希

pub fn sha256(path: &str) -> Result<String, String> {
    let p = Path::new(path);
    if !p.is_file() {
        return Err("文件不存在".into());
    }
    let h = crate::collect::util::sha256_file(p, 2 << 30);
    if h.is_empty() { Err("计算失败（文件过大或无法读取）".into()) } else { Ok(h) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_path_maps_hives() {
        assert_eq!(full_reg_path(r"HKLM\SOFTWARE\Test").as_deref(), Some(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test"));
        assert_eq!(full_reg_path(r"HKCU\Software\X").as_deref(), Some(r"HKEY_CURRENT_USER\Software\X"));
        // 位置里带有展示用的省略号时只定位到根
        assert_eq!(full_reg_path(r"HKU\S-1-5-21-1\...\Run").as_deref(), Some("HKEY_USERS"));
        assert_eq!(full_reg_path("C:\notregistry"), None);
    }

    #[test]
    fn clear_hidden_removes_attributes() {
        use windows::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, GetFileAttributesW, SetFileAttributesW,
        };
        use windows::core::PCWSTR;

        let path = std::env::temp_dir().join(format!("lwi_hidden_test_{}.txt", std::process::id()));
        std::fs::write(&path, b"test").unwrap();
        let s = path.display().to_string();
        let w = wide(&s);
        unsafe {
            SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM).unwrap();
            let before = GetFileAttributesW(PCWSTR(w.as_ptr()));
            assert_ne!(before & FILE_ATTRIBUTE_HIDDEN.0, 0, "前置条件：文件应为隐藏");

            assert!(clear_hidden(&s).is_ok());

            let after = GetFileAttributesW(PCWSTR(w.as_ptr()));
            assert_eq!(after & FILE_ATTRIBUTE_HIDDEN.0, 0, "隐藏属性应已去除");
            assert_eq!(after & FILE_ATTRIBUTE_SYSTEM.0, 0, "系统属性应已去除");
        }
        // 重复执行应提示本就没有隐藏属性，而不是报错
        assert!(clear_hidden(&s).unwrap().contains("本就"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kill_refuses_system_pids() {
        assert!(kill_process(4, "System").is_err());
    }
}
