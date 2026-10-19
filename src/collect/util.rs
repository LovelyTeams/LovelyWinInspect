//! 采集模块公用的小工具：宽字符串、时间换算、注册表读取、路径判定等。

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, TimeZone, Utc};
use windows::Win32::Foundation::FILETIME;
use windows::core::PWSTR;
use winreg::RegKey;
use winreg::enums::*;

use crate::model::Time;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// # Safety
/// `p` 必须为空或指向以 0 结尾的 UTF-16 字符串。
pub unsafe fn pwstr(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string().unwrap_or_default() }
}

pub fn filetime_to_local(ft: FILETIME) -> Option<Time> {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    filetime_ticks_to_local(ticks)
}

pub fn filetime_ticks_to_local(ticks: u64) -> Option<Time> {
    if ticks == 0 {
        return None;
    }
    // FILETIME 以 1601-01-01 为纪元，单位 100ns
    let secs = (ticks / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    unix_to_local(secs, nanos)
}

pub fn unix_to_local(secs: i64, nanos: u32) -> Option<Time> {
    if secs <= 0 {
        return None;
    }
    Utc.timestamp_opt(secs, nanos)
        .single()
        .map(|t| t.with_timezone(&Local))
}

pub fn systime_to_local(t: SystemTime) -> Option<Time> {
    let d = t.duration_since(UNIX_EPOCH).ok()?;
    unix_to_local(d.as_secs() as i64, d.subsec_nanos())
}

pub fn parse_rfc3339_local(s: &str) -> Option<Time> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Local))
}

pub fn days_ago(days: u32) -> Time {
    Local::now() - chrono::Duration::days(days as i64)
}

/// 静默执行系统命令并取得标准输出（UTF-8 / 有损）。
pub fn run_hidden(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 以 UTF-8 输出方式执行一段 PowerShell。
pub fn run_powershell(script: &str) -> Option<String> {
    let full = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='SilentlyContinue'; {script}"
    );
    run_hidden(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full],
    )
}

/// 读取 UTF-16 (带 BOM) 或 UTF-8 文本文件。
pub fn read_text_any(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(decode_text(&bytes))
}

pub fn decode_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let words: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&words);
    }
    if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    // 没有 BOM 但看起来是 UTF-16LE（大量 0 字节）
    if bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 {
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&words);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------- 注册表

pub fn hive(name: &str) -> RegKey {
    match name {
        "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
        "HKU" => RegKey::predef(HKEY_USERS),
        "HKCR" => RegKey::predef(HKEY_CLASSES_ROOT),
        _ => RegKey::predef(HKEY_LOCAL_MACHINE),
    }
}

pub fn reg_open(root: &str, path: &str) -> Option<RegKey> {
    hive(root)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .ok()
}


/// 将任意注册表值安全地转为字符串（不会因畸形数据 panic）。
pub fn reg_value_to_string(v: &winreg::RegValue) -> String {
    let bytes: &[u8] = &v.bytes;
    match v.vtype {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ | REG_LINK => {
            let words: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let mut s = String::from_utf16_lossy(&words);
            while s.ends_with('\0') {
                s.pop();
            }
            if v.vtype == REG_MULTI_SZ {
                s = s
                    .split('\0')
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<_>>()
                    .join(" | ");
            }
            s
        }
        REG_DWORD if bytes.len() >= 4 => {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string()
        }
        REG_QWORD if bytes.len() >= 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(a).to_string()
        }
        _ => bytes
            .iter()
            .take(64)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

pub fn key_str(key: &RegKey, name: &str) -> Option<String> {
    let v = key.get_raw_value(name).ok()?;
    Some(reg_value_to_string(&v))
}

pub fn key_dword(key: &RegKey, name: &str) -> Option<u32> {
    let v = key.get_raw_value(name).ok()?;
    match v.vtype {
        REG_DWORD if v.bytes.len() >= 4 => Some(u32::from_le_bytes([
            v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3],
        ])),
        REG_QWORD if v.bytes.len() >= 8 => Some(u32::from_le_bytes([
            v.bytes[0], v.bytes[1], v.bytes[2], v.bytes[3],
        ])),
        REG_SZ | REG_EXPAND_SZ => reg_value_to_string(&v).trim().parse().ok(),
        _ => None,
    }
}

pub fn reg_str(root: &str, path: &str, name: &str) -> Option<String> {
    key_str(&reg_open(root, path)?, name)
}

pub fn reg_dword(root: &str, path: &str, name: &str) -> Option<u32> {
    key_dword(&reg_open(root, path)?, name)
}

pub fn reg_values(key: &RegKey) -> Vec<(String, String)> {
    key.enum_values()
        .filter_map(|r| r.ok())
        .map(|(n, v)| (n, reg_value_to_string(&v)))
        .collect()
}

pub fn reg_subkeys(key: &RegKey) -> Vec<String> {
    key.enum_keys().filter_map(|r| r.ok()).collect()
}

pub fn key_last_write(key: &RegKey) -> Option<Time> {
    let info = key.query_info().ok()?;
    let ft = &*info.last_write_time;
    filetime_ticks_to_local(((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64)
}

// ---------------------------------------------------------------- 路径

pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

pub fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string())
}

/// 展开 %VAR% 形式的环境变量。
pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match std::env::var(name) {
                Ok(val) if !name.is_empty() => out.push_str(&val),
                _ => {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push('%');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// 规范化服务 ImagePath / 驱动路径中的 \SystemRoot\、\??\ 等前缀。
pub fn normalize_nt_path(p: &str) -> String {
    let mut s = expand_env(p.trim());
    let lower = s.to_ascii_lowercase();
    if lower.starts_with(r"\??\") {
        s = s[4..].to_string();
    } else if lower.starts_with(r"\systemroot\") {
        s = format!("{}{}", system_root(), &s[11..]);
    } else if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
        s = format!("{}\\{}", system_root(), s);
    }
    s
}

/// 从命令行中提取可执行文件路径。
pub fn exe_from_cmdline(cmd: &str) -> String {
    let cmd = normalize_nt_path(cmd);
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return String::new();
    }
    let candidate = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        // 不带引号：尝试逐步扩展到存在的文件（处理 C:\Program Files\x.exe arg）
        let lower = cmd.to_ascii_lowercase();
        let mut found = None;
        for ext in [".exe", ".com", ".bat", ".cmd", ".dll", ".sys", ".ps1", ".vbs", ".js", ".scr"] {
            let mut search_from = 0;
            while let Some(pos) = lower[search_from..].find(ext) {
                let end = search_from + pos + ext.len();
                let next = lower[end..].chars().next();
                if next.is_none() || next == Some(' ') || next == Some(',') || next == Some('"') {
                    found = Some(cmd[..end].to_string());
                    break;
                }
                search_from = end;
            }
            if found.is_some() {
                break;
            }
        }
        found.unwrap_or_else(|| cmd.split_whitespace().next().unwrap_or("").to_string())
    };
    resolve_exe(&candidate)
}

/// 将 "cmd.exe" 这样的裸文件名解析到 System32 下的完整路径。
pub fn resolve_exe(p: &str) -> String {
    let p = p.trim().trim_matches('"');
    if p.is_empty() {
        return String::new();
    }
    if p.contains('\\') || p.contains('/') {
        return p.to_string();
    }
    let mut name = p.to_string();
    if !name.contains('.') {
        name.push_str(".exe");
    }
    let sys32 = format!("{}\\System32\\{}", system_root(), name);
    if Path::new(&sys32).exists() {
        return sys32;
    }
    let win = format!("{}\\{}", system_root(), name);
    if Path::new(&win).exists() {
        return win;
    }
    name
}


/// 系统更新 / 安全服务相关域名片段（Hosts 与 DNS 缓存中被指向本地或内网时提示）。
pub const UPDATE_DOMAINS: &[&str] = &["microsoft.com", "windowsupdate", "windows.com", "defender"];

/// 是否位于普通用户可写、恶意程序常用的落地目录。
pub fn is_suspicious_dir(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('/', "\\");
    const MARKS: &[&str] = &[
        r"\appdata\local\temp\",
        r"\windows\temp\",
        r"\users\public\",
        r"\downloads\",
        r"\$recycle.bin\",
        r"\perflogs\",
        r"\appdata\roaming\",
        r"\windows\debug\",
        r"\windows\tasks\",
        r"\windows\fonts\",
        r"\windows\help\",
        r"\intel\",
        r"\temp\",
        r"\tmp\",
    ];
    if MARKS.iter().any(|m| p.contains(m)) {
        return true;
    }
    // ProgramData 根目录直接放置的可执行文件
    if let Some(rest) = p.strip_prefix(r"c:\programdata\") {
        return !rest.contains('\\');
    }
    // 磁盘根目录
    p.len() > 3 && p.as_bytes()[1] == b':' && !p[3..].contains('\\')
}

pub fn is_system_dir(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    let root = system_root().to_ascii_lowercase();
    p.starts_with(&format!("{root}\\system32\\"))
        || p.starts_with(&format!("{root}\\syswow64\\"))
        || p.starts_with(&format!("{root}\\winsxs\\"))
        || p.starts_with(&format!("{root}\\servicing\\"))
        || p.starts_with(&format!("{root}\\systemapps\\"))
        || p.starts_with(&format!("{root}\\microsoft.net\\"))
        || (p.starts_with(&format!("{root}\\")) && !p[root.len() + 1..].contains('\\'))
}


pub fn file_times(path: &Path) -> (Option<Time>, Option<Time>, u64) {
    match std::fs::metadata(path) {
        Ok(m) => (
            m.created().ok().and_then(systime_to_local),
            m.modified().ok().and_then(systime_to_local),
            m.len(),
        ),
        Err(_) => (None, None, 0),
    }
}


/// 所有本地用户配置文件目录（C:\Users\xxx）。
pub fn user_profiles() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(key) = reg_open(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
    ) {
        for sid in reg_subkeys(&key) {
            if !sid.starts_with("S-1-5-21-") {
                continue;
            }
            if let Ok(sub) = key.open_subkey_with_flags(&sid, KEY_READ) {
                if let Some(p) = key_str(&sub, "ProfileImagePath") {
                    let p = std::path::PathBuf::from(expand_env(&p));
                    if p.is_dir() {
                        out.push(p);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        let base = format!("{}\\Users", system_drive());
        if let Ok(rd) = std::fs::read_dir(base) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_ascii_lowercase();
                if e.path().is_dir() && !["public", "default", "default user", "all users"].contains(&n.as_str()) {
                    out.push(e.path());
                }
            }
        }
    }
    out
}

pub fn sha256_file(path: &Path, max_bytes: u64) -> String {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let Ok(meta) = std::fs::metadata(path) else {
        return String::new();
    };
    if meta.len() > max_bytes {
        return String::new();
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return String::new(),
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(&std::net::IpAddr::V4(v4));
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xffc0) == 0xfe80
                || (seg[0] & 0xfe00) == 0xfc00
        }
    }
}

pub fn is_private_ip_str(s: &str) -> bool {
    s.parse::<std::net::IpAddr>()
        .map(|ip| is_private_ip(&ip))
        .unwrap_or(true)
}
