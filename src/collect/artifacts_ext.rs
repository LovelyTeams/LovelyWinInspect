//! 补充的用户活动 / 执行痕迹：BAM、运行对话框、RDP 外连记录、近期安装软件、USB 设备。

use winreg::enums::KEY_READ;

use super::persistence::user_hives;
use super::signature;
use super::util::*;
use crate::model::{ArtifactKind, FileArtifact, Severity, ShadowCopy, SignState, Time};

pub(super) fn collect(out: &mut Vec<FileArtifact>, since: Time) {
    bam(out, since);
    run_mru(out);
    rdp_outbound(out);
    software(out, since);
    usb(out);
}

fn artifact(kind: ArtifactKind, name: &str, path: &str) -> FileArtifact {
    FileArtifact {
        kind,
        path: path.to_string(),
        name: name.to_string(),
        size: 0,
        created: None,
        modified: None,
        sign: SignState::NotChecked,
        sha256: String::new(),
        note: String::new(),
        origin: String::new(),
        streams: Vec::new(),
        risk: Severity::Info,
        reasons: Vec::new(),
    }
}

/// 只读列举卷影副本（需要管理员权限；None 表示无法读取）。
pub(super) fn shadow_copies() -> Option<Vec<ShadowCopy>> {
    let ps = r#"
$vol = @{}
Get-CimInstance Win32_Volume | ForEach-Object { $vol[[string]$_.DeviceID] = [string]$_.DriveLetter }
try {
  $items = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | ForEach-Object {
    @{ id = [string]$_.ID; vol = [string]$_.VolumeName; drive = [string]$vol[[string]$_.VolumeName]; dev = [string]$_.DeviceObject; t = $(if ($_.InstallDate) { $_.InstallDate.ToString('o') } else { '' }) } })
  @{ ok = $true; items = $items } | ConvertTo-Json -Depth 3 -Compress
} catch { '{"ok":false}' }
"#;
    let text = run_powershell(ps)?;
    let v: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
        return None;
    }
    let items = match v.get("items") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(o @ serde_json::Value::Object(_)) => vec![o.clone()],
        _ => vec![],
    };
    let s = |o: &serde_json::Value, k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut out: Vec<ShadowCopy> = items
        .iter()
        .map(|o| {
            let drive = s(o, "drive");
            ShadowCopy {
                id: s(o, "id"),
                volume: if drive.is_empty() { s(o, "vol") } else { drive },
                device: s(o, "dev"),
                created: parse_rfc3339_local(&s(o, "t")),
            }
        })
        .collect();
    out.sort_by(|a, b| b.created.cmp(&a.created));
    Some(out)
}

/// \Device\HarddiskVolumeN → 盘符 的映射。
fn device_map() -> Vec<(String, String)> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut v = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let w = wide(&drive);
        let mut buf = vec![0u16; 512];
        let n = unsafe { QueryDosDeviceW(windows::core::PCWSTR(w.as_ptr()), Some(&mut buf)) };
        if n > 0 {
            let dev = from_wide(&buf);
            if !dev.is_empty() {
                v.push((dev.to_ascii_lowercase(), drive));
            }
        }
    }
    v
}

fn bam(out: &mut Vec<FileArtifact>, since: Time) {
    let map = device_map();
    for base in [r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", r"SYSTEM\CurrentControlSet\Services\bam\UserSettings"] {
        let Some(root) = reg_open("HKLM", base) else { continue };
        for sid in reg_subkeys(&root) {
            let Ok(k) = root.open_subkey_with_flags(&sid, KEY_READ) else { continue };
            for r in k.enum_values().flatten() {
                let (name, val) = r;
                if !name.starts_with('\\') || val.bytes.len() < 8 {
                    continue;
                }
                let mut ft = [0u8; 8];
                ft.copy_from_slice(&val.bytes[..8]);
                let Some(t) = filetime_ticks_to_local(u64::from_le_bytes(ft)) else { continue };
                if t < since {
                    continue;
                }
                let lower = name.to_ascii_lowercase();
                let path = map
                    .iter()
                    .find(|(dev, _)| lower.starts_with(&format!("{dev}\\")))
                    .map(|(dev, drive)| format!("{drive}{}", &name[dev.len()..]))
                    .unwrap_or(name.clone());
                let mut a = artifact(ArtifactKind::Bam, &path.rsplit('\\').next().unwrap_or(&path).to_string(), &path);
                a.modified = Some(t);
                a.note = format!("用户 SID {} 最后执行时间", sid.rsplit('-').next().unwrap_or(&sid));
                if is_suspicious_dir(&path) {
                    a.risk = Severity::Low;
                    a.reasons.push("曾从临时/公共/用户可写目录执行".into());
                    if path.to_ascii_lowercase().ends_with(".exe") {
                        a.sign = signature::check(&path);
                        if a.sign == SignState::Unsigned {
                            a.risk = Severity::Medium;
                            a.reasons.push("程序无有效签名".into());
                        }
                    }
                }
                out.push(a);
            }
        }
    }
}

fn run_mru(out: &mut Vec<FileArtifact>) {
    for (label, sid) in user_hives() {
        let p = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
        let Some(k) = reg_open("HKU", &p) else { continue };
        let t = key_last_write(&k);
        let order = key_str(&k, "MRUList").unwrap_or_default();
        for (name, v) in reg_values(&k) {
            if name == "MRUList" {
                continue;
            }
            let cmd = v.trim_end_matches("\\1").to_string();
            let mut a = artifact(ArtifactKind::RunMru, &cmd, &format!("{label}\\...\\RunMRU"));
            // 只有排在第一位的条目能确定时间（键最后写入时间）
            if order.starts_with(&name) {
                a.modified = t;
            }
            a.note = format!("Win+R 运行过: {cmd}");
            out.push(a);
        }
    }
}

fn rdp_outbound(out: &mut Vec<FileArtifact>) {
    for (label, sid) in user_hives() {
        let p = format!(r"{sid}\Software\Microsoft\Terminal Server Client\Servers");
        if let Some(k) = reg_open("HKU", &p) {
            for host in reg_subkeys(&k) {
                let Ok(sk) = k.open_subkey_with_flags(&host, KEY_READ) else { continue };
                let hint = key_str(&sk, "UsernameHint").unwrap_or_default();
                let mut a = artifact(ArtifactKind::RdpOutbound, &host, &format!("{label}\\...\\Terminal Server Client\\Servers"));
                a.modified = key_last_write(&sk);
                a.note = format!("本机曾远程桌面连接到 {host}{}", if hint.is_empty() { String::new() } else { format!("（账户 {hint}）") });
                out.push(a);
            }
        }
    }
}

fn software(out: &mut Vec<FileArtifact>, since: Time) {
    let mut roots: Vec<(String, String)> = vec![
        ("HKLM".into(), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".into()),
        ("HKLM".into(), r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall".into()),
    ];
    for (_, sid) in user_hives() {
        roots.push(("HKU".into(), format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall")));
    }
    let mut seen = std::collections::HashSet::new();
    for (root, path) in roots {
        let Some(k) = reg_open(&root, &path) else { continue };
        for id in reg_subkeys(&k) {
            let Ok(sk) = k.open_subkey_with_flags(&id, KEY_READ) else { continue };
            let Some(name) = key_str(&sk, "DisplayName").filter(|n| !n.trim().is_empty()) else { continue };
            let date = key_str(&sk, "InstallDate").unwrap_or_default();
            let t = chrono::NaiveDate::parse_from_str(date.trim(), "%Y%m%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .and_then(|d| d.and_local_timezone(chrono::Local).single())
                .or_else(|| key_last_write(&sk));
            let Some(t) = t else { continue };
            if t < since || !seen.insert(name.clone()) {
                continue;
            }
            let publisher = key_str(&sk, "Publisher").unwrap_or_default();
            let location = key_str(&sk, "InstallLocation").unwrap_or_default();
            let mut a = artifact(ArtifactKind::Software, &name, &if location.is_empty() { format!("{root}\\{path}\\{id}") } else { location.clone() });
            a.modified = Some(t);
            a.note = format!("发布者: {} 版本: {}", if publisher.is_empty() { "未知" } else { &publisher }, key_str(&sk, "DisplayVersion").unwrap_or_default());
            if publisher.trim().is_empty() {
                a.risk = Severity::Low;
                a.reasons.push("近期安装且无发布者信息".into());
            }
            if !location.is_empty() && is_suspicious_dir(&location) {
                a.risk = Severity::Low;
                a.reasons.push("安装在用户可写目录".into());
            }
            out.push(a);
        }
    }
}

fn usb(out: &mut Vec<FileArtifact>) {
    let base = r"SYSTEM\CurrentControlSet\Enum\USBSTOR";
    let Some(root) = reg_open("HKLM", base) else { return };
    for dev in reg_subkeys(&root) {
        let Ok(dk) = root.open_subkey_with_flags(&dev, KEY_READ) else { continue };
        for serial in reg_subkeys(&dk) {
            let Ok(sk) = dk.open_subkey_with_flags(&serial, KEY_READ) else { continue };
            let friendly = key_str(&sk, "FriendlyName").unwrap_or_else(|| dev.clone());
            let mut a = artifact(ArtifactKind::Usb, &friendly, &format!(r"HKLM\{base}\{dev}\{serial}"));
            a.modified = key_last_write(&sk);
            a.note = format!("序列号 {}", serial.trim_end_matches("&0"));
            out.push(a);
        }
    }
}
