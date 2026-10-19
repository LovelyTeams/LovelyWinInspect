//! 注册表取证：应急响应中常用的执行痕迹、用户活动与网络历史。
//!
//! 全部为只读枚举；原始二进制值（UserAssist、ShimCache、RecentDocs 等）在本模块内解析。

use winreg::RegKey;
use winreg::enums::KEY_READ;

use super::persistence::user_hives;
use super::util::*;
use crate::model::{RegCategory, RegItem, Severity, Time};

pub fn collect(since: Time) -> Vec<RegItem> {
    let mut out = Vec::new();
    user_assist(&mut out);
    shim_cache(&mut out);
    mui_cache(&mut out);
    recent_docs(&mut out);
    typed_paths(&mut out);
    word_wheel(&mut out);
    last_visited(&mut out);
    network_list(&mut out);
    mount_points(&mut out);
    office(&mut out);
    sysinternals(&mut out);
    key_timeline(&mut out, since);
    out
}

fn item(category: RegCategory, name: &str, location: &str) -> RegItem {
    RegItem {
        category,
        name: name.to_string(),
        value: String::new(),
        location: location.to_string(),
        user: String::new(),
        time: None,
        note: String::new(),
        risk: Severity::Info,
        reasons: Vec::new(),
    }
}

fn bump(it: &mut RegItem, sev: Severity, why: &str) {
    if sev > it.risk {
        it.risk = sev;
    }
    it.reasons.push(why.to_string());
}

/// 可写目录中的程序：执行痕迹里值得关注的信号。
fn flag_path(it: &mut RegItem, path: &str) {
    if path.is_empty() {
        return;
    }
    if is_suspicious_dir(path) {
        bump(it, Severity::Low, "程序位于临时/公共/用户可写目录");
    }
}

/// SID 末段（RID），用于在界面上区分用户。
fn user_label(sid: &str) -> String {
    sid.rsplit('-').next().unwrap_or(sid).to_string()
}

fn utf16_at(b: &[u8], off: usize, max_bytes: usize) -> String {
    let end = (off + max_bytes).min(b.len());
    if off >= end {
        return String::new();
    }
    let words: Vec<u16> = b[off..end].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let n = words.iter().position(|&w| w == 0).unwrap_or(words.len());
    String::from_utf16_lossy(&words[..n])
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(o)?, *b.get(o + 1)?, *b.get(o + 2)?, *b.get(o + 3)?]))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    let mut v = [0u8; 8];
    v.copy_from_slice(b.get(o..o + 8)?);
    Some(u64::from_le_bytes(v))
}

fn raw_value(key: &RegKey, name: &str) -> Option<Vec<u8>> {
    key.get_raw_value(name).ok().map(|v| v.bytes.into_owned())
}

// ---------------------------------------------------------------- UserAssist

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

/// UserAssist 中常见的已知文件夹 GUID。
fn expand_known_folder(s: &str) -> String {
    const MAP: &[(&str, &str)] = &[
        ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "%SystemRoot%\\System32"),
        ("{6D809377-6AF0-444B-8957-A3773F02200E}", "%ProgramFiles%"),
        ("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "%ProgramFiles(x86)%"),
        ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "%SystemRoot%"),
        ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "%SystemRoot%\\System32"),
        ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "桌面"),
        ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "文档"),
        ("{374DE290-123F-4565-9164-39C4925E467B}", "下载"),
        ("{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "开始菜单\\程序"),
        ("{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "公用开始菜单\\程序"),
        ("{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "任务栏固定项"),
    ];
    let mut out = s.to_string();
    for (guid, name) in MAP {
        if out.to_ascii_uppercase().starts_with(guid) {
            out = format!("{name}{}", &out[guid.len()..]);
            break;
        }
    }
    out
}

fn user_assist(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
        let Some(root) = reg_open("HKU", &base) else { continue };
        for guid in reg_subkeys(&root) {
            let Ok(count) = root.open_subkey_with_flags(format!(r"{guid}\Count"), KEY_READ) else { continue };
            for name in count.enum_values().flatten().map(|(n, _)| n) {
                let Some(data) = raw_value(&count, &name) else { continue };
                // Win7 及以上为 72 字节：偏移 4 运行次数，偏移 60 最后执行时间
                if data.len() < 68 {
                    continue;
                }
                let decoded = expand_known_folder(&rot13(&name));
                // UEME_CTLSESSION 等统计项不是程序
                if decoded.starts_with("UEME_") {
                    continue;
                }
                // Win7+ 结构：偏移 4 运行次数、偏移 8 获得焦点次数、偏移 60 最后执行时间
                let runs = u32_at(&data, 4).unwrap_or(0);
                let focus = u32_at(&data, 8).unwrap_or(0);
                let time = u64_at(&data, 60).and_then(filetime_ticks_to_local);
                let mut it = item(RegCategory::UserAssist, &decoded, &format!(r"{label}\...\UserAssist\{guid}\Count"));
                it.user = user_label(&sid);
                it.time = time;
                it.value = format!("运行 {runs} 次，获得焦点 {focus} 次");
                it.note = "资源管理器记录的图形界面程序启动记录".into();
                flag_path(&mut it, &expand_env(&decoded));
                out.push(it);
            }
        }
    }
}

// ---------------------------------------------------------------- ShimCache

/// 解析 Win8/10/11 的 AppCompatCache：条目以 "10ts" 开头，顺序排列。
fn parse_shimcache(data: &[u8]) -> Vec<(String, Option<Time>)> {
    const MAGIC: &[u8; 4] = b"10ts";
    let Some(mut off) = data.windows(4).position(|w| w == MAGIC) else { return Vec::new() };
    let mut out = Vec::new();
    while off + 20 <= data.len() && out.len() < 2000 {
        if &data[off..off + 4] != MAGIC {
            break;
        }
        let entry_size = match u32_at(data, off + 8) {
            Some(v) => v as usize,
            None => break,
        };
        let path_len = match data.get(off + 12..off + 14) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]) as usize,
            None => break,
        };
        let path_off = off + 14;
        if path_len == 0 || path_off + path_len > data.len() || path_len > 1024 {
            break;
        }
        let path = utf16_at(data, path_off, path_len);
        let time = u64_at(data, path_off + path_len).and_then(filetime_ticks_to_local);
        if !path.is_empty() {
            out.push((path, time));
        }
        // 条目大小从 "10ts" 之后第 12 字节起算
        let next = off + 12 + entry_size;
        if entry_size == 0 || next <= off || next > data.len() {
            break;
        }
        off = next;
    }
    out
}

fn shim_cache(out: &mut Vec<RegItem>) {
    let path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
    let Some(key) = reg_open("HKLM", path) else { return };
    let Some(data) = raw_value(&key, "AppCompatCache") else { return };
    for (p, time) in parse_shimcache(&data) {
        let clean = normalize_nt_path(&p);
        let mut it = item(RegCategory::ShimCache, &file_base(&clean), &format!(r"HKLM\{path}"));
        it.value = clean.clone();
        it.time = time;
        it.note = "ShimCache 记录（时间为文件修改时间，且仅在关机时写入注册表）".into();
        flag_path(&mut it, &clean);
        out.push(it);
    }
}

fn file_base(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

// ---------------------------------------------------------------- MuiCache / RecentDocs

fn mui_cache(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        // <SID>_Classes 与 <SID>\Software\Classes 指向同一处，取先命中的一个即可
        for base in [
            format!(r"{sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
            format!(r"{sid}\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
        ] {
            let Some(key) = reg_open("HKU", &base) else { continue };
            let t = key_last_write(&key);
            for (name, value) in reg_values(&key) {
                let Some(path) = name.strip_suffix(".FriendlyAppName") else { continue };
                let mut it = item(RegCategory::MuiCache, &file_base(path), &format!(r"{label}\...\Shell\MuiCache"));
                it.user = user_label(&sid);
                it.value = path.to_string();
                it.time = t;
                it.note = format!("程序名称：{value}");
                flag_path(&mut it, path);
                out.push(it);
            }
            break;
        }
    }
}

/// RecentDocs：根键下为全局最近文档，子键按扩展名分组。
fn recent_docs(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
        let Some(root) = reg_open("HKU", &base) else { continue };
        let mut groups: Vec<(String, RegKey)> = vec![(String::new(), root)];
        if let Some(r2) = reg_open("HKU", &base) {
            for ext in reg_subkeys(&r2) {
                if let Ok(k) = r2.open_subkey_with_flags(&ext, KEY_READ) {
                    groups.push((ext, k));
                }
            }
        }
        for (ext, key) in groups {
            let t = key_last_write(&key);
            for name in key.enum_values().flatten().map(|(n, _)| n) {
                if name == "MRUListEx" {
                    continue;
                }
                let Some(data) = raw_value(&key, &name) else { continue };
                // 值以 UTF-16 文件名开头，其后为 PIDL
                let doc = utf16_at(&data, 0, data.len());
                if doc.trim().is_empty() {
                    continue;
                }
                let where_ = if ext.is_empty() {
                    format!(r"{label}\...\Explorer\RecentDocs")
                } else {
                    format!(r"{label}\...\RecentDocs\{ext}")
                };
                let mut it = item(RegCategory::RecentDocs, &doc, &where_);
                it.user = user_label(&sid);
                it.value = if ext.is_empty() { "全部类型".into() } else { format!("扩展名 {ext}") };
                it.time = t;
                it.note = "最近打开的文档（时间为该分组的最后写入时间）".into();
                out.push(it);
            }
        }
    }
}

fn typed_paths(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths");
        let Some(key) = reg_open("HKU", &base) else { continue };
        let t = key_last_write(&key);
        for (name, value) in reg_values(&key) {
            if value.trim().is_empty() {
                continue;
            }
            let mut it = item(RegCategory::TypedPaths, &value, &format!(r"{label}\...\Explorer\TypedPaths"));
            it.user = user_label(&sid);
            it.value = name;
            it.time = t;
            it.note = "资源管理器地址栏中手动输入过的路径".into();
            if value.starts_with(r"\\") {
                bump(&mut it, Severity::Low, "手动访问过 UNC 网络路径");
            }
            out.push(it);
        }
    }
}

fn word_wheel(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery");
        let Some(key) = reg_open("HKU", &base) else { continue };
        let t = key_last_write(&key);
        for name in key.enum_values().flatten().map(|(n, _)| n) {
            if name == "MRUListEx" {
                continue;
            }
            let Some(data) = raw_value(&key, &name) else { continue };
            let term = utf16_at(&data, 0, data.len());
            if term.trim().is_empty() {
                continue;
            }
            let mut it = item(RegCategory::SearchTerm, &term, &format!(r"{label}\...\Explorer\WordWheelQuery"));
            it.user = user_label(&sid);
            it.time = t;
            it.note = "在资源管理器中搜索过的关键词".into();
            out.push(it);
        }
    }
}

fn last_visited(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let base = format!(
            r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
        );
        let Some(key) = reg_open("HKU", &base) else { continue };
        let t = key_last_write(&key);
        for name in key.enum_values().flatten().map(|(n, _)| n) {
            if name == "MRUListEx" {
                continue;
            }
            let Some(data) = raw_value(&key, &name) else { continue };
            let exe = utf16_at(&data, 0, data.len());
            if exe.trim().is_empty() {
                continue;
            }
            let mut it = item(RegCategory::FileDialog, &exe, &format!(r"{label}\...\ComDlg32\LastVisitedPidlMRU"));
            it.user = user_label(&sid);
            it.time = t;
            it.note = "曾通过该程序的打开/保存对话框浏览过文件".into();
            out.push(it);
        }
    }
}

// ---------------------------------------------------------------- 网络与挂载

/// NetworkList 中的 DateCreated / DateLastConnected 为 16 字节 SYSTEMTIME。
fn systemtime_blob(b: &[u8]) -> Option<Time> {
    if b.len() < 16 {
        return None;
    }
    let w = |i: usize| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]) as u32;
    let naive = chrono::NaiveDate::from_ymd_opt(w(0) as i32, w(1), w(3))?
        .and_hms_opt(w(4), w(5), w(6))?;
    naive.and_local_timezone(chrono::Local).single()
}

fn network_list(out: &mut Vec<RegItem>) {
    let base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList";
    // 先收集签名中的网关 MAC，便于识别同一网络
    let mut gateways: Vec<(String, String)> = Vec::new();
    for kind in ["Managed", "Unmanaged"] {
        let Some(sig) = reg_open("HKLM", &format!(r"{base}\Signatures\{kind}")) else { continue };
        for id in reg_subkeys(&sig) {
            let Ok(k) = sig.open_subkey_with_flags(&id, KEY_READ) else { continue };
            let profile = key_str(&k, "ProfileGuid").unwrap_or_default();
            let mac = raw_value(&k, "DefaultGatewayMac")
                .map(|b| b.iter().take(6).map(|x| format!("{x:02X}")).collect::<Vec<_>>().join("-"))
                .unwrap_or_default();
            if !profile.is_empty() && !mac.is_empty() {
                gateways.push((profile, mac));
            }
        }
    }
    let Some(root) = reg_open("HKLM", &format!(r"{base}\Profiles")) else { return };
    for guid in reg_subkeys(&root) {
        let Ok(k) = root.open_subkey_with_flags(&guid, KEY_READ) else { continue };
        let name = key_str(&k, "ProfileName").unwrap_or_else(|| guid.clone());
        let created = raw_value(&k, "DateCreated").and_then(|b| systemtime_blob(&b));
        let last = raw_value(&k, "DateLastConnected").and_then(|b| systemtime_blob(&b));
        let mac = gateways.iter().find(|(p, _)| p.eq_ignore_ascii_case(&guid)).map(|(_, m)| m.clone());
        let managed = key_dword(&k, "Managed").unwrap_or(0) == 1;
        let mut it = item(RegCategory::Network, &name, &format!(r"HKLM\{base}\Profiles\{guid}"));
        it.time = last;
        it.value = match &mac {
            Some(m) => format!("网关 MAC {m}"),
            None => String::new(),
        };
        it.note = format!(
            "{} | 首次连接 {} | 最后连接 {}",
            if managed { "域网络" } else { "普通网络" },
            created.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or("-".into()),
            last.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or("-".into())
        );
        out.push(it);
    }
}

fn mount_points(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2");
        let Some(root) = reg_open("HKU", &base) else { continue };
        for name in reg_subkeys(&root) {
            // ##server#share 形式为网络共享，CPC/Volume 为本地卷
            if !name.starts_with("##") {
                continue;
            }
            let share = name.trim_start_matches('#').replace('#', "\\");
            let t = root.open_subkey_with_flags(&name, KEY_READ).ok().and_then(|k| key_last_write(&k));
            let mut it = item(RegCategory::MappedDrive, &format!(r"\\{share}"), &format!(r"{label}\...\MountPoints2"));
            it.user = user_label(&sid);
            it.time = t;
            it.note = "该用户曾连接的网络共享".into();
            bump(&mut it, Severity::Low, "存在网络共享连接记录");
            out.push(it);
        }
    }
}

// ---------------------------------------------------------------- Office / Sysinternals

fn office(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let Some(root) = reg_open("HKU", &format!(r"{sid}\Software\Microsoft\Office")) else { continue };
        for ver in reg_subkeys(&root) {
            if ver.parse::<f32>().is_err() {
                continue;
            }
            for app in ["Word", "Excel", "PowerPoint", "Outlook", "Access"] {
                let sec = format!(r"{sid}\Software\Microsoft\Office\{ver}\{app}\Security");
                if let Some(k) = reg_open("HKU", &sec) {
                    // VBAWarnings: 1 = 启用所有宏（最不安全）
                    if let Some(w) = key_dword(&k, "VBAWarnings") {
                        let mut it = item(RegCategory::Office, &format!("{app} 宏安全设置"), &format!(r"{label}\...\Office\{ver}\{app}\Security"));
                        it.user = user_label(&sid);
                        it.time = key_last_write(&k);
                        it.value = match w {
                            1 => "启用所有宏".into(),
                            2 => "禁用所有宏并通知".into(),
                            3 => "仅启用数字签名的宏".into(),
                            4 => "禁用所有宏且不通知".into(),
                            other => format!("VBAWarnings={other}"),
                        };
                        if w == 1 {
                            bump(&mut it, Severity::Medium, "Office 配置为启用所有宏");
                        }
                        out.push(it);
                    }
                }
                let trusted = format!(r"{sid}\Software\Microsoft\Office\{ver}\{app}\Security\Trusted Documents\TrustRecords");
                let Some(k) = reg_open("HKU", &trusted) else { continue };
                let t = key_last_write(&k);
                for (doc, _) in reg_values(&k) {
                    let mut it = item(RegCategory::Office, &file_base(&doc), &format!(r"{label}\...\{app}\Trusted Documents"));
                    it.user = user_label(&sid);
                    it.value = doc.clone();
                    it.time = t;
                    it.note = format!("用户曾在 {app} 中信任该文档（通常意味着启用了其中的内容或宏）");
                    bump(&mut it, Severity::Low, "存在被用户信任的 Office 文档");
                    out.push(it);
                }
            }
        }
    }
}

fn sysinternals(out: &mut Vec<RegItem>) {
    for (label, sid) in user_hives() {
        let Some(root) = reg_open("HKU", &format!(r"{sid}\Software\Sysinternals")) else { continue };
        for tool in reg_subkeys(&root) {
            let t = root.open_subkey_with_flags(&tool, KEY_READ).ok().and_then(|k| key_last_write(&k));
            let mut it = item(RegCategory::ToolUsage, &tool, &format!(r"{label}\Software\Sysinternals\{tool}"));
            it.user = user_label(&sid);
            it.time = t;
            it.note = "该用户曾在本机运行过此 Sysinternals 工具（已接受许可协议）".into();
            bump(&mut it, Severity::Low, "存在系统工具使用痕迹");
            out.push(it);
        }
    }
}

// ---------------------------------------------------------------- 键写入时间线

/// 回溯期内被写入的敏感注册表位置，用于发现配置被改动的时间点。
fn key_timeline(out: &mut Vec<RegItem>, since: Time) {
    const WATCH: &[(&str, &str, &str)] = &[
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "LSA 安全配置"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "WDigest 凭据缓存配置"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "远程桌面开关"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy", "防火墙策略"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC 与系统策略"),
        ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender", "Defender 组策略"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Exclusions", "Defender 排除项"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\SafeBoot", "安全模式配置"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon 配置"),
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB 服务端配置"),
    ];
    for (root, path, desc) in WATCH {
        let Some(key) = reg_open(root, path) else { continue };
        let Some(t) = key_last_write(&key) else { continue };
        if t < since {
            continue;
        }
        let mut it = item(RegCategory::Timeline, desc, &format!(r"{root}\{path}"));
        it.time = Some(t);
        it.note = "回溯期内该敏感位置被写入，建议结合日志确认变更来源".into();
        bump(&mut it, Severity::Low, "敏感注册表位置近期被修改");
        out.push(it);
    }
}
