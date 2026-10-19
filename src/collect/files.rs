//! 文件痕迹：落地目录中近期新增的可执行/脚本文件、Web 目录近期变更、Prefetch、最近访问、Hosts、PowerShell 历史。

use std::path::{Path, PathBuf};

use super::persistence::walk;
use super::signature;
use super::util::*;
use crate::model::{ArtifactKind, FileArtifact, Severity, SignState, Time};

const EXEC_EXT: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "pif", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd",
    "jar", "msi", "sct", "lnk", "py", "cpl", "ocx",
];

fn ext_of(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn artifact(kind: ArtifactKind, p: &Path) -> FileArtifact {
    let (created, modified, size) = file_times(p);
    FileArtifact {
        kind,
        path: p.display().to_string(),
        name: p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        size,
        created,
        modified,
        sign: SignState::NotChecked,
        sha256: String::new(),
        note: String::new(),
        origin: String::new(),
        streams: Vec::new(),
        risk: Severity::Info,
        reasons: Vec::new(),
    }
}

// ---------------------------------------------------------------- 备用数据流 (ADS)

/// 常见的系统 / 同步软件元数据流，不单独提示。
const BENIGN_STREAMS: &[&str] = &["SmartScreen", "com.dropbox.attributes", "com.dropbox.attrs", "AFP_AfpInfo", "AFP_Resource", "encryptable", "ms-properties", "OECustomProperty"];

/// 文件的备用数据流（不含主数据流）：(名称, 大小)。
pub(crate) fn alt_streams(p: &Path) -> Vec<(String, i64)> {
    use windows::Win32::Storage::FileSystem::{FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, WIN32_FIND_STREAM_DATA};
    let w = wide(&p.display().to_string());
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let mut v = Vec::new();
    unsafe {
        let Ok(h) = FindFirstStreamW(windows::core::PCWSTR(w.as_ptr()), FindStreamInfoStandard, &mut data as *mut _ as *mut _, None) else {
            return v;
        };
        loop {
            // 流名形如 ":Zone.Identifier:$DATA"，主数据流为 "::$DATA"
            let name = from_wide(&data.cStreamName);
            if let Some(n) = name.strip_prefix(':').and_then(|n| n.strip_suffix(":$DATA")) {
                if !n.is_empty() {
                    v.push((n.to_string(), data.StreamSize));
                }
            }
            if v.len() >= 32 || FindNextStreamW(h, &mut data as *mut _ as *mut _).is_err() {
                break;
            }
        }
        let _ = FindClose(h);
    }
    v
}

fn stream_path(p: &Path, stream: &str) -> String {
    format!("{}:{stream}", p.display())
}

fn stream_is_pe(p: &Path, stream: &str) -> bool {
    use std::io::Read;
    let mut head = [0u8; 2];
    std::fs::File::open(stream_path(p, stream))
        .and_then(|mut f| f.read_exact(&mut head))
        .map(|_| &head == b"MZ")
        .unwrap_or(false)
}

/// Zone.Identifier → "HostUrl（来源页 ReferrerUrl，区域）"。
fn zone_origin(p: &Path) -> Option<String> {
    let bytes = std::fs::read(stream_path(p, "Zone.Identifier")).ok()?;
    let text = decode_text(&bytes[..bytes.len().min(8192)]);
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.trim().split_once('=').filter(|(n, _)| n.trim().eq_ignore_ascii_case(k)).map(|(_, v)| v.trim().to_string()))
            .filter(|v| !v.is_empty())
    };
    let zone = match field("ZoneId").and_then(|z| z.parse::<u32>().ok()) {
        Some(0) => "本机",
        Some(1) => "本地内网",
        Some(2) => "受信任站点",
        Some(3) => "互联网",
        Some(4) => "受限站点",
        _ => "未知区域",
    };
    let host = field("HostUrl");
    let referrer = field("ReferrerUrl");
    Some(match (host, referrer) {
        (Some(h), Some(r)) if h != r => format!("{h}（来源页 {r}，{zone}）"),
        (Some(u), _) | (None, Some(u)) => format!("{u}（{zone}）"),
        (None, None) => format!("{zone}（未记录下载地址）"),
    })
}

/// 记录下载来源与非常见备用数据流；流中含 PE 头时提示。返回是否存在非常见数据流。
fn inspect_streams(a: &mut FileArtifact, p: &Path) -> bool {
    let mut unusual = false;
    for (name, size) in alt_streams(p) {
        if name.eq_ignore_ascii_case("Zone.Identifier") {
            a.origin = zone_origin(p).unwrap_or_default();
            continue;
        }
        a.streams.push(format!("{name} ({})", size.max(0)));
        if BENIGN_STREAMS.iter().any(|b| name.eq_ignore_ascii_case(b)) {
            continue;
        }
        unusual = true;
        if size >= 64 && stream_is_pe(p, &name) {
            bump(a, Severity::Medium, format!("备用数据流 {name} 中包含可执行文件 (MZ 头)"));
        } else {
            bump(a, Severity::Info, format!("存在备用数据流 {name}"));
        }
    }
    unusual
}

fn bump(a: &mut FileArtifact, sev: Severity, why: impl Into<String>) {
    if sev > a.risk {
        a.risk = sev;
    }
    a.reasons.push(why.into());
}

pub fn collect(since: Time) -> Vec<FileArtifact> {
    let mut out = Vec::new();
    recent_drops(&mut out, since);
    web_changes(&mut out, since);
    prefetch(&mut out, since);
    recent_docs(&mut out, since);
    hosts(&mut out);
    ps_history(&mut out);
    super::artifacts_ext::collect(&mut out, since);
    out
}

fn drop_dirs() -> Vec<(PathBuf, usize)> {
    let drive = system_drive();
    let mut v = vec![
        (PathBuf::from(format!("{}\\Temp", system_root())), 3),
        (PathBuf::from(format!("{drive}\\Users\\Public")), 4),
        (PathBuf::from(format!("{drive}\\PerfLogs")), 4),
        (PathBuf::from(format!("{drive}\\ProgramData")), 1),
        (PathBuf::from(format!("{}\\Tasks", system_root())), 1),
        (PathBuf::from(format!("{}\\debug", system_root())), 2),
        (PathBuf::from(format!("{drive}\\")), 0),
    ];
    for p in user_profiles() {
        v.push((p.join("AppData\\Local\\Temp"), 3));
        v.push((p.join("Downloads"), 2));
        v.push((p.join("Desktop"), 1));
        v.push((p.join("AppData\\Roaming"), 1));
        v.push((p.join("Documents"), 1));
    }
    v
}

fn recent_drops(out: &mut Vec<FileArtifact>, since: Time) {
    let mut seen = std::collections::HashSet::new();
    let mut count = 0usize;
    for (dir, depth) in drop_dirs() {
        // 每个目录单独限额，避免某个大目录（如 Temp）占满总额导致 Downloads 等目录未被扫描
        let mut in_dir = 0usize;
        // 非可执行文件只为检查备用数据流读取时间戳，限制数量避免大目录拖慢扫描
        let mut other_budget = 4000usize;
        walk(&dir, 0, depth, &mut |p| {
            if count > 3000 || in_dir >= 500 {
                return;
            }
            let ext = ext_of(p);
            if !EXEC_EXT.contains(&ext.as_str()) {
                if other_budget == 0 || !seen.insert(p.display().to_string().to_ascii_lowercase()) {
                    return;
                }
                other_budget -= 1;
                let mut a = artifact(ArtifactKind::AltStream, p);
                if a.created.max(a.modified).map(|t| t < since).unwrap_or(true) {
                    return;
                }
                if inspect_streams(&mut a, p) {
                    count += 1;
                    in_dir += 1;
                    if a.risk >= Severity::Medium {
                        a.sha256 = sha256_file(p, 100 << 20);
                    }
                    a.note = format!("{} · 目录: {}", a.streams.join(", "), p.parent().map(|d| d.display().to_string()).unwrap_or_default());
                    out.push(a);
                }
                return;
            }
            let key = p.display().to_string().to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                return;
            }
            if key.contains("\\appdata\\roaming\\microsoft\\") && ext == "lnk" {
                return;
            }
            let fname = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            if ["pagefile.sys", "swapfile.sys", "hiberfil.sys"].contains(&fname.as_str()) {
                return;
            }
            let mut a = artifact(ArtifactKind::RecentFile, p);
            let newest = a.created.max(a.modified);
            if newest.map(|t| t < since).unwrap_or(true) {
                return;
            }
            count += 1;
            in_dir += 1;
            let name_lower = a.name.to_ascii_lowercase();
            if ["exe", "dll", "sys", "scr", "com", "cpl", "ocx"].contains(&ext.as_str()) {
                a.sign = signature::check(&a.path);
                if a.sign == SignState::Unsigned {
                    bump(&mut a, Severity::Medium, "可执行文件无有效签名");
                }
            }
            if ["ps1", "vbs", "vbe", "jse", "hta", "wsf", "sct", "bat", "cmd"].contains(&ext.as_str()) {
                bump(&mut a, Severity::Low, "临时/公共目录中的脚本文件");
            }
            // 双扩展名伪装
            let stem = name_lower.trim_end_matches(&format!(".{ext}"));
            if [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt", ".zip", ".rar"]
                .iter()
                .any(|d| stem.ends_with(d))
            {
                bump(&mut a, Severity::High, "双扩展名伪装文档");
            }
            inspect_streams(&mut a, p);
            if a.risk >= Severity::Medium {
                a.sha256 = sha256_file(p, 100 << 20);
            }
            let dir = p.parent().map(|d| d.display().to_string()).unwrap_or_default();
            a.note = if a.origin.is_empty() { format!("目录: {dir}") } else { format!("下载自 {} · 目录: {dir}", a.origin) };
            out.push(a);
        });
    }
}

/// Web 根目录中近期新增/修改的服务端脚本，供人工复核。
fn web_changes(out: &mut Vec<FileArtifact>, since: Time) {
    let drive = system_drive();
    let mut roots = vec![
        PathBuf::from(format!("{drive}\\inetpub")),
        PathBuf::from(format!("{drive}\\xampp\\htdocs")),
        PathBuf::from(format!("{drive}\\phpstudy_pro\\WWW")),
        PathBuf::from(format!("{drive}\\wamp64\\www")),
        PathBuf::from(format!("{drive}\\www")),
        PathBuf::from(format!("{drive}\\wwwroot")),
    ];
    if let Ok(rd) = std::fs::read_dir(format!("{drive}\\Program Files\\Apache Software Foundation")) {
        for e in rd.flatten() {
            roots.push(e.path().join("webapps"));
        }
    }
    let exts = ["asp", "aspx", "ashx", "asmx", "php", "jsp", "jspx"];
    let mut scanned = 0usize;
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        walk(&root, 0, 10, &mut |p| {
            if scanned > 20000 || !exts.contains(&ext_of(p).as_str()) {
                return;
            }
            scanned += 1;
            let mut a = artifact(ArtifactKind::WebChange, p);
            let newest = a.created.max(a.modified);
            if newest.map(|t| t < since).unwrap_or(true) {
                return;
            }
            bump(&mut a, Severity::Low, "Web 目录近期新增/修改的脚本，请人工复核");
            a.sha256 = sha256_file(p, 10 << 20);
            a.note = format!("Web 目录: {}", root.display());
            out.push(a);
        });
    }
}

fn prefetch(out: &mut Vec<FileArtifact>, since: Time) {
    let dir = format!("{}\\Prefetch", system_root());
    let Ok(rd) = std::fs::read_dir(&dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if ext_of(&p) != "pf" {
            continue;
        }
        let mut a = artifact(ArtifactKind::Prefetch, &p);
        if a.modified.map(|t| t < since).unwrap_or(true) {
            continue;
        }
        // 文件名形如 NOTEPAD.EXE-1A2B3C4D.pf
        let exe = a.name.rsplit_once('-').map(|(n, _)| n.to_string()).unwrap_or(a.name.clone());
        a.note = format!("程序: {exe}");
        out.push(a);
    }
}

fn recent_docs(out: &mut Vec<FileArtifact>, since: Time) {
    for profile in user_profiles() {
        let dir = profile.join("AppData\\Roaming\\Microsoft\\Windows\\Recent");
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let user = profile.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        for e in rd.flatten() {
            let p = e.path();
            if ext_of(&p) != "lnk" {
                continue;
            }
            let mut a = artifact(ArtifactKind::RecentDoc, &p);
            if a.modified.map(|t| t < since).unwrap_or(true) {
                continue;
            }
            let target = super::lnk::parse_file(&p).map(|l| l.target).unwrap_or_default();
            a.note = format!(
                "用户 {user} 访问: {}",
                if target.is_empty() { a.name.trim_end_matches(".lnk").to_string() } else { target }
            );
            out.push(a);
        }
    }
}

fn hosts(out: &mut Vec<FileArtifact>) {
    let p = PathBuf::from(format!("{}\\System32\\drivers\\etc\\hosts", system_root()));
    let Some(text) = read_text_any(&p) else { return };
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut a = artifact(ArtifactKind::Hosts, &p);
        a.note = l.to_string();
        let lower = l.to_ascii_lowercase();
        if UPDATE_DOMAINS.iter().any(|d| lower.contains(d)) {
            bump(&mut a, Severity::High, "Hosts 改写了系统更新/安全服务域名");
        } else {
            bump(&mut a, Severity::Low, "Hosts 中存在自定义解析");
        }
        out.push(a);
    }
}

fn ps_history(out: &mut Vec<FileArtifact>) {
    for profile in user_profiles() {
        let p = profile.join("AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        let Some(text) = read_text_any(&p) else { continue };
        let user = profile.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let lines = text.lines().filter(|l| !l.trim().is_empty()).count();
        let mut a = artifact(ArtifactKind::PsHistory, &p);
        a.note = format!("用户 {user} 共 {lines} 条命令历史，可在证据导出后人工审阅");
        out.push(a);
    }
}

/// 证据导出时复制的文本类证据文件。
pub fn evidence_text_files() -> Vec<(String, PathBuf)> {
    let mut v = vec![(
        "hosts.txt".to_string(),
        PathBuf::from(format!("{}\\System32\\drivers\\etc\\hosts", system_root())),
    )];
    for profile in user_profiles() {
        let user = profile.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let p = profile.join("AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        if p.is_file() {
            v.push((format!("PSHistory_{user}.txt"), p));
        }
    }
    v
}
