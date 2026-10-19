//! 受信任根证书：本机与各用户的 ROOT 存储（只读枚举），标记回溯期内新写入的自签名根证书。

use std::collections::HashSet;

use windows::Win32::Security::Cryptography::*;

use super::persistence::user_hives;
use super::util::*;
use crate::model::{PersistItem, PersistKind, Severity, SignState, Time};

/// 本机 ROOT 逻辑存储对应的物理位置（注册表）。
const LM_SOURCES: &[(&str, &str)] = &[
    ("本机", r"SOFTWARE\Microsoft\SystemCertificates\ROOT"),
    ("本机组策略", r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root"),
    ("本机企业", r"SOFTWARE\Microsoft\EnterpriseCertificates\Root"),
];

struct CertInfo {
    thumb: String,
    subject: String,
    issuer: String,
    friendly: String,
    not_before: Option<Time>,
    not_after: Option<Time>,
    self_signed: bool,
}

pub(super) fn collect(out: &mut Vec<PersistItem>, since: Time) {
    let mut seen: HashSet<String> = HashSet::new();

    // 本机 ROOT（含组策略 / 企业物理存储）
    let lm_flags = CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE);
    for c in system_store(lm_flags) {
        if !seen.insert(c.thumb.clone()) {
            continue;
        }
        let (label, path, time) = LM_SOURCES
            .iter()
            .find_map(|(label, base)| {
                let p = format!(r"{base}\Certificates\{}", c.thumb);
                reg_open("HKLM", &p).map(|k| (*label, format!(r"HKLM\{p}"), key_last_write(&k)))
            })
            .unwrap_or(("本机", r"LocalMachine\ROOT".to_string(), None));
        out.push(item(&c, &format!("{label} ROOT"), path, time, false, since));
    }

    // 各已加载用户配置单元中的用户级 ROOT
    for (_, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Microsoft\SystemCertificates\Root");
        let Some(key) = reg_open("HKU", &base) else { continue };
        let user = sid_user(&sid);
        for c in registry_store(&key) {
            if !seen.insert(c.thumb.clone()) {
                continue;
            }
            let p = format!(r"{base}\Certificates\{}", c.thumb);
            let time = reg_open("HKU", &p).and_then(|k| key_last_write(&k));
            out.push(item(&c, &format!("用户 {user} ROOT"), format!(r"HKU\{p}"), time, true, since));
        }
    }

    // 当前用户逻辑存储中剩余的（用户组策略 / 智能卡等其他物理存储）
    let cu_flags = CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER);
    for c in system_store(cu_flags) {
        if !seen.insert(c.thumb.clone()) {
            continue;
        }
        let p = format!(r"Software\Policies\Microsoft\SystemCertificates\Root\Certificates\{}", c.thumb);
        let (path, time) = match reg_open("HKCU", &p) {
            Some(k) => (format!(r"HKCU\{p}"), key_last_write(&k)),
            None => (r"CurrentUser\ROOT".to_string(), None),
        };
        out.push(item(&c, "当前用户 ROOT", path, time, true, since));
    }
}

fn item(c: &CertInfo, store: &str, location: String, time: Option<Time>, user_scope: bool, since: Time) -> PersistItem {
    let fmt_day = |t: Option<Time>| t.map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or_else(|| "?".into());
    let expired = c.not_after.map(|t| t < chrono::Local::now()).unwrap_or(false);
    let mut it = PersistItem {
        kind: PersistKind::RootCert,
        name: if c.subject.is_empty() { c.friendly.clone() } else { c.subject.clone() },
        location,
        command: format!(
            "颁发者: {} · 有效期 {} ~ {}{}",
            if c.issuer.is_empty() { "-" } else { &c.issuer },
            fmt_day(c.not_before),
            fmt_day(c.not_after),
            if expired { "（已过期）" } else { "" }
        ),
        image: String::new(),
        sign: SignState::NotChecked,
        enabled: true,
        extra: format!(
            "存储: {store} · SHA1: {} · 自签名: {}{}",
            c.thumb,
            if c.self_signed { "是" } else { "否" },
            if c.friendly.is_empty() { String::new() } else { format!(" · 友好名称: {}", c.friendly) }
        ),
        time,
        risk: Severity::Info,
        reasons: Vec::new(),
    };
    let recent = time.map(|t| t >= since).unwrap_or(false);
    if recent && c.self_signed {
        it.risk = Severity::Low;
        it.reasons.push("回溯期内新写入的自签名受信任根证书".into());
        if c.not_before.map(|t| t >= since).unwrap_or(false) {
            it.reasons.push("证书签发时间也在回溯期内（新生成的根 CA）".into());
        }
        if user_scope {
            it.reasons.push("用户级根证书，仅对该用户生效".into());
        }
    }
    it
}

/// SID → 用户配置文件目录名（用于显示）。
fn sid_user(sid: &str) -> String {
    if sid == "S-1-5-18" {
        return "SYSTEM".into();
    }
    reg_str("HKLM", &format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"), "ProfileImagePath")
        .and_then(|p| p.rsplit('\\').next().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| sid.to_string())
}

fn system_store(location: CERT_OPEN_STORE_FLAGS) -> Vec<CertInfo> {
    let name = wide("ROOT");
    let flags = CERT_OPEN_STORE_FLAGS(location.0 | CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0);
    unsafe {
        match CertOpenStore(CERT_STORE_PROV_SYSTEM_W, CERT_QUERY_ENCODING_TYPE::default(), None, flags, Some(name.as_ptr() as *const _)) {
            Ok(store) => enumerate(store),
            Err(_) => Vec::new(),
        }
    }
}

/// 直接读取某个注册表位置下的证书（用于未登录到当前进程的其他用户配置单元）。
fn registry_store(key: &winreg::RegKey) -> Vec<CertInfo> {
    let flags = CERT_OPEN_STORE_FLAGS(CERT_STORE_READONLY_FLAG.0 | CERT_STORE_OPEN_EXISTING_FLAG.0);
    unsafe {
        // 提供程序会自行复制该句柄，调用方保留所有权
        match CertOpenStore(CERT_STORE_PROV_REG, CERT_QUERY_ENCODING_TYPE::default(), None, flags, Some(key.raw_handle() as *const _)) {
            Ok(store) => enumerate(store),
            Err(_) => Vec::new(),
        }
    }
}

unsafe fn enumerate(store: HCERTSTORE) -> Vec<CertInfo> {
    let mut out = Vec::new();
    unsafe {
        let mut prev: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            // 传入上一个上下文时由系统负责释放它
            let ctx = CertEnumCertificatesInStore(store, (!prev.is_null()).then_some(prev as *const _));
            if ctx.is_null() {
                break;
            }
            if let Some(c) = read_cert(ctx) {
                out.push(c);
            }
            prev = ctx;
        }
        let _ = CertCloseStore(Some(store), 0);
    }
    out
}

unsafe fn read_cert(ctx: *const CERT_CONTEXT) -> Option<CertInfo> {
    unsafe {
        let info = (*ctx).pCertInfo.as_ref()?;
        let thumb = prop_bytes(ctx, CERT_SHA1_HASH_PROP_ID)?
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>();
        let friendly = prop_bytes(ctx, CERT_FRIENDLY_NAME_PROP_ID)
            .map(|b| {
                let words: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                from_wide(&words)
            })
            .unwrap_or_default();
        Some(CertInfo {
            thumb,
            subject: name_string(ctx, 0),
            issuer: name_string(ctx, CERT_NAME_ISSUER_FLAG),
            friendly,
            not_before: filetime_to_local(info.NotBefore),
            not_after: filetime_to_local(info.NotAfter),
            self_signed: CertCompareCertificateName(X509_ASN_ENCODING, &info.Subject, &info.Issuer).as_bool(),
        })
    }
}

unsafe fn name_string(ctx: *const CERT_CONTEXT, flags: u32) -> String {
    let mut buf = vec![0u16; 512];
    let n = unsafe { CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, Some(&mut buf)) };
    if n <= 1 { String::new() } else { from_wide(&buf) }
}

unsafe fn prop_bytes(ctx: *const CERT_CONTEXT, id: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut len = 0u32;
        CertGetCertificateContextProperty(ctx, id, None, &mut len).ok()?;
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        CertGetCertificateContextProperty(ctx, id, Some(buf.as_mut_ptr() as *mut _), &mut len).ok()?;
        buf.truncate(len as usize);
        Some(buf)
    }
}
