//! 补充的自启动位置（参考 Kansa / Velociraptor / KapeFiles / 应急响应笔记等公开清单整理）。
//! 只读取配置并标记异常，不做任何修改。

use std::path::Path;

use winreg::enums::KEY_READ;

use super::persistence::{assess_command, item, user_hives};
use super::signature;
use super::util::*;
use crate::model::{PersistItem, PersistKind, Severity, SignState};

pub(super) fn collect(out: &mut Vec<PersistItem>) {
    failure_commands(out);
    logon_scripts(out);
    ps_profiles(out);
    session_manager(out);
    wow64(out);
    print_monitors(out);
    time_providers(out);
    active_setup(out);
    file_assoc(out);
    screensavers(out);
    port_proxy(out);
    firewall_rules(out);
}

fn bump(it: &mut PersistItem, sev: Severity, why: &str) {
    if sev > it.risk {
        it.risk = sev;
    }
    it.reasons.push(why.to_string());
}

/// DLL 类条目：不在系统目录或未签名即提示。
fn assess_dll(it: &mut PersistItem, dll: &str) {
    let path = resolve_exe(&normalize_nt_path(dll));
    it.image = path.clone();
    if !path.contains('\\') {
        return;
    }
    if is_suspicious_dir(&path) {
        bump(it, Severity::High, "DLL 位于临时/公共/用户可写目录");
    } else if !is_system_dir(&path) {
        bump(it, Severity::Medium, "DLL 不在系统目录");
    }
    it.sign = signature::check(&path);
    match it.sign {
        SignState::Unsigned => bump(it, Severity::High, "DLL 无有效数字签名"),
        SignState::Missing => bump(it, Severity::Low, "DLL 文件不存在"),
        _ => {}
    }
}

// ---------------------------------------------------------------- 服务故障恢复命令

fn failure_commands(out: &mut Vec<PersistItem>) {
    let base = r"SYSTEM\CurrentControlSet\Services";
    let Some(root) = reg_open("HKLM", base) else { return };
    for name in reg_subkeys(&root) {
        let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Some(cmd) = key_str(&k, "FailureCommand").filter(|c| !c.trim().is_empty()) else { continue };
        // FailureActions: 20 字节头（重置周期、重启消息、命令、动作数、动作指针）+ N 个 SC_ACTION{Type, Delay}
        // 只有动作类型为 3 (SC_ACTION_RUN_COMMAND) 时命令才会被执行
        let runs = k
            .get_raw_value("FailureActions")
            .ok()
            .map(|v| {
                let b: &[u8] = &v.bytes;
                let n = if b.len() >= 16 { u32::from_le_bytes([b[12], b[13], b[14], b[15]]) as usize } else { 0 };
                (0..n.min(16)).any(|i| {
                    let o = 20 + i * 8;
                    b.len() >= o + 4 && u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) == 3
                })
            })
            .unwrap_or(false);
        if !runs {
            continue;
        }
        let mut it = item(PersistKind::FailureCommand, &name, &format!("HKLM\\{base}\\{name}"), &cmd);
        it.time = key_last_write(&k);
        assess_command(&mut it);
        bump(&mut it, Severity::Low, "服务崩溃后会执行该命令");
        out.push(it);
    }
}

// ---------------------------------------------------------------- 登录脚本 / 组策略脚本

fn logon_scripts(out: &mut Vec<PersistItem>) {
    let domain_joined = reg_str("HKLM", r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Domain")
        .map(|d| !d.trim().is_empty())
        .unwrap_or(false);
    for (label, sid) in user_hives() {
        let p = format!(r"{sid}\Environment");
        if let Some(v) = reg_str("HKU", &p, "UserInitMprLogonScript").filter(|v| !v.trim().is_empty()) {
            let mut it = item(PersistKind::LogonScript, "UserInitMprLogonScript", &format!("{label}\\Environment"), &v);
            assess_command(&mut it);
            bump(&mut it, Severity::High, "用户环境变量中配置了登录脚本");
            out.push(it);
        }
        for kind in ["Logon", "Logoff"] {
            gp_script_keys(out, "HKU", &format!(r"{sid}\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\{kind}"), &label, domain_joined);
        }
    }
    for kind in ["Startup", "Shutdown"] {
        gp_script_keys(out, "HKLM", &format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\{kind}"), "HKLM", domain_joined);
    }
    // 本地组策略脚本配置文件
    for scope in ["Machine", "User"] {
        for file in ["scripts.ini", "psscripts.ini"] {
            let p = format!(r"{}\System32\GroupPolicy\{scope}\Scripts\{file}", system_root());
            let Some(text) = read_text_any(Path::new(&p)) else { continue };
            let mut section = String::new();
            for line in text.lines() {
                let l = line.trim();
                if l.starts_with('[') {
                    section = l.trim_matches(['[', ']']).to_string();
                    continue;
                }
                let Some((k, v)) = l.split_once('=') else { continue };
                if !k.to_ascii_lowercase().ends_with("cmdline") || v.trim().is_empty() {
                    continue;
                }
                let mut it = item(PersistKind::LogonScript, &format!("{scope} {section}"), &p, v.trim());
                it.time = file_times(Path::new(&p)).1;
                assess_command(&mut it);
                if !domain_joined {
                    bump(&mut it, Severity::Medium, "非域环境下配置了本地组策略脚本");
                }
                out.push(it);
            }
        }
    }
}

fn gp_script_keys(out: &mut Vec<PersistItem>, root: &str, path: &str, label: &str, domain_joined: bool) {
    let Some(k) = reg_open(root, path) else { return };
    for gpo in reg_subkeys(&k) {
        let Ok(gk) = k.open_subkey_with_flags(&gpo, KEY_READ) else { continue };
        for idx in reg_subkeys(&gk) {
            let Ok(sk) = gk.open_subkey_with_flags(&idx, KEY_READ) else { continue };
            let script = key_str(&sk, "Script").unwrap_or_default();
            if script.trim().is_empty() {
                continue;
            }
            let params = key_str(&sk, "Parameters").unwrap_or_default();
            let cmd = format!("{script} {params}").trim().to_string();
            let mut it = item(PersistKind::LogonScript, &format!("{}\\{gpo}\\{idx}", path.rsplit('\\').next().unwrap_or("")), &format!("{label}\\...\\{path}"), &cmd);
            it.time = key_last_write(&sk);
            assess_command(&mut it);
            if !domain_joined {
                bump(&mut it, Severity::Medium, "非域环境下存在组策略脚本");
            }
            out.push(it);
        }
    }
}

// ---------------------------------------------------------------- PowerShell 配置文件

fn ps_profiles(out: &mut Vec<PersistItem>) {
    let root = system_root();
    let mut files = vec![
        format!(r"{root}\System32\WindowsPowerShell\v1.0\profile.ps1"),
        format!(r"{root}\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"),
        format!(r"{root}\SysWOW64\WindowsPowerShell\v1.0\profile.ps1"),
        format!(r"{root}\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"),
        r"C:\Program Files\PowerShell\7\profile.ps1".to_string(),
        r"C:\Program Files\PowerShell\7\Microsoft.PowerShell_profile.ps1".to_string(),
    ];
    for p in user_profiles() {
        for dir in ["WindowsPowerShell", "PowerShell"] {
            for f in ["profile.ps1", "Microsoft.PowerShell_profile.ps1", "Microsoft.VSCode_profile.ps1"] {
                files.push(p.join("Documents").join(dir).join(f).display().to_string());
            }
        }
    }
    for f in files {
        let path = Path::new(&f);
        if !path.is_file() {
            continue;
        }
        let (_, modified, size) = file_times(path);
        let mut it = item(PersistKind::PsProfile, &file_name_of(&f), &f, &f);
        it.image = String::new();
        it.time = modified;
        it.extra = format!("大小 {size} 字节，每次启动 PowerShell 时自动加载");
        let system_wide = f.to_ascii_lowercase().starts_with(&root.to_ascii_lowercase()) || f.contains("Program Files");
        bump(&mut it, if system_wide { Severity::Medium } else { Severity::Low }, if system_wide { "存在全局 PowerShell 配置文件" } else { "存在用户 PowerShell 配置文件" });
        out.push(it);
    }
}

fn file_name_of(p: &str) -> String {
    p.rsplit('\\').next().unwrap_or(p).to_string()
}

// ---------------------------------------------------------------- Session Manager / WOW64

fn session_manager(out: &mut Vec<PersistItem>) {
    let sm = r"SYSTEM\CurrentControlSet\Control\Session Manager";
    if let Some(k) = reg_open("HKLM", &format!(r"{sm}\AppCertDlls")) {
        for (name, v) in reg_values(&k) {
            if v.trim().is_empty() {
                continue;
            }
            let mut it = item(PersistKind::AppCertDlls, &name, &format!(r"HKLM\{sm}\AppCertDlls"), &v);
            assess_dll(&mut it, &v);
            bump(&mut it, Severity::High, "AppCertDlls 会被注入到创建进程的程序中");
            out.push(it);
        }
    }
    if let Some(v) = reg_str("HKLM", sm, "ExcludeFromKnownDlls").filter(|v| !v.trim().is_empty()) {
        let mut it = item(PersistKind::KnownDlls, "ExcludeFromKnownDlls", &format!(r"HKLM\{sm}"), &v);
        it.image = String::new();
        bump(&mut it, Severity::Medium, "系统 DLL 被排除出 KnownDlls，存在 DLL 搜索顺序劫持风险");
        out.push(it);
    }
}

fn wow64(out: &mut Vec<PersistItem>) {
    let p = r"SOFTWARE\Microsoft\Wow64\x86";
    let Some(k) = reg_open("HKLM", p) else { return };
    let v = key_str(&k, "").unwrap_or_default();
    if v.is_empty() {
        return;
    }
    let ok = ["wow64cpu.dll", "xtajit.dll", "xtajit64.dll", "wowarmhw.dll"].contains(&v.trim().to_ascii_lowercase().as_str());
    if !ok {
        let mut it = item(PersistKind::Wow64, "x86 (默认)", &format!(r"HKLM\{p}"), &v);
        assess_dll(&mut it, &v);
        bump(&mut it, Severity::High, "WOW64 模拟层 DLL 非默认值");
        out.push(it);
    }
}

// ---------------------------------------------------------------- 打印监视器 / 时间提供程序

fn print_monitors(out: &mut Vec<PersistItem>) {
    let base = r"SYSTEM\CurrentControlSet\Control\Print\Monitors";
    let Some(root) = reg_open("HKLM", base) else { return };
    for name in reg_subkeys(&root) {
        let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Some(drv) = key_str(&k, "Driver").filter(|d| !d.trim().is_empty()) else { continue };
        let mut it = item(PersistKind::PrintMonitor, &name, &format!(r"HKLM\{base}\{name}"), &drv);
        it.time = key_last_write(&k);
        assess_dll(&mut it, &drv);
        if it.risk >= Severity::Medium {
            out.push(it);
        }
    }
}

fn time_providers(out: &mut Vec<PersistItem>) {
    let base = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders";
    let Some(root) = reg_open("HKLM", base) else { return };
    for name in reg_subkeys(&root) {
        let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Some(dll) = key_str(&k, "DllName").filter(|d| !d.trim().is_empty()) else { continue };
        let mut it = item(PersistKind::TimeProvider, &name, &format!(r"HKLM\{base}\{name}"), &dll);
        it.time = key_last_write(&k);
        assess_dll(&mut it, &dll);
        if it.risk >= Severity::Medium {
            out.push(it);
        }
    }
}

// ---------------------------------------------------------------- Active Setup / 文件关联 / 屏保

fn active_setup(out: &mut Vec<PersistItem>) {
    for base in [
        r"SOFTWARE\Microsoft\Active Setup\Installed Components",
        r"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components",
    ] {
        let Some(root) = reg_open("HKLM", base) else { continue };
        for id in reg_subkeys(&root) {
            let Ok(k) = root.open_subkey_with_flags(&id, KEY_READ) else { continue };
            let Some(stub) = key_str(&k, "StubPath").filter(|s| !s.trim().is_empty()) else { continue };
            let name = key_str(&k, "").filter(|s| !s.is_empty()).unwrap_or(id.clone());
            let mut it = item(PersistKind::ActiveSetup, &name, &format!(r"HKLM\{base}\{id}"), &stub);
            it.time = key_last_write(&k);
            assess_command(&mut it);
            if it.risk >= Severity::Low {
                out.push(it);
            }
        }
    }
}

fn file_assoc(out: &mut Vec<PersistItem>) {
    for class in ["exefile", "comfile", "batfile", "cmdfile", "piffile"] {
        let p = format!(r"SOFTWARE\Classes\{class}\shell\open\command");
        if let Some(v) = reg_str("HKLM", &p, "") {
            let norm: String = v.split_whitespace().collect::<Vec<_>>().join(" ");
            if norm != "\"%1\" %*" && !norm.is_empty() {
                let mut it = item(PersistKind::FileAssoc, class, &format!(r"HKLM\{p}"), &v);
                assess_command(&mut it);
                bump(&mut it, Severity::High, "可执行文件的打开方式被修改（默认 \"%1\" %*）");
                out.push(it);
            }
        }
        for (label, sid) in user_hives() {
            let up = format!(r"{sid}\Software\Classes\{class}\shell\open\command");
            if let Some(v) = reg_str("HKU", &up, "") {
                let mut it = item(PersistKind::FileAssoc, class, &format!(r"{label}\Software\Classes\{class}\shell\open\command"), &v);
                assess_command(&mut it);
                bump(&mut it, Severity::High, "用户级覆盖了可执行文件的打开方式");
                out.push(it);
            }
        }
    }
}

fn screensavers(out: &mut Vec<PersistItem>) {
    for (label, sid) in user_hives() {
        let p = format!(r"{sid}\Control Panel\Desktop");
        let Some(v) = reg_str("HKU", &p, "SCRNSAVE.EXE").filter(|v| !v.trim().is_empty()) else { continue };
        let path = resolve_exe(&normalize_nt_path(&v));
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".scr") && is_system_dir(&lower) {
            continue;
        }
        let mut it = item(PersistKind::ScreenSaver, "SCRNSAVE.EXE", &format!(r"{label}\Control Panel\Desktop"), &v);
        it.image = path.clone();
        assess_command(&mut it);
        bump(&mut it, Severity::Medium, "屏幕保护程序不是系统目录下的 .scr 文件");
        out.push(it);
    }
}

// ---------------------------------------------------------------- 端口转发 / 防火墙放行

fn port_proxy(out: &mut Vec<PersistItem>) {
    let base = r"SYSTEM\CurrentControlSet\Services\PortProxy";
    for kind in ["v4tov4", "v4tov6", "v6tov4", "v6tov6"] {
        let p = format!(r"{base}\{kind}\tcp");
        let Some(k) = reg_open("HKLM", &p) else { continue };
        let t = key_last_write(&k);
        for (listen, connect) in reg_values(&k) {
            let mut it = item(PersistKind::PortProxy, &format!("{listen} → {connect}"), &format!(r"HKLM\{p}"), &format!("netsh interface portproxy {kind} listen={listen} connect={connect}"));
            it.image = String::new();
            it.time = t;
            bump(&mut it, Severity::High, "存在系统级端口转发规则，可能被用于流量中转");
            out.push(it);
        }
    }
}

fn firewall_rules(out: &mut Vec<PersistItem>) {
    let p = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
    let Some(k) = reg_open("HKLM", p) else { return };
    let mut seen = std::collections::HashSet::new();
    for (id, v) in reg_values(&k) {
        let mut fields = std::collections::HashMap::new();
        for part in v.split('|') {
            if let Some((a, b)) = part.split_once('=') {
                fields.entry(a.to_string()).or_insert_with(|| b.to_string());
            }
        }
        let get = |k: &str| fields.get(k).cloned().unwrap_or_default();
        if !get("Action").eq_ignore_ascii_case("Allow") || !get("Dir").eq_ignore_ascii_case("In") || !get("Active").eq_ignore_ascii_case("TRUE") {
            continue;
        }
        let app = get("App");
        if app.is_empty() {
            continue;
        }
        let path = expand_env(&app);
        if !seen.insert(path.to_ascii_lowercase()) {
            continue;
        }
        let name = {
            let n = get("Name");
            if n.is_empty() || n.starts_with('@') { id.clone() } else { n }
        };
        let mut it = item(PersistKind::FirewallRule, &name, &format!(r"HKLM\{p}"), &path);
        it.image = path.clone();
        it.extra = format!("端口:{} 协议:{} 配置文件:{}", if get("LPort").is_empty() { "全部".into() } else { get("LPort") }, get("Protocol"), if get("Profile").is_empty() { "全部".into() } else { get("Profile") });
        if !is_system_dir(&path) {
            it.sign = signature::check(&path);
        }
        let unsigned = it.sign == SignState::Unsigned;
        if is_suspicious_dir(&path) {
            let sev = if unsigned { Severity::Medium } else { Severity::Low };
            bump(&mut it, sev, "入站放行规则指向用户可写目录中的程序");
        } else if unsigned {
            bump(&mut it, Severity::Low, "入站放行规则指向无签名程序");
        }
        if it.risk >= Severity::Low {
            out.push(it);
        }
    }
}
