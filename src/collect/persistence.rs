//! 持久化项采集：注册表自启动、服务、计划任务、启动目录、映像劫持、WMI 订阅等。

use std::collections::HashMap;
use std::path::Path;

use windows::Win32::System::Services::*;
use windows::core::PCWSTR;
use winreg::enums::*;

use super::signature;
use super::util::*;
use crate::model::{PersistItem, PersistKind, Severity, SignState, Time};

pub fn collect(lookback: Time) -> Vec<PersistItem> {
    let mut out = Vec::new();
    run_keys(&mut out);
    winlogon(&mut out);
    ifeo(&mut out);
    appinit(&mut out);
    lsa(&mut out);
    boot_execute(&mut out);
    services(&mut out);
    scheduled_tasks(&mut out, lookback);
    startup_folders(&mut out);
    accessibility(&mut out);
    netsh_helpers(&mut out);
    com_hijack(&mut out);
    wmi(&mut out);
    super::persistence_ext::collect(&mut out);
    super::certs::collect(&mut out, lookback);
    out
}

pub(super) fn item(kind: PersistKind, name: &str, location: &str, command: &str) -> PersistItem {
    let image = exe_from_cmdline(command);
    PersistItem {
        kind,
        name: name.to_string(),
        location: location.to_string(),
        command: command.to_string(),
        image,
        sign: SignState::NotChecked,
        enabled: true,
        extra: String::new(),
        time: None,
        risk: Severity::Info,
        reasons: Vec::new(),
    }
}

/// 通用的命令/镜像研判：可疑目录、脚本引擎、编码命令、签名、文件缺失。
pub fn assess_command(it: &mut PersistItem) {
    let cmd = it.command.to_ascii_lowercase();
    let image_lower = it.image.to_ascii_lowercase();
    let bump = |it: &mut PersistItem, sev: Severity, why: &str| {
        if sev > it.risk {
            it.risk = sev;
        }
        it.reasons.push(why.to_string());
    };

    // rundll32/regsvr32 加载的真实 DLL
    let mut target = it.image.clone();
    if image_lower.ends_with("rundll32.exe") || image_lower.ends_with("regsvr32.exe") {
        if let Some(dll) = dll_from_loader(&it.command) {
            target = dll;
        }
    }

    if is_suspicious_dir(&target) {
        bump(it, Severity::High, "程序位于临时/公共/用户可写目录");
    }
    let engines = ["powershell", "pwsh", "mshta", "wscript", "cscript", "cmd.exe /c", "cmd /c"];
    if engines.iter().any(|e| cmd.contains(e)) && it.risk < Severity::Medium {
        bump(it, Severity::Medium, "通过脚本解释器/系统工具启动");
    }

    if !target.is_empty() && target.contains('\\') {
        let st = signature::check(&target);
        it.sign = st;
        match st {
            SignState::Unsigned => {
                let sev = if is_system_dir(&target) { Severity::High } else { Severity::Medium };
                bump(it, sev, "目标程序无有效数字签名");
            }
            SignState::Missing => bump(it, Severity::Low, "目标文件不存在（可能已被清理）"),
            _ => {}
        }
    }
}

fn dll_from_loader(cmd: &str) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();
    let pos = lower.find(".dll")?;
    let before = &cmd[..pos + 4];
    let start = before
        .rfind(['"', ' ', ','])
        .map(|i| i + 1)
        .unwrap_or(0);
    let p = before[start..].trim_matches('"');
    Some(resolve_exe(p))
}

// ---------------------------------------------------------------- 注册表 Run

pub(super) fn user_hives() -> Vec<(String, String)> {
    // (显示名, HKU 下的子键前缀)
    let mut v = Vec::new();
    if let Some(hku) = reg_open("HKU", "") {
        for sid in reg_subkeys(&hku) {
            if (sid.starts_with("S-1-5-21-") || sid == "S-1-5-18") && !sid.ends_with("_Classes") {
                v.push((format!("HKU\\{sid}"), sid));
            }
        }
    }
    v
}

fn startup_approved(root: &str, base: &str, sub: &str, name: &str) -> bool {
    let path = format!("{base}\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\{sub}");
    if let Some(k) = reg_open(root, &path) {
        if let Ok(v) = k.get_raw_value(name) {
            if let Some(b) = v.bytes.first() {
                return b & 1 == 0;
            }
        }
    }
    true
}

fn run_keys(out: &mut Vec<PersistItem>) {
    let mut sources: Vec<(String, String, String)> = vec![]; // (root, path, label)
    let hklm_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ];
    for p in hklm_paths {
        sources.push(("HKLM".into(), p.into(), format!("HKLM\\{p}")));
    }
    let user_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ];
    for (label, sid) in user_hives() {
        for p in user_paths {
            sources.push(("HKU".into(), format!("{sid}\\{p}"), format!("{label}\\{p}")));
        }
    }

    for (root, path, label) in sources {
        let Some(key) = reg_open(&root, &path) else { continue };
        let t = key_last_write(&key);
        for (name, value) in reg_values(&key) {
            if value.trim().is_empty() {
                continue;
            }
            let mut it = item(PersistKind::RunKey, &name, &label, &value);
            it.time = t;
            if path.ends_with("\\Run") {
                let (r, base) = if root == "HKLM" {
                    ("HKLM", "SOFTWARE".to_string())
                } else {
                    let sid = path.split('\\').next().unwrap_or("");
                    ("HKU", format!("{sid}\\Software"))
                };
                let sub = if path.contains("WOW6432Node") { "Run32" } else { "Run" };
                it.enabled = startup_approved(r, &base, sub, &name);
            }
            assess_command(&mut it);
            out.push(it);
        }
        // RunOnceEx 子键
        if path.ends_with("RunOnceEx") {
            for sub in reg_subkeys(&key) {
                if let Ok(sk) = key.open_subkey_with_flags(&sub, KEY_READ) {
                    for (name, value) in reg_values(&sk) {
                        let mut it = item(PersistKind::RunKey, &format!("{sub}\\{name}"), &label, &value);
                        it.time = t;
                        assess_command(&mut it);
                        out.push(it);
                    }
                }
            }
        }
    }

    // Windows NT\CurrentVersion\Windows 下的 Load / Run
    for (label, sid) in user_hives() {
        let p = format!(r"{sid}\Software\Microsoft\Windows NT\CurrentVersion\Windows");
        if let Some(k) = reg_open("HKU", &p) {
            for name in ["Load", "Run"] {
                if let Some(v) = key_str(&k, name).filter(|v| !v.trim().is_empty()) {
                    let mut it = item(PersistKind::RunKey, name, &format!("{label}\\...\\Windows"), &v);
                    assess_command(&mut it);
                    if it.risk < Severity::Medium {
                        it.risk = Severity::Medium;
                        it.reasons.push("罕见的 Load/Run 自启动位置".into());
                    }
                    out.push(it);
                }
            }
        }
    }
}

// ---------------------------------------------------------------- Winlogon / IFEO / AppInit / LSA

fn winlogon(out: &mut Vec<PersistItem>) {
    let path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    if let Some(k) = reg_open("HKLM", path) {
        let shell = key_str(&k, "Shell").unwrap_or_default();
        let mut it = item(PersistKind::Winlogon, "Shell", &format!("HKLM\\{path}"), &shell);
        if !shell.trim().eq_ignore_ascii_case("explorer.exe") && !shell.is_empty() {
            it.risk = Severity::Critical;
            it.reasons.push("Winlogon Shell 被篡改（默认 explorer.exe）".into());
        }
        out.push(it);

        let ui = key_str(&k, "Userinit").unwrap_or_default();
        let mut it = item(PersistKind::Winlogon, "Userinit", &format!("HKLM\\{path}"), &ui);
        let parts: Vec<String> = ui
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let ok = parts.len() == 1 && parts[0].ends_with("\\system32\\userinit.exe");
        if !ok && !ui.is_empty() {
            it.risk = Severity::Critical;
            it.reasons.push("Userinit 中追加了额外程序".into());
        }
        out.push(it);

        for extra in ["Taskman", "AppSetup", "GinaDLL"] {
            if let Some(v) = key_str(&k, extra).filter(|v| !v.is_empty()) {
                let mut it = item(PersistKind::Winlogon, extra, &format!("HKLM\\{path}"), &v);
                it.risk = Severity::High;
                it.reasons.push("非默认的 Winlogon 启动值".into());
                out.push(it);
            }
        }
    }
    for (label, sid) in user_hives() {
        let p = format!(r"{sid}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon");
        if let Some(k) = reg_open("HKU", &p) {
            if let Some(v) = key_str(&k, "Shell").filter(|v| !v.is_empty()) {
                let mut it = item(PersistKind::Winlogon, "Shell (用户级)", &format!("{label}\\...\\Winlogon"), &v);
                it.risk = Severity::Critical;
                it.reasons.push("用户级 Winlogon Shell 覆盖".into());
                out.push(it);
            }
        }
    }
}

const ACCESSIBILITY: &[&str] = &[
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "narrator.exe",
    "magnify.exe",
    "displayswitch.exe",
    "atbroker.exe",
];

fn ifeo(out: &mut Vec<PersistItem>) {
    for base in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    ] {
        let Some(root) = reg_open("HKLM", base) else { continue };
        for name in reg_subkeys(&root) {
            let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
            if let Some(dbg) = key_str(&k, "Debugger").filter(|v| !v.trim().is_empty()) {
                let mut it = item(PersistKind::Ifeo, &name, &format!("HKLM\\{base}\\{name}"), &dbg);
                it.time = key_last_write(&k);
                if ACCESSIBILITY.contains(&name.to_ascii_lowercase().as_str()) {
                    it.risk = Severity::Critical;
                    it.reasons.push("辅助功能程序设置了映像劫持".into());
                } else {
                    it.risk = Severity::High;
                    it.reasons.push("设置了 IFEO Debugger 映像劫持".into());
                }
                assess_command(&mut it);
                out.push(it);
            }
            if let Some(gf) = key_dword(&k, "GlobalFlag") {
                if gf & 0x200 != 0 {
                    let sp = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{name}");
                    if let Some(mp) = reg_str("HKLM", &sp, "MonitorProcess") {
                        let mut it = item(PersistKind::Ifeo, &format!("{name} (SilentProcessExit)"), &format!("HKLM\\{sp}"), &mp);
                        it.risk = Severity::High;
                        it.reasons.push("利用静默进程退出监控实现持久化".into());
                        assess_command(&mut it);
                        out.push(it);
                    }
                }
            }
        }
    }
}

fn appinit(out: &mut Vec<PersistItem>) {
    for base in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ] {
        if let Some(k) = reg_open("HKLM", base) {
            let dlls = key_str(&k, "AppInit_DLLs").unwrap_or_default();
            if dlls.trim().is_empty() {
                continue;
            }
            let load = key_dword(&k, "LoadAppInit_DLLs").unwrap_or(0);
            let mut it = item(PersistKind::AppInit, "AppInit_DLLs", &format!("HKLM\\{base}"), &dlls);
            it.enabled = load == 1;
            it.risk = if load == 1 { Severity::High } else { Severity::Low };
            it.reasons.push("配置了 AppInit_DLLs，DLL 将注入所有 GUI 进程".into());
            out.push(it);
        }
    }
}

fn lsa(out: &mut Vec<PersistItem>) {
    let base = r"SYSTEM\CurrentControlSet\Control\Lsa";
    let known: HashMap<&str, &[&str]> = HashMap::from([
        ("Authentication Packages", &["msv1_0"][..]),
        ("Notification Packages", &["scecli", "rassfm", "kdcpw", "passwdflt"][..]),
        (
            "Security Packages",
            &["", "\"\"", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "livessp", "msoidssp", "wsauth"][..],
        ),
    ]);
    for (sub, names) in [(base.to_string(), vec!["Authentication Packages", "Notification Packages", "Security Packages"]), (format!(r"{base}\OSConfig"), vec!["Security Packages"])] {
        let Some(k) = reg_open("HKLM", &sub) else { continue };
        for n in names {
            let Some(v) = key_str(&k, n) else { continue };
            let entries: Vec<String> = v
                .split(['|', ' ', '\n'])
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            let unknown: Vec<&String> = entries
                .iter()
                .filter(|e| !known[n].contains(&e.as_str()))
                .collect();
            let mut it = item(PersistKind::Lsa, n, &format!("HKLM\\{sub}"), &v);
            it.image = String::new();
            if !unknown.is_empty() {
                it.risk = Severity::High;
                it.reasons.push(format!(
                    "存在非默认 LSA 包: {}",
                    unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
            out.push(it);
        }
    }
}

fn boot_execute(out: &mut Vec<PersistItem>) {
    let p = r"SYSTEM\CurrentControlSet\Control\Session Manager";
    if let Some(v) = reg_str("HKLM", p, "BootExecute") {
        let mut it = item(PersistKind::BootExecute, "BootExecute", &format!("HKLM\\{p}"), &v);
        it.image = String::new();
        let norm = v.to_ascii_lowercase().replace(" | ", "|");
        if norm.trim() != "autocheck autochk *" && !norm.trim().is_empty() {
            it.risk = Severity::High;
            it.reasons.push("BootExecute 非默认值（默认 autocheck autochk *）".into());
        }
        out.push(it);
    }
}

// ---------------------------------------------------------------- 服务

fn service_states() -> HashMap<String, (u32, u32)> {
    let mut map = HashMap::new();
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else {
            return map;
        };
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32 | SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            PCWSTR::null(),
        );
        if needed > 0 {
            let mut buf = vec![0u64; needed as usize / 8 + 64];
            let bytes = std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len() * 8);
            resume = 0;
            if EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                Some(bytes),
                &mut needed,
                &mut count,
                Some(&mut resume),
                PCWSTR::null(),
            )
            .is_ok()
            {
                let arr = std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    count as usize,
                );
                for s in arr {
                    let name = pwstr(s.lpServiceName).to_ascii_lowercase();
                    let st = &s.ServiceStatusProcess;
                    map.insert(name, (st.dwCurrentState.0, st.dwProcessId));
                }
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    map
}

fn start_label(start: u32) -> &'static str {
    match start {
        0 => "引导",
        1 => "系统",
        2 => "自动",
        3 => "手动",
        4 => "禁用",
        _ => "未知",
    }
}

fn services(out: &mut Vec<PersistItem>) {
    let states = service_states();
    let base = r"SYSTEM\CurrentControlSet\Services";
    let Some(root) = reg_open("HKLM", base) else { return };
    for name in reg_subkeys(&root) {
        let Ok(k) = root.open_subkey_with_flags(&name, KEY_READ) else { continue };
        let Some(ty) = key_dword(&k, "Type") else { continue };
        let Some(image_path) = key_str(&k, "ImagePath") else { continue };
        let start = key_dword(&k, "Start").unwrap_or(3);
        let is_driver = ty & 0x0B != 0 && ty & 0x30 == 0;
        let is_win32 = ty & 0x30 != 0;
        if !is_driver && !is_win32 {
            continue;
        }
        let display = key_str(&k, "DisplayName").unwrap_or_default();
        let obj = key_str(&k, "ObjectName").unwrap_or_default();
        let service_dll = reg_open("HKLM", &format!(r"{base}\{name}\Parameters"))
            .and_then(|p| key_str(&p, "ServiceDll"))
            .or_else(|| key_str(&k, "ServiceDll"))
            .map(|d| normalize_nt_path(&d));

        let mut it = item(PersistKind::Service, &name, &format!("HKLM\\{base}\\{name}"), &image_path);
        it.image = if is_driver {
            normalize_nt_path(&image_path)
        } else {
            exe_from_cmdline(&image_path)
        };
        let state = states.get(&name.to_ascii_lowercase());
        let running = state.map(|s| s.0 == 4).unwrap_or(false);
        it.enabled = start != 4;
        it.extra = format!(
            "{} | {} | 启动:{} | 状态:{}{}",
            if display.starts_with('@') { name.clone() } else { display },
            if is_driver { "驱动".to_string() } else { obj },
            start_label(start),
            if running { "运行中" } else { "已停止" },
            service_dll.as_ref().map(|d| format!(" | DLL:{d}")).unwrap_or_default()
        );
        it.time = key_last_write(&k);

        if is_driver {
            // 驱动数量多，只对非系统目录或未签名驱动研判
            let img = it.image.clone();
            if img.is_empty() || (is_system_dir(&img) && !is_suspicious_dir(&img)) {
                let st = signature::check(&img);
                if st != SignState::Unsigned || start > 2 {
                    continue;
                }
                it.sign = st;
                it.risk = Severity::High;
                it.reasons.push("自启动驱动未签名".into());
            } else {
                assess_command(&mut it);
                if it.risk < Severity::Low {
                    it.risk = Severity::Low;
                    it.reasons.push("驱动位于非系统目录".into());
                }
            }
            it.kind = PersistKind::Service;
            out.push(it);
            continue;
        }

        assess_command(&mut it);
        if let Some(dll) = service_dll {
            if is_suspicious_dir(&dll) {
                it.risk = it.risk.max(Severity::High);
                it.reasons.push("ServiceDll 位于可疑目录".into());
            }
            let st = signature::check(&dll);
            if st == SignState::Unsigned {
                it.risk = it.risk.max(Severity::High);
                it.reasons.push("svchost 服务 DLL 未签名".into());
            }
            if it.sign == SignState::Signed && st != SignState::Signed {
                it.sign = st;
            }
        }
        out.push(it);
    }
}

// ---------------------------------------------------------------- 计划任务

fn scheduled_tasks(out: &mut Vec<PersistItem>, lookback: Time) {
    let root = format!("{}\\System32\\Tasks", system_root());
    let mut files = Vec::new();
    walk(Path::new(&root), 0, 8, &mut |p| files.push(p.to_path_buf()));

    for f in files {
        let Some(text) = read_text_any(&f) else { continue };
        let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
        let rel = f
            .strip_prefix(&root)
            .map(|p| format!("\\{}", p.display()))
            .unwrap_or_else(|_| f.display().to_string());
        let find = |tag: &str| -> Option<String> {
            doc.descendants()
                .find(|n| n.has_tag_name(tag))
                .and_then(|n| n.text())
                .map(|s| s.trim().to_string())
        };
        let author = find("Author").unwrap_or_default();
        let date = find("Date");
        let hidden = find("Hidden").map(|v| v == "true").unwrap_or(false);
        let enabled = doc
            .descendants()
            .find(|n| n.has_tag_name("Settings"))
            .and_then(|s| s.children().find(|c| c.has_tag_name("Enabled")))
            .and_then(|n| n.text())
            .map(|v| v.trim() != "false")
            .unwrap_or(true);
        let user = find("UserId").unwrap_or_default();
        let run_level = find("RunLevel").unwrap_or_default();
        let triggers: Vec<String> = doc
            .descendants()
            .find(|n| n.has_tag_name("Triggers"))
            .map(|t| {
                t.children()
                    .filter(|c| c.is_element())
                    .map(|c| trigger_label(c.tag_name().name()).to_string())
                    .collect()
            })
            .unwrap_or_default();

        let mut commands = Vec::new();
        for exec in doc.descendants().filter(|n| n.has_tag_name("Exec")) {
            let cmd = exec
                .children()
                .find(|c| c.has_tag_name("Command"))
                .and_then(|n| n.text())
                .unwrap_or("")
                .trim()
                .to_string();
            let args = exec
                .children()
                .find(|c| c.has_tag_name("Arguments"))
                .and_then(|n| n.text())
                .unwrap_or("")
                .trim()
                .to_string();
            let full = if cmd.contains(' ') && !cmd.starts_with('"') {
                format!("\"{cmd}\" {args}")
            } else {
                format!("{cmd} {args}")
            };
            commands.push(full.trim().to_string());
        }
        for com in doc.descendants().filter(|n| n.has_tag_name("ComHandler")) {
            let id = com
                .children()
                .find(|c| c.has_tag_name("ClassId"))
                .and_then(|n| n.text())
                .unwrap_or("")
                .to_string();
            commands.push(format!("COM {id}"));
        }
        let command = commands.join(" ; ");
        let is_ms = rel.to_ascii_lowercase().starts_with("\\microsoft\\");

        let mut it = item(PersistKind::ScheduledTask, &rel, &f.display().to_string(), &command);
        if command.starts_with("COM ") {
            it.image = String::new();
        }
        it.enabled = enabled;
        it.time = date.as_deref().and_then(parse_task_date);
        it.extra = format!(
            "作者:{} | 运行身份:{}{} | 触发器:{}{}",
            if author.is_empty() { "-" } else { &author },
            if user.is_empty() { "-" } else { &user },
            if run_level == "HighestAvailable" { " (最高权限)" } else { "" },
            if triggers.is_empty() { "-".to_string() } else { triggers.join("/") },
            if hidden { " | 隐藏" } else { "" }
        );
        if !it.image.is_empty() {
            assess_command(&mut it);
        }
        if hidden && !is_ms {
            it.risk = it.risk.max(Severity::Medium);
            it.reasons.push("任务被设置为隐藏".into());
        }
        if !is_ms {
            if let Some(t) = it.time {
                if t >= lookback {
                    it.risk = it.risk.max(Severity::Medium);
                    it.reasons.push("近期新注册的非微软计划任务".into());
                }
            }
            if (user.eq_ignore_ascii_case("S-1-5-18") || user.eq_ignore_ascii_case("SYSTEM"))
                && it.risk >= Severity::Medium
            {
                it.reasons.push("以 SYSTEM 身份运行".into());
            }
        }
        out.push(it);
    }

    // 删除 SD 的隐藏计划任务（Tarrask 手法）
    let tree = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";
    if let Some(k) = reg_open("HKLM", tree) {
        let mut stack = vec![(k, String::new())];
        while let Some((key, prefix)) = stack.pop() {
            for sub in reg_subkeys(&key) {
                let Ok(sk) = key.open_subkey_with_flags(&sub, KEY_READ) else { continue };
                let path = format!("{prefix}\\{sub}");
                if key_str(&sk, "Id").is_some() && sk.get_raw_value("SD").is_err() {
                    let mut it = item(PersistKind::ScheduledTask, &path, &format!("HKLM\\{tree}{path}"), "");
                    it.risk = Severity::Critical;
                    it.reasons.push("任务缓存缺少 SD 值，属于刻意隐藏的计划任务".into());
                    it.time = key_last_write(&sk);
                    out.push(it);
                }
                if stack.len() < 2000 {
                    stack.push((sk, path));
                }
            }
        }
    }
}

fn trigger_label(tag: &str) -> &str {
    match tag {
        "BootTrigger" => "开机",
        "LogonTrigger" => "登录",
        "TimeTrigger" => "定时",
        "CalendarTrigger" => "日程",
        "IdleTrigger" => "空闲",
        "EventTrigger" => "事件",
        "RegistrationTrigger" => "注册时",
        "SessionStateChangeTrigger" => "会话变化",
        "WnfStateChangeTrigger" => "WNF",
        other => other,
    }
}

fn parse_task_date(s: &str) -> Option<Time> {
    if let Some(t) = parse_rfc3339_local(s) {
        return Some(t);
    }
    let s = s.split('.').next().unwrap_or(s);
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .and_then(|n| n.and_local_timezone(chrono::Local).single())
}

pub fn walk(dir: &Path, depth: usize, max_depth: usize, f: &mut dyn FnMut(&Path)) {
    if depth > max_depth {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    // 先处理本层文件再进入子目录：带上限的扫描优先覆盖浅层（落地文件通常位于目录顶层）
    let mut subdirs = Vec::new();
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            subdirs.push(e.path());
        } else {
            f(&e.path());
        }
    }
    for p in subdirs {
        walk(&p, depth + 1, max_depth, f);
    }
}

// ---------------------------------------------------------------- 启动目录 / 辅助功能 / Netsh / COM / WMI

fn startup_folders(out: &mut Vec<PersistItem>) {
    let mut dirs = vec![format!(
        r"{}\Microsoft\Windows\Start Menu\Programs\StartUp",
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into())
    )];
    for p in user_profiles() {
        dirs.push(format!(
            r"{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            p.display()
        ));
    }
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.eq_ignore_ascii_case("desktop.ini") || p.is_dir() {
                continue;
            }
            let (target, args) = if name.to_ascii_lowercase().ends_with(".lnk") {
                super::lnk::parse_file(&p)
                    .map(|l| (l.target, l.arguments))
                    .unwrap_or_default()
            } else {
                (p.display().to_string(), String::new())
            };
            let cmd = if args.is_empty() { target.clone() } else { format!("\"{target}\" {args}") };
            let mut it = item(PersistKind::StartupFolder, &name, &d, &cmd);
            it.time = file_times(&p).1;
            assess_command(&mut it);
            let lower = name.to_ascii_lowercase();
            if [".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".exe", ".scr"]
                .iter()
                .any(|x| lower.ends_with(x))
            {
                it.risk = it.risk.max(Severity::Medium);
                it.reasons.push("启动目录中直接放置了脚本/可执行文件".into());
            }
            out.push(it);
        }
    }
}

fn accessibility(out: &mut Vec<PersistItem>) {
    let sys = format!("{}\\System32", system_root());
    let mut ref_hashes = HashMap::new();
    for r in ["cmd.exe", "powershell.exe", "explorer.exe", "taskmgr.exe"] {
        let p = if r == "powershell.exe" {
            format!("{sys}\\WindowsPowerShell\\v1.0\\{r}")
        } else if r == "explorer.exe" {
            format!("{}\\{r}", system_root())
        } else {
            format!("{sys}\\{r}")
        };
        let h = sha256_file(Path::new(&p), 64 << 20);
        if !h.is_empty() {
            ref_hashes.insert(h, r);
        }
    }
    for name in ACCESSIBILITY {
        let p = format!("{sys}\\{name}");
        if !Path::new(&p).exists() {
            continue;
        }
        let mut it = item(PersistKind::Accessibility, name, &sys, &p);
        let h = sha256_file(Path::new(&p), 64 << 20);
        it.sign = signature::check(&p);
        it.time = file_times(Path::new(&p)).1;
        if let Some(r) = ref_hashes.get(&h) {
            it.risk = Severity::Critical;
            it.reasons.push(format!("文件哈希与 {r} 相同，辅助功能程序已被替换"));
        } else if it.sign == SignState::Unsigned {
            it.risk = Severity::Critical;
            it.reasons.push("辅助功能程序签名无效，可能被替换".into());
        }
        it.extra = format!("SHA256: {h}");
        out.push(it);
    }
}

fn netsh_helpers(out: &mut Vec<PersistItem>) {
    let p = r"SOFTWARE\Microsoft\NetSh";
    let Some(k) = reg_open("HKLM", p) else { return };
    for (name, value) in reg_values(&k) {
        let dll = resolve_exe(&value);
        let suspicious = is_suspicious_dir(&dll) || (dll.contains('\\') && !is_system_dir(&dll));
        if !suspicious {
            continue;
        }
        let mut it = item(PersistKind::NetshHelper, &name, &format!("HKLM\\{p}"), &value);
        it.image = dll;
        it.risk = Severity::High;
        it.reasons.push("Netsh Helper DLL 指向非系统目录".into());
        assess_command(&mut it);
        out.push(it);
    }
}

fn com_hijack(out: &mut Vec<PersistItem>) {
    for (label, sid) in user_hives() {
        let base = format!(r"{sid}\Software\Classes\CLSID");
        let Some(k) = reg_open("HKU", &base) else { continue };
        for clsid in reg_subkeys(&k) {
            for server in ["InprocServer32", "LocalServer32"] {
                let Ok(sk) = k.open_subkey_with_flags(format!("{clsid}\\{server}"), KEY_READ) else {
                    continue;
                };
                let Some(v) = key_str(&sk, "").filter(|v| !v.trim().is_empty()) else { continue };
                let mut it = item(PersistKind::ComHijack, &clsid, &format!("{label}\\Software\\Classes\\CLSID\\{clsid}\\{server}"), &v);
                it.time = key_last_write(&sk);
                it.image = resolve_exe(&normalize_nt_path(v.trim().trim_matches('"')));
                if server == "LocalServer32" {
                    it.image = exe_from_cmdline(&v);
                }
                assess_command(&mut it);
                // 同 CLSID 在 HKLM 中也存在 → 用户级覆盖了系统 COM 对象
                if reg_open("HKLM", &format!(r"SOFTWARE\Classes\CLSID\{clsid}")).is_some() {
                    // 签名正常且位于常规目录的覆盖较常见（如 OneDrive），仅提示
                    let sev = if it.risk >= Severity::Medium || it.sign == SignState::Unsigned { Severity::Medium } else { Severity::Low };
                    it.risk = it.risk.max(sev);
                    it.reasons.push("用户级注册覆盖了系统 COM 对象".into());
                }
                out.push(it);
            }
        }
    }
}

fn wmi(out: &mut Vec<PersistItem>) {
    let ps = r#"
$r = @{}
$r.consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | ForEach-Object {
  @{ cls = $_.CimClass.CimClassName; name = [string]$_.Name; cmd = [string]$_.CommandLineTemplate; exe = [string]$_.ExecutablePath; script = [string]$_.ScriptText; engine = [string]$_.ScriptingEngine } })
$r.filters = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object { @{ name = [string]$_.Name; query = [string]$_.Query } })
$r.bindings = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object { @{ filter = [string]$_.Filter.Name; consumer = [string]$_.Consumer.Name } })
$r | ConvertTo-Json -Depth 4 -Compress
"#;
    let Some(text) = run_powershell(ps) else { return };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) else { return };
    let arr = |k: &str| -> Vec<serde_json::Value> {
        match v.get(k) {
            Some(serde_json::Value::Array(a)) => a.clone(),
            Some(o @ serde_json::Value::Object(_)) => vec![o.clone()],
            _ => vec![],
        }
    };
    let s = |o: &serde_json::Value, k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let filters: HashMap<String, String> = arr("filters")
        .iter()
        .map(|f| (s(f, "name"), s(f, "query")))
        .collect();
    let bindings: HashMap<String, String> = arr("bindings")
        .iter()
        .map(|b| (s(b, "consumer"), s(b, "filter")))
        .collect();
    for c in arr("consumers") {
        let cls = s(&c, "cls");
        let name = s(&c, "name");
        let command = [s(&c, "cmd"), s(&c, "exe"), s(&c, "script")]
            .into_iter()
            .find(|x| !x.is_empty())
            .unwrap_or_default();
        let mut it = item(PersistKind::Wmi, &name, &format!("root\\subscription:{cls}"), &command);
        if cls != "CommandLineEventConsumer" {
            it.image = String::new();
        }
        let filter = bindings.get(&name).cloned().unwrap_or_default();
        it.extra = format!(
            "过滤器:{} {}",
            if filter.is_empty() { "-" } else { &filter },
            filters.get(&filter).cloned().unwrap_or_default()
        );
        let benign = name == "SCM Event Log Consumer" && cls == "NTEventLogEventConsumer";
        if !benign {
            match cls.as_str() {
                "CommandLineEventConsumer" | "ActiveScriptEventConsumer" => {
                    it.risk = Severity::Critical;
                    it.reasons.push("WMI 永久事件订阅执行命令/脚本".into());
                }
                _ => {
                    it.risk = Severity::Medium;
                    it.reasons.push("非默认 WMI 事件消费者".into());
                }
            }
        }
        if !it.image.is_empty() {
            assess_command(&mut it);
        }
        out.push(it);
    }
}
