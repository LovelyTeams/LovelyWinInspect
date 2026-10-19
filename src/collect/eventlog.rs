//! Windows 事件日志采集：只拉取与入侵研判相关的关键事件 ID。

use std::collections::HashMap;
use std::ffi::c_void;

use windows::Win32::System::EventLog::*;
use windows::core::PCWSTR;

use super::util::{parse_rfc3339_local, wide};
use crate::model::{EventRecord, Severity, Tactic, Time};

#[derive(Debug, Default, Clone)]
pub struct RawEvent {
    pub id: u32,
    pub time: Option<Time>,
    pub channel: String,
    pub level: u32,
    pub data: HashMap<String, String>,
    pub raw_data: Vec<String>,
}

impl RawEvent {
    fn get(&self, k: &str) -> String {
        self.data.get(k).cloned().unwrap_or_default()
    }
}

struct EvtHandle(EVT_HANDLE);
impl Drop for EvtHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

pub fn query(channel: &str, xpath: &str, max: usize) -> Result<Vec<RawEvent>, String> {
    let wc = wide(channel);
    let wq = wide(xpath);
    let mut out = Vec::new();
    unsafe {
        let h = EvtQuery(
            None,
            PCWSTR(wc.as_ptr()),
            PCWSTR(wq.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
        .map_err(|e| format!("{channel}: {}", e.message()))?;
        let h = EvtHandle(h);
        let mut handles = [0isize; 64];
        let mut buf: Vec<u16> = vec![0; 8192];
        'outer: loop {
            let mut returned = 0u32;
            if EvtNext(h.0, &mut handles, 2000, 0, &mut returned).is_err() || returned == 0 {
                break;
            }
            for &raw in &handles[..returned as usize] {
                let ev = EvtHandle(EVT_HANDLE(raw));
                if out.len() >= max {
                    continue;
                }
                let mut used = 0u32;
                let mut props = 0u32;
                let mut ok = EvtRender(
                    None,
                    ev.0,
                    EvtRenderEventXml.0,
                    (buf.len() * 2) as u32,
                    Some(buf.as_mut_ptr() as *mut c_void),
                    &mut used,
                    &mut props,
                )
                .is_ok();
                if !ok && used as usize > buf.len() * 2 {
                    buf = vec![0; used as usize / 2 + 16];
                    ok = EvtRender(
                        None,
                        ev.0,
                        EvtRenderEventXml.0,
                        (buf.len() * 2) as u32,
                        Some(buf.as_mut_ptr() as *mut c_void),
                        &mut used,
                        &mut props,
                    )
                    .is_ok();
                }
                if ok {
                    let n = (used as usize / 2).min(buf.len());
                    let xml = String::from_utf16_lossy(&buf[..n]);
                    if let Some(e) = parse_xml(xml.trim_end_matches('\0')) {
                        out.push(e);
                    }
                }
            }
            if out.len() >= max {
                break 'outer;
            }
        }
    }
    Ok(out)
}

fn parse_xml(xml: &str) -> Option<RawEvent> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let mut e = RawEvent::default();
    for n in doc.descendants() {
        match n.tag_name().name() {
            "EventID" => e.id = n.text().unwrap_or("0").trim().parse().unwrap_or(0),
            "Level" => e.level = n.text().unwrap_or("0").trim().parse().unwrap_or(0),
            "Channel" => e.channel = n.text().unwrap_or("").to_string(),
            "TimeCreated" => e.time = n.attribute("SystemTime").and_then(parse_rfc3339_local),
            "Data" => {
                let v = n.text().unwrap_or("").trim().to_string();
                if let Some(name) = n.attribute("Name") {
                    e.data.insert(name.to_string(), v);
                } else {
                    e.raw_data.push(v);
                }
            }
            _ => {}
        }
    }
    // UserData 下的自定义字段（如 RDP 1149、日志清除 1102）
    if let Some(ud) = doc.descendants().find(|n| n.has_tag_name("UserData")) {
        for n in ud.descendants().filter(|n| n.is_element()) {
            if n.children().all(|c| c.is_text()) {
                if let Some(t) = n.text() {
                    e.data.insert(n.tag_name().name().to_string(), t.trim().to_string());
                }
            }
        }
    }
    Some(e)
}

fn time_filter(days: u32) -> String {
    format!("TimeCreated[timediff(@SystemTime) <= {}]", days as u64 * 86_400_000)
}

fn ids_xpath(ids: &[u32], days: u32, extra: &str) -> String {
    let ids = ids
        .iter()
        .map(|i| format!("EventID={i}"))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("*[System[({ids}) and {}{extra}]]", time_filter(days))
}

pub fn logon_type_label(t: &str) -> &'static str {
    match t {
        "2" => "交互式",
        "3" => "网络",
        "4" => "批处理",
        "5" => "服务",
        "7" => "解锁",
        "8" => "网络明文",
        "9" => "新凭据",
        "10" => "远程桌面",
        "11" => "缓存交互",
        _ => "",
    }
}

fn title_of(channel: &str, id: u32) -> &'static str {
    match (channel, id) {
        ("Security", 4624) => "登录成功",
        ("Security", 4625) => "登录失败",
        ("Security", 4648) => "使用显式凭据登录",
        ("Security", 4697) => "安装系统服务",
        ("Security", 4698) => "创建计划任务",
        ("Security", 4699) => "删除计划任务",
        ("Security", 4702) => "修改计划任务",
        ("Security", 4719) => "审核策略被修改",
        ("Security", 4720) => "创建用户账户",
        ("Security", 4722) => "启用用户账户",
        ("Security", 4724) => "重置用户密码",
        ("Security", 4725) => "禁用用户账户",
        ("Security", 4726) => "删除用户账户",
        ("Security", 4738) => "修改用户账户",
        ("Security", 4781) => "账户名被修改",
        ("Security", 4728) => "成员加入全局安全组",
        ("Security", 4732) => "成员加入本地安全组",
        ("Security", 4733) => "成员移出本地安全组",
        ("Security", 4756) => "成员加入通用安全组",
        ("Security", 1102) => "安全日志被清除",
        ("System", 104) => "系统日志被清除",
        ("System", 7045) => "新服务被安装",
        ("System", 7040) => "服务启动类型被修改",
        ("System", 6005) => "系统启动",
        ("System", 6006) => "系统正常关机",
        ("System", 6008) => "系统异常关机",
        (_, 1149) => "RDP 网络认证成功",
        (_, 21) => "RDP 会话登录",
        (_, 24) => "RDP 会话断开",
        (_, 25) => "RDP 会话重连",
        (_, 4104) => "PowerShell 脚本块告警",
        ("Security", 4688) => "进程创建",
        ("Security", 5140) => "访问网络共享",
        (_, 1116) => "Defender 检测到威胁",
        (_, 1117) => "Defender 已处置威胁",
        (_, 5001) => "Defender 实时防护被关闭",
        (_, 5007) => "Defender 配置被修改",
        (_, 5010) => "Defender 恶意软件扫描被禁用",
        (_, 5012) => "Defender 病毒扫描被禁用",
        (_, 106) => "计划任务被注册",
        (_, 140) => "计划任务被更新",
        (_, 141) => "计划任务被删除",
        (_, 5861) => "WMI 永久事件订阅注册",
        (_, 59) => "BITS 传输任务",
        _ => "事件",
    }
}

fn is_noise_account(user: &str) -> bool {
    let u = user.to_ascii_uppercase();
    u.is_empty()
        || u == "-"
        || u.ends_with('$')
        || u == "SYSTEM"
        || u == "LOCAL SERVICE"
        || u == "NETWORK SERVICE"
        || u == "ANONYMOUS LOGON"
        || u.starts_with("DWM-")
        || u.starts_with("UMFD-")
}

fn ip_clean(ip: &str) -> String {
    let ip = ip.trim();
    if ip == "-" || ip == "::1" || ip == "127.0.0.1" {
        String::new()
    } else {
        ip.trim_start_matches("::ffff:").to_string()
    }
}

pub struct EventCollection {
    pub events: Vec<EventRecord>,
    pub errors: Vec<String>,
}

pub fn collect(days: u32) -> EventCollection {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    let run = |channel: &str, xpath: String, max: usize, errors: &mut Vec<String>| -> Vec<RawEvent> {
        match query(channel, &xpath, max) {
            Ok(v) => v,
            Err(e) => {
                errors.push(e);
                Vec::new()
            }
        }
    };

    // ---- 登录成功：只保留交互/网络/RDP/缓存登录，去除系统账户噪音
    let logon = run(
        "Security",
        format!(
            "*[System[(EventID=4624) and {}] and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='3' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]",
            time_filter(days)
        ),
        4000,
        &mut errors,
    );
    for e in logon {
        let user = e.get("TargetUserName");
        if is_noise_account(&user) {
            continue;
        }
        let lt = e.get("LogonType");
        let ip = ip_clean(&e.get("IpAddress"));
        if lt == "3" && ip.is_empty() {
            continue;
        }
        let rdp = lt == "10";
        events.push(EventRecord {
            time: e.time,
            channel: "Security".into(),
            event_id: 4624,
            title: if rdp { "远程桌面登录成功".into() } else { "登录成功".into() },
            user: format!("{}\\{}", e.get("TargetDomainName"), user),
            source_ip: ip,
            logon_type: format!("{} {}", lt, logon_type_label(&lt)),
            process: e.get("ProcessName"),
            detail: format!("工作站:{} 认证包:{}", e.get("WorkstationName"), e.get("AuthenticationPackageName")),
            severity: Severity::Info,
            tactic: Some(Tactic::InitialAccess),
        });
    }

    // ---- 登录失败
    for e in run("Security", ids_xpath(&[4625], days, ""), 5000, &mut errors) {
        let lt = e.get("LogonType");
        events.push(EventRecord {
            time: e.time,
            channel: "Security".into(),
            event_id: 4625,
            title: "登录失败".into(),
            user: format!("{}\\{}", e.get("TargetDomainName"), e.get("TargetUserName")),
            source_ip: ip_clean(&e.get("IpAddress")),
            logon_type: format!("{} {}", lt, logon_type_label(&lt)),
            process: e.get("ProcessName"),
            detail: format!("状态:{} 子状态:{} 工作站:{}", e.get("Status"), e.get("SubStatus"), e.get("WorkstationName")),
            severity: Severity::Low,
            tactic: Some(Tactic::CredentialAccess),
        });
    }

    // ---- 账户、服务、计划任务、日志清除等关键安全事件
    let sec_ids = [
        4720, 4722, 4724, 4725, 4726, 4738, 4781, 4728, 4732, 4733, 4756, 1102, 4697, 4698, 4699, 4702, 4648, 4719,
    ];
    for e in run("Security", ids_xpath(&sec_ids, days, ""), 3000, &mut errors) {
        let mut r = EventRecord {
            time: e.time,
            channel: "Security".into(),
            event_id: e.id,
            title: title_of("Security", e.id).into(),
            ..Default::default()
        };
        let subject = format!("{}\\{}", e.get("SubjectDomainName"), e.get("SubjectUserName"));
        match e.id {
            4720 | 4722 | 4724 | 4725 | 4726 | 4738 | 4781 => {
                r.user = subject;
                r.detail = format!(
                    "目标账户: {}\\{}{}",
                    e.get("TargetDomainName"),
                    e.get("TargetUserName"),
                    if e.id == 4781 { format!(" (原名 {} → 新名 {})", e.get("OldTargetUserName"), e.get("NewTargetUserName")) } else { String::new() }
                );
                r.severity = match e.id {
                    4720 | 4781 => Severity::High,
                    4738 => Severity::Info,
                    _ => Severity::Medium,
                };
                r.tactic = Some(Tactic::Persistence);
            }
            4728 | 4732 | 4756 | 4733 => {
                r.user = subject;
                let member = if e.get("MemberName").is_empty() || e.get("MemberName") == "-" {
                    e.get("MemberSid")
                } else {
                    e.get("MemberName")
                };
                r.detail = format!("成员 {} → 组 {}\\{}", member, e.get("TargetDomainName"), e.get("TargetUserName"));
                let admin_group = e.get("TargetSid") == "S-1-5-32-544" || e.get("TargetSid") == "S-1-5-32-555";
                r.severity = if e.id == 4733 { Severity::Low } else if admin_group { Severity::High } else { Severity::Medium };
                r.tactic = Some(Tactic::PrivilegeEscalation);
            }
            1102 => {
                r.user = format!("{}\\{}", e.get("SubjectDomainName"), e.get("SubjectUserName"));
                r.detail = "安全审计日志被清空，攻击者常用于清除痕迹".into();
                r.severity = Severity::Critical;
                r.tactic = Some(Tactic::DefenseEvasion);
            }
            4697 => {
                r.user = subject;
                r.process = e.get("ServiceFileName");
                r.detail = format!("服务名: {} 启动类型: {}", e.get("ServiceName"), e.get("ServiceStartType"));
                r.severity = Severity::Medium;
                r.tactic = Some(Tactic::Persistence);
            }
            4698 | 4699 | 4702 => {
                r.user = subject;
                r.detail = format!("任务: {}", e.get("TaskName"));
                if let Some(cmd) = task_command(&e.get("TaskContent")) {
                    r.process = cmd;
                }
                r.severity = if e.id == 4698 { Severity::Medium } else { Severity::Low };
                r.tactic = Some(Tactic::Persistence);
            }
            4648 => {
                let target = e.get("TargetUserName");
                if is_noise_account(&target) {
                    continue;
                }
                r.user = subject;
                r.source_ip = ip_clean(&e.get("IpAddress"));
                r.process = e.get("ProcessName");
                r.detail = format!("使用凭据 {}\\{} 访问 {}", e.get("TargetDomainName"), target, e.get("TargetServerName"));
                r.severity = Severity::Low;
                r.tactic = Some(Tactic::LateralMovement);
            }
            4719 => {
                r.user = subject;
                r.detail = format!("子类别: {} 变更: {}", e.get("SubcategoryGuid"), e.get("AuditPolicyChanges"));
                r.severity = Severity::High;
                r.tactic = Some(Tactic::DefenseEvasion);
            }
            _ => {}
        }
        events.push(r);
    }

    // ---- 进程创建审计（4688）：基于路径/父进程/参数特征筛选
    for e in run("Security", ids_xpath(&[4688], days, ""), 20000, &mut errors) {
        let image = e.get("NewProcessName");
        let parent = e.get("ParentProcessName");
        let cmd = e.get("CommandLine");
        let image_l = image.to_ascii_lowercase();
        let parent_name = parent.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
        let child_name = image_l.rsplit('\\').next().unwrap_or("").to_string();
        let mut reasons: Vec<(Severity, String)> = Vec::new();
        if super::util::is_suspicious_dir(&image_l) {
            reasons.push((Severity::Medium, "从临时/公共/用户可写目录启动".into()));
        }
        let shells = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
        let office = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "wps.exe", "et.exe", "wpp.exe"];
        let servers = ["w3wp.exe", "httpd.exe", "nginx.exe", "java.exe", "javaw.exe", "php-cgi.exe", "sqlservr.exe", "tomcat9.exe"];
        if shells.contains(&child_name.as_str()) {
            if office.contains(&parent_name.as_str()) {
                reasons.push((Severity::High, format!("办公软件 {parent_name} 启动了 {child_name}")));
            }
            if servers.contains(&parent_name.as_str()) {
                reasons.push((Severity::Critical, format!("Web/数据库服务 {parent_name} 启动了 {child_name}")));
            }
        }
        for (sev, why) in crate::analysis::cmdline_flags(&cmd) {
            reasons.push((sev, why.to_string()));
        }
        let Some(sev) = reasons.iter().map(|r| r.0).max() else { continue };
        events.push(EventRecord {
            time: e.time,
            channel: "Security".into(),
            event_id: 4688,
            title: format!("进程创建：{}", reasons.iter().map(|r| r.1.as_str()).collect::<Vec<_>>().join("；")),
            user: format!("{}\\{}", e.get("SubjectDomainName"), e.get("SubjectUserName")),
            process: image,
            detail: format!("父进程: {parent}  命令行: {cmd}"),
            severity: sev,
            tactic: Some(Tactic::Execution),
            ..Default::default()
        });
    }

    // ---- 管理共享访问（需开启“审核文件共享”）
    for e in run("Security", ids_xpath(&[5140], days, ""), 2000, &mut errors) {
        let share = e.get("ShareName");
        let upper = share.to_ascii_uppercase();
        // 只关注 ADMIN$ 与磁盘管理共享（C$、D$ …）
        let admin_share = upper.ends_with("\\ADMIN$") || (upper.ends_with('$') && upper.rsplit('\\').next().map(|s| s.len() == 2).unwrap_or(false));
        if !admin_share {
            continue;
        }
        let ip = ip_clean(&e.get("IpAddress"));
        if ip.is_empty() {
            continue;
        }
        events.push(EventRecord {
            time: e.time,
            channel: "Security".into(),
            event_id: 5140,
            title: "访问管理共享".into(),
            user: format!("{}\\{}", e.get("SubjectDomainName"), e.get("SubjectUserName")),
            source_ip: ip,
            detail: format!("共享: {share}"),
            severity: Severity::Medium,
            tactic: Some(Tactic::LateralMovement),
            ..Default::default()
        });
    }

    // ---- 本机向外发起的远程桌面连接
    for e in run("Microsoft-Windows-TerminalServices-RDPClient/Operational", ids_xpath(&[1024], days, ""), 500, &mut errors) {
        let target = e.get("Value");
        events.push(EventRecord {
            time: e.time,
            channel: "RDP".into(),
            event_id: 1024,
            title: "向外发起远程桌面连接".into(),
            detail: format!("目标: {target}"),
            severity: Severity::Info,
            tactic: Some(Tactic::LateralMovement),
            ..Default::default()
        });
    }

    // ---- WinRM 入站会话
    for e in run("Microsoft-Windows-WinRM/Operational", ids_xpath(&[91], days, ""), 500, &mut errors) {
        events.push(EventRecord {
            time: e.time,
            channel: "WinRM".into(),
            event_id: 91,
            title: "WinRM 远程会话创建".into(),
            detail: e.get("resourceUri"),
            severity: Severity::Low,
            tactic: Some(Tactic::LateralMovement),
            ..Default::default()
        });
    }

    // ---- System
    for e in run("System", ids_xpath(&[7045, 7040, 104, 6005, 6006, 6008], days, ""), 2000, &mut errors) {
        let mut r = EventRecord {
            time: e.time,
            channel: "System".into(),
            event_id: e.id,
            title: title_of("System", e.id).into(),
            ..Default::default()
        };
        match e.id {
            7045 => {
                r.process = e.get("ImagePath");
                r.user = e.get("AccountName");
                r.detail = format!("服务名: {} 类型: {} 启动: {}", e.get("ServiceName"), e.get("ServiceType"), e.get("StartType"));
                r.severity = Severity::Medium;
                r.tactic = Some(Tactic::Persistence);
                let lower = r.process.to_ascii_lowercase();
                if lower.contains("cmd.exe")
                    || lower.contains("powershell")
                    || lower.contains("\\temp\\")
                    || lower.contains("\\users\\public\\")
                {
                    r.severity = Severity::High;
                }
            }
            7040 => {
                let name = e.raw_data.first().cloned().unwrap_or_else(|| e.get("param1"));
                let change = format!(
                    "{} → {}",
                    e.raw_data.get(1).cloned().unwrap_or_else(|| e.get("param2")),
                    e.raw_data.get(2).cloned().unwrap_or_else(|| e.get("param3"))
                );
                r.detail = format!("服务 {name}: {change}");
                let lower = name.to_ascii_lowercase();
                let sensitive = ["defender", "windefend", "eventlog", "firewall", "mpssvc", "wscsvc", "sense"];
                if sensitive.iter().any(|s| lower.contains(s)) && (change.contains("禁用") || change.to_ascii_lowercase().contains("disabled")) {
                    r.severity = Severity::High;
                    r.tactic = Some(Tactic::DefenseEvasion);
                } else {
                    continue;
                }
            }
            104 => {
                r.user = format!("{}\\{}", e.get("SubjectDomainName"), e.get("SubjectUserName"));
                r.detail = format!("被清除的日志: {}", e.get("Channel"));
                r.severity = Severity::Critical;
                r.tactic = Some(Tactic::DefenseEvasion);
            }
            6008 => r.severity = Severity::Low,
            _ => r.severity = Severity::Info,
        }
        events.push(r);
    }

    // ---- RDP
    for e in run(
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        ids_xpath(&[1149], days, ""),
        1000,
        &mut errors,
    ) {
        let ip = e.data.get("Param3").cloned().unwrap_or_default();
        events.push(EventRecord {
            time: e.time,
            channel: "RDP".into(),
            event_id: 1149,
            title: title_of("", 1149).into(),
            user: format!("{}\\{}", e.get("Param2"), e.get("Param1")),
            source_ip: ip_clean(&ip),
            logon_type: "10 远程桌面".into(),
            detail: "远程桌面网络级认证成功".into(),
            severity: if super::util::is_private_ip_str(&ip) { Severity::Info } else { Severity::Medium },
            tactic: Some(Tactic::InitialAccess),
            ..Default::default()
        });
    }
    for e in run(
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        ids_xpath(&[21, 24, 25], days, ""),
        1000,
        &mut errors,
    ) {
        let ip = e.get("Address");
        events.push(EventRecord {
            time: e.time,
            channel: "RDP".into(),
            event_id: e.id,
            title: title_of("", e.id).into(),
            user: e.get("User"),
            source_ip: if ip.contains('.') || ip.contains(':') { ip_clean(&ip) } else { String::new() },
            detail: format!("会话 ID: {} 来源: {}", e.get("SessionID"), ip),
            severity: Severity::Info,
            tactic: Some(Tactic::InitialAccess),
            ..Default::default()
        });
    }

    // ---- PowerShell
    let mut seen_scripts = std::collections::HashSet::new();
    for e in run(
        "Microsoft-Windows-PowerShell/Operational",
        format!("*[System[(EventID=4104) and (Level=3) and {}]]", time_filter(days)),
        500,
        &mut errors,
    ) {
        // 长脚本会被拆成多条记录，只保留第一段，并按内容去重
        let part = e.get("MessageNumber");
        if !part.is_empty() && part != "1" {
            continue;
        }
        let script = e.get("ScriptBlockText");
        let key: String = script.chars().take(200).collect();
        if !seen_scripts.insert(key) {
            continue;
        }
        let short: String = script.chars().take(600).collect();
        events.push(EventRecord {
            time: e.time,
            channel: "PowerShell".into(),
            event_id: 4104,
            title: title_of("", 4104).into(),
            process: e.get("Path"),
            detail: short,
            severity: Severity::Medium,
            tactic: Some(Tactic::Execution),
            ..Default::default()
        });
    }
    // ---- PowerShell 2.0 引擎被调用（旧版引擎不产生脚本块日志）
    for e in run("Windows PowerShell", ids_xpath(&[400], days, ""), 3000, &mut errors) {
        let data = e.raw_data.join("\n");
        let engine = data
            .lines()
            .find_map(|l| l.trim().strip_prefix("EngineVersion="))
            .unwrap_or("")
            .to_string();
        if !engine.starts_with("2.") {
            continue;
        }
        let host_app = data.lines().find_map(|l| l.trim().strip_prefix("HostApplication=")).unwrap_or("").to_string();
        events.push(EventRecord {
            time: e.time,
            channel: "PowerShell".into(),
            event_id: 400,
            title: "PowerShell 2.0 引擎被调用".into(),
            detail: host_app,
            severity: Severity::High,
            tactic: Some(Tactic::DefenseEvasion),
            ..Default::default()
        });
    }

    // ---- Defender
    for e in run(
        "Microsoft-Windows-Windows Defender/Operational",
        ids_xpath(&[1116, 1117, 5001, 5007, 5010, 5012], days, ""),
        1000,
        &mut errors,
    ) {
        let mut r = EventRecord {
            time: e.time,
            channel: "Defender".into(),
            event_id: e.id,
            title: title_of("", e.id).into(),
            ..Default::default()
        };
        match e.id {
            1116 | 1117 => {
                r.detail = format!("威胁: {} 严重性: {} 操作: {}", e.get("Threat Name"), e.get("Severity Name"), e.get("Action Name"));
                r.process = e.get("Path");
                r.user = e.get("Detection User");
                r.severity = if e.id == 1116 { Severity::High } else { Severity::Medium };
                r.tactic = Some(Tactic::Execution);
            }
            5007 => {
                let newv = e.get("New Value");
                if !newv.contains("Exclusions") && !newv.contains("DisableRealtimeMonitoring") && !newv.contains("DisableAntiSpyware") {
                    continue;
                }
                r.detail = format!("新值: {newv}");
                r.severity = Severity::High;
                r.tactic = Some(Tactic::DefenseEvasion);
            }
            _ => {
                r.detail = "Defender 防护能力被关闭".into();
                r.severity = Severity::High;
                r.tactic = Some(Tactic::DefenseEvasion);
            }
        }
        events.push(r);
    }

    // ---- 计划任务操作日志
    for e in run(
        "Microsoft-Windows-TaskScheduler/Operational",
        ids_xpath(&[106, 140, 141], days, ""),
        1000,
        &mut errors,
    ) {
        let task = e.get("TaskName");
        if task.to_ascii_lowercase().starts_with("\\microsoft\\") {
            continue;
        }
        events.push(EventRecord {
            time: e.time,
            channel: "TaskScheduler".into(),
            event_id: e.id,
            title: title_of("", e.id).into(),
            user: e.get("UserContext").to_string() + &e.get("UserName"),
            detail: format!("任务: {task}"),
            severity: if e.id == 106 { Severity::Medium } else { Severity::Low },
            tactic: Some(Tactic::Persistence),
            ..Default::default()
        });
    }

    // ---- WMI 永久订阅
    for e in run("Microsoft-Windows-WMI-Activity/Operational", ids_xpath(&[5861], days, ""), 200, &mut errors) {
        events.push(EventRecord {
            time: e.time,
            channel: "WMI".into(),
            event_id: 5861,
            title: title_of("", 5861).into(),
            detail: format!("{} {}", e.get("ESS"), e.get("PossibleCause")).chars().take(600).collect(),
            severity: Severity::High,
            tactic: Some(Tactic::Persistence),
            ..Default::default()
        });
    }

    // ---- BITS 下载
    for e in run("Microsoft-Windows-Bits-Client/Operational", ids_xpath(&[59], days, ""), 1000, &mut errors) {
        let url = e.get("url");
        let lower = url.to_ascii_lowercase();
        let benign = ["microsoft.com", "windowsupdate.com", "msedge.net", "office.net", "office.com", "windows.com", "live.com", "bing.com", "msn.com", "delivery.mp.microsoft", "azureedge.net", "skype.com", "onedrive"]
            .iter()
            .any(|d| lower.contains(d));
        if benign || url.is_empty() {
            continue;
        }
        events.push(EventRecord {
            time: e.time,
            channel: "BITS".into(),
            event_id: 59,
            title: "BITS 下载任务（非微软域名）".into(),
            detail: format!("任务: {} URL: {}", e.get("name"), url),
            severity: Severity::Medium,
            tactic: Some(Tactic::CommandAndControl),
            ..Default::default()
        });
    }

    events.sort_by(|a, b| b.time.cmp(&a.time));
    // 通道不存在/未启用的错误不算异常
    errors.retain(|e| !e.contains("15007") && !e.to_ascii_lowercase().contains("not found") && !e.contains("找不到"));
    EventCollection { events, errors }
}

fn task_command(xml: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let cmd = doc.descendants().find(|n| n.has_tag_name("Command"))?.text()?.to_string();
    let args = doc
        .descendants()
        .find(|n| n.has_tag_name("Arguments"))
        .and_then(|n| n.text())
        .unwrap_or("");
    Some(format!("{cmd} {args}").trim().to_string())
}

/// 将关键日志通道导出为 .evtx 原始证据。
pub fn export_evtx(channel: &str, target: &std::path::Path) -> Result<(), String> {
    let wc = wide(channel);
    let wq = wide("*");
    let wt = wide(&target.display().to_string());
    unsafe {
        EvtExportLog(
            None,
            PCWSTR(wc.as_ptr()),
            PCWSTR(wq.as_ptr()),
            PCWSTR(wt.as_ptr()),
            EvtExportLogChannelPath.0 | EvtExportLogOverwrite.0,
        )
        .map_err(|e| e.message().to_string())
    }
}
