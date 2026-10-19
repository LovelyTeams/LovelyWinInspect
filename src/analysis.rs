//! 研判引擎：对采集结果做规则匹配，生成调查发现、入侵时间线与攻击链。

use std::collections::{HashMap, HashSet};

use crate::collect::util::{is_suspicious_dir, is_system_dir};
use crate::model::*;

/// 通用命令行特征（参数层面的行为特征，不含具体工具名单）。
pub fn cmdline_flags(cmd: &str) -> Vec<(Severity, &'static str)> {
    let mut out = Vec::new();
    if cmd.is_empty() {
        return out;
    }
    let lower = format!(" {} ", cmd.to_ascii_lowercase());
    let is_ps = lower.contains("powershell") || lower.contains("pwsh");
    if is_ps && (lower.contains(" -enc") || lower.contains(" -e ") || lower.contains(" -ec ")) {
        out.push((Severity::Medium, "PowerShell 使用编码命令参数"));
    }
    if is_ps && (lower.contains(" -w hidden") || lower.contains(" -windowstyle hidden") || lower.contains(" -w 1 ")) {
        out.push((Severity::Low, "PowerShell 以隐藏窗口运行"));
    }
    out
}

// ---------------------------------------------------------------- 系统进程画像

/// (进程名, 期望目录(小写后缀), 期望父进程)
const SYSTEM_PROCS: &[(&str, &[&str], &[&str])] = &[
    ("svchost.exe", &["\\system32\\svchost.exe", "\\syswow64\\svchost.exe"], &["services.exe", "svchost.exe"]),
    ("lsass.exe", &["\\system32\\lsass.exe"], &["wininit.exe"]),
    ("services.exe", &["\\system32\\services.exe"], &["wininit.exe"]),
    ("csrss.exe", &["\\system32\\csrss.exe"], &[]),
    ("wininit.exe", &["\\system32\\wininit.exe"], &[]),
    ("winlogon.exe", &["\\system32\\winlogon.exe"], &[]),
    ("smss.exe", &["\\system32\\smss.exe"], &["system", "smss.exe"]),
    ("spoolsv.exe", &["\\system32\\spoolsv.exe"], &["services.exe"]),
    ("lsm.exe", &["\\system32\\lsm.exe"], &["wininit.exe"]),
    ("explorer.exe", &["\\windows\\explorer.exe", "\\syswow64\\explorer.exe"], &[]),
    ("taskhostw.exe", &["\\system32\\taskhostw.exe"], &[]),
    ("conhost.exe", &["\\system32\\conhost.exe"], &[]),
    ("dllhost.exe", &["\\system32\\dllhost.exe", "\\syswow64\\dllhost.exe"], &[]),
    ("rundll32.exe", &["\\system32\\rundll32.exe", "\\syswow64\\rundll32.exe"], &[]),
    ("cmd.exe", &["\\system32\\cmd.exe", "\\syswow64\\cmd.exe"], &[]),
    ("powershell.exe", &["\\windowspowershell\\v1.0\\powershell.exe"], &[]),
    ("dwm.exe", &["\\system32\\dwm.exe"], &[]),
    ("ctfmon.exe", &["\\system32\\ctfmon.exe", "\\syswow64\\ctfmon.exe"], &[]),
    ("sihost.exe", &["\\system32\\sihost.exe"], &[]),
    ("runtimebroker.exe", &["\\system32\\runtimebroker.exe"], &[]),
    ("userinit.exe", &["\\system32\\userinit.exe"], &[]),
    ("wmiprvse.exe", &["\\system32\\wbem\\wmiprvse.exe", "\\syswow64\\wbem\\wmiprvse.exe"], &[]),
    ("searchindexer.exe", &["\\system32\\searchindexer.exe"], &[]),
];

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

const OFFICE: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "wps.exe", "et.exe", "wpp.exe", "acrord32.exe", "foxitreader.exe", "hwp.exe"];
const WEB_SERVERS: &[&str] = &["w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat8.exe", "tomcat9.exe", "java.exe", "javaw.exe", "php-cgi.exe", "php.exe", "sqlservr.exe", "mysqld.exe", "weblogic.exe", "redis-server.exe"];
const SHELLS: &[&str] = &["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"];
const REMOTE_TOOLS: &[&str] = &["anydesk", "teamviewer", "todesk", "sunloginclient", "向日葵", "rustdesk", "radmin", "vncserver", "winvnc", "ammyy", "splashtop", "gotohttp", "parsec"];

fn assess_process(p: &mut ProcessInfo, conns: u32) {
    let name = p.name.to_ascii_lowercase();
    let path = p.path.to_ascii_lowercase();
    let parent = p.parent_name.to_ascii_lowercase();
    let add = |p: &mut ProcessInfo, sev: Severity, why: String| {
        if sev > p.risk {
            p.risk = sev;
        }
        p.reasons.push(why);
    };

    // 系统进程伪装：同名但路径不符 / 父进程异常
    if let Some((_, paths, parents)) = SYSTEM_PROCS.iter().find(|(n, _, _)| *n == name) {
        if !path.is_empty() && !paths.iter().any(|s| path.ends_with(s)) {
            add(p, Severity::Critical, format!("系统进程名伪装：{} 不应位于 {}", p.name, p.path));
        }
        if !parents.is_empty() && !parent.is_empty() && !parents.contains(&parent.as_str()) {
            add(p, Severity::High, format!("父进程异常：{} 的父进程为 {}", p.name, p.parent_name));
        }
    } else {
        // 名称与系统进程高度相似（svch0st.exe / lsasss.exe）
        for (sys, _, _) in SYSTEM_PROCS {
            if name.len() > 5 && edit_distance(&name, sys) == 1 {
                add(p, Severity::High, format!("进程名疑似仿冒系统进程 {sys}"));
                break;
            }
        }
    }

    if !path.is_empty() && is_suspicious_dir(&path) {
        let sev = if p.sign == SignState::Unsigned { Severity::High } else { Severity::Low };
        add(p, sev, "从临时/公共/用户可写目录运行".into());
    }
    if p.sign == SignState::Unsigned {
        let sev = if is_system_dir(&path) { Severity::High } else { Severity::Low };
        let why = if conns > 0 { "无有效数字签名且存在外联" } else { "可执行文件无有效数字签名" };
        add(p, sev, why.into());
    }
    for (sev, why) in cmdline_flags(&p.cmdline) {
        add(p, sev, why.into());
    }
    if OFFICE.contains(&parent.as_str()) && SHELLS.contains(&name.as_str()) {
        add(p, Severity::High, format!("办公软件 {} 启动了 {}", p.parent_name, p.name));
    }
    if WEB_SERVERS.contains(&parent.as_str()) && SHELLS.contains(&name.as_str()) {
        add(p, Severity::Critical, format!("Web/数据库服务 {} 启动了 {}", p.parent_name, p.name));
    }
    if REMOTE_TOOLS.iter().any(|t| name.contains(t)) {
        add(p, Severity::Low, "远程控制软件（需确认是否授权使用）".into());
    }
}


const SUSPICIOUS_PORTS: &[u16] = &[4444, 5555, 6666, 7777, 8888, 9999, 1080, 1337, 31337, 2222, 12345, 6667];
const LOLBIN_NET: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "notepad.exe"];

fn assess_conn(c: &mut ConnInfo, proc_: Option<&ProcessInfo>) {
    if !c.external || c.state == "LISTEN" {
        return;
    }
    let name = c.process.to_ascii_lowercase();
    if let Some(p) = proc_ {
        if p.risk >= Severity::Medium {
            c.risk = c.risk.max(p.risk);
            c.reasons.push(format!("所属进程可疑：{}", p.reasons.first().cloned().unwrap_or_default()));
        }
    }
    if LOLBIN_NET.contains(&name.as_str()) {
        c.risk = c.risk.max(Severity::High);
        c.reasons.push(format!("系统脚本/工具程序 {} 直接发起外联", c.process));
    }
    if SUSPICIOUS_PORTS.contains(&c.remote_port) {
        c.risk = c.risk.max(Severity::Medium);
        c.reasons.push(format!("远端端口 {} 不属于常见业务端口", c.remote_port));
    }
    if c.risk == Severity::Info {
        c.risk = Severity::Info;
    }
}

// ---------------------------------------------------------------- 总入口

pub fn analyze(r: &mut ScanReport) {
    let since = crate::collect::util::days_ago(r.lookback_days);

    // 进程 + 网络
    let mut conn_count: HashMap<u32, u32> = HashMap::new();
    for c in &r.connections {
        if c.external && c.state != "LISTEN" {
            *conn_count.entry(c.pid).or_default() += 1;
        }
    }
    for p in &mut r.processes {
        p.net_conns = conn_count.get(&p.pid).copied().unwrap_or(0);
        p.risk = Severity::Info;
        p.reasons.clear();
        assess_process(p, p.net_conns);
    }
    let pmap: HashMap<u32, ProcessInfo> = r.processes.iter().map(|p| (p.pid, p.clone())).collect();
    for c in &mut r.connections {
        c.risk = Severity::Info;
        c.reasons.clear();
        assess_conn(c, pmap.get(&c.pid));
    }

    // 账户
    let created: HashMap<String, Time> = r
        .events
        .iter()
        .filter(|e| e.event_id == 4720)
        .filter_map(|e| {
            let name = e.detail.rsplit('\\').next()?.trim().to_ascii_lowercase();
            Some((name, e.time?))
        })
        .collect();
    for a in &mut r.accounts {
        let lname = a.name.to_ascii_lowercase();
        a.created = created.get(&lname).copied();
        a.is_admin = a.is_admin || a.groups.iter().any(|g| crate::collect::baseline::is_admin_group(g));
        if a.name.ends_with('$') {
            a.risk = Severity::Critical;
            a.reasons.push("账户名以 $ 结尾，属于隐藏账户".into());
        }
        if a.comment == "仅存在于 SAM 注册表中" {
            a.risk = Severity::Critical;
        }
        if a.pwd_not_required && !a.disabled {
            a.risk = a.risk.max(Severity::High);
            a.reasons.push("允许空密码".into());
        }
        if a.rid == 501 && !a.disabled {
            a.risk = a.risk.max(Severity::High);
            a.reasons.push("Guest 账户处于启用状态".into());
            if a.is_admin {
                a.risk = Severity::Critical;
                a.reasons.push("Guest 被加入管理员组".into());
            }
        }
        if let Some(t) = a.created {
            if t >= since {
                a.risk = a.risk.max(if a.is_admin { Severity::Critical } else { Severity::High });
                a.reasons.push(format!("近期新建账户（{}）", t.format("%Y-%m-%d %H:%M")));
            }
        }
        if a.is_admin && !a.disabled && a.rid != 500 && a.risk < Severity::Low {
            a.risk = Severity::Low;
            a.reasons.push("具有管理员权限".into());
        }
    }

    // 事件：暴力破解聚合
    let mut fail_by_ip: HashMap<String, (usize, Option<Time>, Option<Time>, HashSet<String>)> = HashMap::new();
    for e in r.events.iter().filter(|e| e.event_id == 4625) {
        let key = if e.source_ip.is_empty() { "本地".to_string() } else { e.source_ip.clone() };
        let ent = fail_by_ip.entry(key).or_insert((0, None, None, HashSet::new()));
        ent.0 += 1;
        ent.1 = match (ent.1, e.time) { (Some(a), Some(b)) => Some(a.min(b)), (a, b) => a.or(b) };
        ent.2 = match (ent.2, e.time) { (Some(a), Some(b)) => Some(a.max(b)), (a, b) => a.or(b) };
        ent.3.insert(e.user.clone());
    }

    // 审计/日志配置缺口：决定日志类结论的可信度
    let status = |id: &str| r.baseline.iter().find(|b| b.id == id).map(|b| (b.status, b.actual.clone()));
    let mut gaps = Vec::new();
    for (id, what) in [("AUD-01", "登录审核"), ("AUD-05", "进程创建审核"), ("AUD-03", "账户管理审核"), ("AUD-11", "进程命令行记录"), ("AUD-12", "PowerShell 脚本块日志"), ("LOG-01", "安全日志容量")] {
        if let Some((st, actual)) = status(id) {
            if st == CheckStatus::Fail || st == CheckStatus::Warn {
                gaps.push(format!("{what}: {actual}"));
            }
        }
    }
    r.log_gaps = gaps;

    // ------------------------------------------------ 生成调查发现
    let mut findings: Vec<Finding> = Vec::new();
    for p in r.processes.iter().filter(|p| p.risk >= Severity::Medium) {
        findings.push(Finding {
            time: p.start_time,
            category: Category::Process,
            severity: p.risk,
            object: format!("{} ({})", p.name, p.pid),
            title: p.reasons.first().cloned().unwrap_or_default(),
            detail: format!("{}\n命令行: {}\n父进程: {} ({})\n用户: {}", p.reasons.join("；"), p.cmdline, p.parent_name, p.ppid, p.user),
            target: p.path.clone(),
            tactic: Some(Tactic::Execution),
            technique: "T1059 / T1036".into(),
            advice: "核实进程来源；确认恶意后结束进程树、提取样本并隔离文件，排查其持久化与外联".into(),
        });
    }
    for c in r.connections.iter().filter(|c| c.risk >= Severity::Medium) {
        findings.push(Finding {
            time: None,
            category: Category::Network,
            severity: c.risk,
            object: format!("{}:{}", c.remote_addr, c.remote_port),
            title: c.reasons.first().cloned().unwrap_or_else(|| "可疑外联".into()),
            detail: format!("{}\n进程: {} ({})\n本地: {}:{} 状态: {}", c.reasons.join("；"), c.process, c.pid, c.local_addr, c.local_port, c.state),
            target: c.path.clone(),
            tactic: Some(Tactic::CommandAndControl),
            technique: "T1071".into(),
            advice: "在边界设备封禁该 IP 并溯源威胁情报；结合进程排查是否为远控木马".into(),
        });
    }
    for it in r.persistence.iter().filter(|i| i.risk >= Severity::Medium) {
        findings.push(Finding {
            time: it.time,
            category: Category::Persistence,
            severity: it.risk,
            object: it.name.clone(),
            title: format!("{}：{}", it.kind.label(), it.reasons.first().cloned().unwrap_or_default()),
            detail: format!("{}\n命令: {}\n位置: {}\n{}", it.reasons.join("；"), it.command, it.location, it.extra),
            target: if it.image.is_empty() { it.location.clone() } else { it.image.clone() },
            tactic: Some(persist_tactic(it.kind)),
            technique: persist_technique(it.kind).into(),
            advice: "备份后删除该启动项，并对其指向的文件做样本分析与全盘查杀".into(),
        });
    }
    // 近期写入的根证书（单条汇总，低风险提示）
    let certs: Vec<&PersistItem> = r
        .persistence
        .iter()
        .filter(|i| i.kind == PersistKind::RootCert && i.risk == Severity::Low)
        .collect();
    if !certs.is_empty() {
        findings.push(Finding {
            time: certs.iter().filter_map(|c| c.time).max(),
            category: Category::Persistence,
            severity: Severity::Low,
            object: "受信任根证书".into(),
            title: format!("回溯期内新写入 {} 个自签名受信任根证书", certs.len()),
            detail: certs
                .iter()
                .take(10)
                .map(|c| format!("{} · {} · {}", c.name, c.time.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(), c.extra))
                .collect::<Vec<_>>()
                .join("\n"),
            target: certs[0].location.clone(),
            tactic: Some(Tactic::DefenseEvasion),
            technique: persist_technique(PersistKind::RootCert).into(),
            advice: "核实证书来源（安全软件 / 抓包代理 / 开发工具 / 企业 CA），非授权证书在 certlm.msc 或 certmgr.msc 中删除".into(),
        });
    }
    for n in r.neighbors.iter().filter(|n| n.risk >= Severity::Medium) {
        findings.push(Finding {
            time: None,
            category: Category::Network,
            severity: n.risk,
            object: format!("{} ({})", n.ip, n.mac),
            title: n.reasons.first().cloned().unwrap_or_default(),
            detail: format!("{}\n接口: {}\n状态: {}", n.reasons.join("；"), n.interface, n.state),
            target: "ARP 表".into(),
            tactic: Some(Tactic::CredentialAccess),
            technique: "T1557.002".into(),
            advice: "在交换机上核对网关真实 MAC，排查同网段中冒充网关的主机；必要时绑定静态 ARP 并启用 DAI".into(),
        });
    }
    for d in r.dns_cache.iter().filter(|d| d.risk >= Severity::Medium) {
        findings.push(Finding {
            time: None,
            category: Category::Network,
            severity: d.risk,
            object: d.name.clone(),
            title: d.reasons.first().cloned().unwrap_or_default(),
            detail: format!("{} {} → {}", d.name, d.rtype, d.data),
            target: "DNS 缓存".into(),
            tactic: Some(Tactic::CommandAndControl),
            technique: "T1071.004".into(),
            advice: "核对本机 DNS 服务器与 Hosts 配置，确认解析结果是否被篡改".into(),
        });
    }
    for a in r.accounts.iter().filter(|a| a.risk >= Severity::Medium) {
        findings.push(Finding {
            time: a.created.or(a.last_logon),
            category: Category::Account,
            severity: a.risk,
            object: a.name.clone(),
            title: a.reasons.first().cloned().unwrap_or_default(),
            detail: format!("{}\n所属组: {}\n最后登录: {}", a.reasons.join("；"), a.groups.join(", "), a.last_logon.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or("-".into())),
            target: format!("RID {}", a.rid),
            tactic: Some(Tactic::Persistence),
            technique: "T1136.001 / T1564.002".into(),
            advice: "确认账户来源，非授权账户应立即禁用并删除，同时重置所有管理员口令".into(),
        });
    }
    for (ip, (n, first, last, users)) in &fail_by_ip {
        if *n < 10 {
            continue;
        }
        let success: Vec<&EventRecord> = r
            .events
            .iter()
            .filter(|e| e.event_id == 4624 && &e.source_ip == ip && e.time >= *first)
            .collect();
        let sev = if !success.is_empty() { Severity::Critical } else if *n >= 50 { Severity::High } else { Severity::Medium };
        let mut users: Vec<&String> = users.iter().collect();
        users.sort();
        findings.push(Finding {
            time: *last,
            category: Category::EventLog,
            severity: sev,
            object: ip.clone(),
            title: if success.is_empty() { format!("疑似口令暴力破解（失败 {n} 次）") } else { format!("暴力破解后登录成功（失败 {n} 次）") },
            detail: format!(
                "时间范围: {} ~ {}\n尝试账户: {}{}",
                first.map(|t| t.format("%m-%d %H:%M").to_string()).unwrap_or_default(),
                last.map(|t| t.format("%m-%d %H:%M").to_string()).unwrap_or_default(),
                users.iter().take(10).map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                success.first().map(|s| format!("\n成功登录: {} {} {}", s.time.map(|t| t.format("%m-%d %H:%M:%S").to_string()).unwrap_or_default(), s.user, s.logon_type)).unwrap_or_default()
            ),
            target: "Security 4625".into(),
            tactic: Some(if success.is_empty() { Tactic::CredentialAccess } else { Tactic::InitialAccess }),
            technique: "T1110".into(),
            advice: "封禁来源 IP，启用账户锁定策略，排查被爆破成功账户的后续操作".into(),
        });
    }
    let ps_warn: Vec<&EventRecord> = r.events.iter().filter(|e| e.event_id == 4104).collect();
    if !ps_warn.is_empty() {
        let mut paths: Vec<&str> = ps_warn.iter().map(|e| e.process.as_str()).filter(|p| !p.is_empty()).collect();
        paths.sort();
        paths.dedup();
        findings.push(Finding {
            time: ps_warn.first().and_then(|e| e.time),
            category: Category::EventLog,
            severity: Severity::Medium,
            object: "PowerShell 4104".into(),
            title: format!("系统标记的 PowerShell 脚本块告警 {} 条", ps_warn.len()),
            detail: format!("涉及脚本: {}
最近一条: {}", if paths.is_empty() { "交互式/内联".to_string() } else { paths.iter().take(8).cloned().collect::<Vec<_>>().join(", ") }, ps_warn[0].detail.chars().take(300).collect::<String>()),
            target: "Microsoft-Windows-PowerShell/Operational".into(),
            tactic: Some(Tactic::Execution),
            technique: "T1059.001".into(),
            advice: "在“日志”页按 4104 过滤逐条复核脚本内容与来源".into(),
        });
    }
    for e in r.events.iter().filter(|e| e.severity >= Severity::High && e.event_id != 4104) {
        findings.push(Finding {
            time: e.time,
            category: Category::EventLog,
            severity: e.severity,
            object: format!("{} {}", e.channel, e.event_id),
            title: e.title.clone(),
            detail: format!("{}\n用户: {} 来源: {}\n{}", e.detail, e.user, e.source_ip, e.process),
            target: if e.process.is_empty() { e.user.clone() } else { e.process.clone() },
            tactic: e.tactic,
            technique: String::new(),
            advice: "结合时间线排查该事件前后的登录与进程行为".into(),
        });
    }
    // 外网 RDP 登录
    let mut rdp_ext: HashMap<String, (usize, Option<Time>, String)> = HashMap::new();
    for e in r.events.iter().filter(|e| (e.event_id == 4624 || e.event_id == 1149) && !e.source_ip.is_empty() && !crate::collect::util::is_private_ip_str(&e.source_ip)) {
        let ent = rdp_ext.entry(e.source_ip.clone()).or_insert((0, None, e.user.clone()));
        ent.0 += 1;
        ent.1 = ent.1.max(e.time);
    }
    for (ip, (n, last, user)) in rdp_ext {
        findings.push(Finding {
            time: last,
            category: Category::EventLog,
            severity: Severity::Medium,
            object: ip,
            title: format!("公网地址成功登录 {n} 次"),
            detail: format!("账户: {user}"),
            target: "Security 4624 / RDP 1149".into(),
            tactic: Some(Tactic::InitialAccess),
            technique: "T1078 / T1133".into(),
            advice: "确认是否为合法运维来源，必要时限制 RDP 仅允许 VPN/堡垒机访问".into(),
        });
    }
    // 同一目录、同一原因的大量落地文件（如解压出的整套未签名程序）合并为一条
    let mut file_groups: Vec<(String, String, Vec<&FileArtifact>)> = Vec::new();
    let mut group_idx: HashMap<(String, String), usize> = HashMap::new();
    for f in r.files.iter().filter(|f| f.risk >= Severity::Medium) {
        let reason = f.reasons.first().cloned().unwrap_or_default();
        let groupable = matches!(f.kind, ArtifactKind::RecentFile | ArtifactKind::WebChange | ArtifactKind::AltStream);
        let dir = if groupable { f.path.rsplit_once('\\').map(|(d, _)| d.to_string()).unwrap_or_default() } else { f.path.clone() + "\u{0}" + &f.note };
        let i = *group_idx.entry((dir.clone(), reason.clone())).or_insert_with(|| {
            file_groups.push((dir, reason, Vec::new()));
            file_groups.len() - 1
        });
        file_groups[i].2.push(f);
    }
    for (dir, reason, group) in &file_groups {
        let f = group[0];
        let technique = if f.kind == ArtifactKind::AltStream { "T1564.004" } else { "" };
        if group.len() <= 3 {
            for f in group {
                findings.push(Finding {
                    time: f.modified,
                    category: Category::File,
                    severity: f.risk,
                    object: if f.kind == ArtifactKind::Hosts { "hosts".into() } else { f.name.clone() },
                    title: format!("{}：{}", f.kind.label(), f.reasons.first().cloned().unwrap_or_default()),
                    detail: format!("{}\n{}\nSHA256: {}", f.reasons.join("\n"), f.note, if f.sha256.is_empty() { "-" } else { &f.sha256 }),
                    target: f.path.clone(),
                    tactic: Some(artifact_tactic(f.kind)),
                    technique: technique.into(),
                    advice: "记录哈希并核实文件来源，确认无业务用途后隔离处理".into(),
                });
            }
            continue;
        }
        let names: Vec<&str> = group.iter().take(15).map(|f| f.name.as_str()).collect();
        findings.push(Finding {
            time: group.iter().filter_map(|f| f.modified).max(),
            category: Category::File,
            severity: group.iter().map(|f| f.risk).max().unwrap_or(f.risk),
            object: format!("{} 个文件", group.len()),
            title: format!("{}：{}（同一目录 {} 个）", f.kind.label(), reason, group.len()),
            detail: format!("目录: {dir}\n{}{}", names.join("\n"), if group.len() > names.len() { format!("\n… 共 {} 个，逐个详情见“文件”页", group.len()) } else { String::new() }),
            target: dir.clone(),
            tactic: Some(artifact_tactic(f.kind)),
            technique: technique.into(),
            advice: "确认该目录内容来源（如解压的软件包），无业务用途时整体隔离；逐个文件的哈希与签名见“文件”页".into(),
        });
    }
    for s in r.sessions.iter().filter(|s| s.risk >= Severity::Medium) {
        findings.push(Finding {
            time: s.logon_time,
            category: Category::Account,
            severity: s.risk,
            object: s.client_ip.clone(),
            title: s.reasons.first().cloned().unwrap_or_default(),
            detail: format!("类型: {}\n用户: {}\n状态: {}\n客户端: {}", s.kind, s.user, s.state, s.client),
            target: s.user.clone(),
            tactic: Some(Tactic::InitialAccess),
            technique: "T1021".into(),
            advice: "确认会话来源是否为授权运维；非授权时立即注销会话并封禁来源地址".into(),
        });
    }
    if !r.log_gaps.is_empty() {
        findings.push(Finding {
            time: None,
            category: Category::Baseline,
            severity: Severity::Low,
            object: "审计与日志配置".into(),
            title: "审计/日志配置不完整，日志类结论可能缺失".into(),
            detail: r.log_gaps.join("\n"),
            target: "基线核查 → 审计策略 / 日志配置".into(),
            tactic: None,
            technique: String::new(),
            advice: "处置完成后补齐审计策略与日志容量，便于后续溯源".into(),
        });
    }
    for c in r.baseline.iter().filter(|c| c.status == CheckStatus::Fail && c.severity >= Severity::High) {
        findings.push(Finding {
            time: None,
            category: Category::Baseline,
            severity: Severity::Medium,
            object: c.title.clone(),
            title: format!("基线不符合：{}", c.title),
            detail: format!("期望: {}\n实际: {}", c.expected, c.actual),
            target: c.id.clone(),
            tactic: None,
            technique: String::new(),
            advice: c.advice.clone(),
        });
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.time.cmp(&a.time)));
    r.findings = findings;

    // ------------------------------------------------ 时间线
    let mut tl: Vec<TimelineEvent> = Vec::new();
    for e in &r.events {
        let Some(t) = e.time else { continue };
        if e.event_id == 4625 || (e.severity == Severity::Info && ![4624, 6005, 6006, 21, 1149].contains(&e.event_id)) {
            continue;
        }
        tl.push(TimelineEvent {
            time: t,
            source: format!("{} {}", e.channel, e.event_id),
            title: e.title.clone(),
            detail: [e.user.as_str(), e.source_ip.as_str(), e.logon_type.as_str(), e.detail.as_str(), e.process.as_str()]
                .iter()
                .filter(|s| !s.is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join(" · "),
            severity: e.severity,
            tactic: e.tactic,
        });
    }
    for (ip, (n, first, last, _)) in &fail_by_ip {
        if *n < 5 {
            continue;
        }
        if let Some(t) = *first {
            tl.push(TimelineEvent {
                time: t,
                source: "Security 4625".into(),
                title: format!("开始出现登录失败（来源 {ip}，共 {n} 次）"),
                detail: format!("持续至 {}", last.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()),
                severity: if *n >= 10 { Severity::High } else { Severity::Medium },
                tactic: Some(Tactic::CredentialAccess),
            });
        }
    }
    for it in &r.persistence {
        let Some(t) = it.time else { continue };
        let cert = it.kind == PersistKind::RootCert;
        if t < since || (it.risk < Severity::Medium && it.kind != PersistKind::ScheduledTask && !(cert && it.risk >= Severity::Low)) {
            continue;
        }
        if it.kind == PersistKind::ScheduledTask && it.name.to_ascii_lowercase().starts_with("\\microsoft\\") && it.risk < Severity::Medium {
            continue;
        }
        tl.push(TimelineEvent {
            time: t,
            source: it.kind.label().into(),
            title: if cert { format!("根证书写入：{}", it.name) } else { format!("{} 被创建/修改", it.name) },
            detail: format!("{} {}", it.command, it.reasons.join("；")),
            severity: it.risk.max(Severity::Low),
            tactic: Some(persist_tactic(it.kind)),
        });
    }
    for f in &r.files {
        let t = match f.kind {
            ArtifactKind::Prefetch => f.modified,
            _ => f.created.max(f.modified),
        };
        let Some(t) = t else { continue };
        // 用户活动类痕迹即使为“信息”级也进入时间线（默认筛选“低及以上”时不显示）
        let activity = matches!(f.kind, ArtifactKind::Bam | ArtifactKind::Software | ArtifactKind::Usb | ArtifactKind::RdpOutbound | ArtifactKind::RunMru);
        if t < since || (f.risk < Severity::Low && !activity) || f.kind == ArtifactKind::Hosts || f.kind == ArtifactKind::PsHistory {
            continue;
        }
        tl.push(TimelineEvent {
            time: t,
            source: f.kind.label().into(),
            title: match f.kind {
                ArtifactKind::Prefetch => format!("程序执行：{}", f.note.trim_start_matches("程序: ")),
                ArtifactKind::Bam => format!("程序执行：{}", f.name),
                ArtifactKind::RecentDoc => format!("文件访问：{}", f.name.trim_end_matches(".lnk")),
                ArtifactKind::RunMru => format!("运行对话框：{}", f.name),
                ArtifactKind::RdpOutbound => format!("远程桌面外连：{}", f.name),
                ArtifactKind::Software => format!("安装软件：{}", f.name),
                ArtifactKind::Usb => format!("USB 存储设备：{}", f.name),
                ArtifactKind::AltStream => format!("备用数据流：{}", f.name),
                _ => format!("文件落地：{}", f.name),
            },
            detail: format!("{} {} {}", f.path, f.note, f.reasons.join("；")),
            severity: f.risk,
            tactic: Some(artifact_tactic(f.kind)),
        });
    }
    for p in r.processes.iter().filter(|p| p.risk >= Severity::Medium) {
        if let Some(t) = p.start_time {
            tl.push(TimelineEvent {
                time: t,
                source: "进程".into(),
                title: format!("可疑进程启动：{} ({})", p.name, p.pid),
                detail: format!("{} {}", p.cmdline, p.reasons.join("；")),
                severity: p.risk,
                tactic: Some(Tactic::Execution),
            });
        }
    }
    for a in &r.accounts {
        if let Some(t) = a.created {
            if t >= since {
                tl.push(TimelineEvent {
                    time: t,
                    source: "账户".into(),
                    title: format!("新建账户 {}", a.name),
                    detail: a.reasons.join("；"),
                    severity: a.risk.max(Severity::Medium),
                    tactic: Some(Tactic::Persistence),
                });
            }
        }
    }
    tl.retain(|e| e.time >= since);
    tl.sort_by(|a, b| b.time.cmp(&a.time));
    r.timeline = tl;
}

fn artifact_tactic(k: ArtifactKind) -> Tactic {
    match k {
        ArtifactKind::WebChange => Tactic::Persistence,
        ArtifactKind::Hosts => Tactic::DefenseEvasion,
        ArtifactKind::RdpOutbound => Tactic::LateralMovement,
        ArtifactKind::Usb => Tactic::InitialAccess,
        ArtifactKind::AltStream => Tactic::DefenseEvasion,
        _ => Tactic::Execution,
    }
}

fn persist_tactic(k: PersistKind) -> Tactic {
    match k {
        PersistKind::RootCert => Tactic::DefenseEvasion,
        _ => Tactic::Persistence,
    }
}

fn persist_technique(k: PersistKind) -> &'static str {
    match k {
        PersistKind::RunKey => "T1547.001",
        PersistKind::Service => "T1543.003",
        PersistKind::ScheduledTask => "T1053.005",
        PersistKind::StartupFolder => "T1547.001",
        PersistKind::Ifeo => "T1546.012",
        PersistKind::Winlogon => "T1547.004",
        PersistKind::AppInit => "T1546.010",
        PersistKind::Lsa => "T1547.002 / T1556.002",
        PersistKind::Wmi => "T1546.003",
        PersistKind::ComHijack => "T1546.015",
        PersistKind::BootExecute => "T1547.012",
        PersistKind::NetshHelper => "T1546.007",
        PersistKind::Accessibility => "T1546.008",
        PersistKind::FailureCommand => "T1543.003",
        PersistKind::LogonScript => "T1037.001 / T1037.003",
        PersistKind::PsProfile => "T1546.013",
        PersistKind::AppCertDlls => "T1546.009",
        PersistKind::KnownDlls | PersistKind::Wow64 => "T1574",
        PersistKind::PrintMonitor => "T1547.010",
        PersistKind::TimeProvider => "T1547.003",
        PersistKind::ActiveSetup => "T1547.014",
        PersistKind::FileAssoc => "T1546.001",
        PersistKind::ScreenSaver => "T1546.002",
        PersistKind::PortProxy => "T1090",
        PersistKind::FirewallRule => "T1562.004",
        PersistKind::RootCert => "T1553.004",
    }
}

/// 攻击链汇总：每个战术阶段的发现数与最高等级。
pub fn tactic_summary(r: &ScanReport) -> Vec<(Tactic, usize, Severity)> {
    Tactic::ALL
        .iter()
        .map(|t| {
            let items: Vec<&Finding> = r.findings.iter().filter(|f| f.tactic == Some(*t)).collect();
            let tl_max = r
                .timeline
                .iter()
                .filter(|e| e.tactic == Some(*t) && e.severity >= Severity::Medium)
                .map(|e| e.severity)
                .max();
            let max = items.iter().map(|f| f.severity).max().into_iter().chain(tl_max).max().unwrap_or(Severity::Info);
            (*t, items.len(), max)
        })
        .collect()
}
