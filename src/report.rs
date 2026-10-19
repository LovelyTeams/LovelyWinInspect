//! 报告与证据导出：JSON / HTML / CSV / 原始 evtx / 文本证据，并生成 SHA256 清单。

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::collect::{eventlog, files, util};
use crate::model::*;

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ExportOptions {
    pub json: bool,
    pub html: bool,
    pub csv: bool,
    pub evtx: bool,
    pub evidence: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self { json: true, html: true, csv: true, evtx: false, evidence: true }
    }
}

pub struct ExportResult {
    pub dir: PathBuf,
    pub files: Vec<(String, u64)>,
    pub warnings: Vec<String>,
}

pub fn default_root() -> PathBuf {
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let root = base.join("LovelyWinInspect_Reports");
    if std::fs::create_dir_all(&root).is_ok() {
        return root;
    }
    let desktop = std::env::var("USERPROFILE")
        .map(|p| PathBuf::from(p).join("Desktop").join("LovelyWinInspect_Reports"))
        .unwrap_or_else(|_| PathBuf::from("LovelyWinInspect_Reports"));
    let _ = std::fs::create_dir_all(&desktop);
    desktop
}

/// `root` 为空时使用默认目录（程序所在目录下的 LovelyWinInspect_Reports）。
pub fn export(r: &ScanReport, opts: ExportOptions, root: Option<&Path>) -> Result<ExportResult, String> {
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let host = if r.host.hostname.is_empty() { "HOST".to_string() } else { r.host.hostname.clone() };
    let root = root.map(Path::to_path_buf).unwrap_or_else(default_root);
    let dir = root.join(format!("{host}_{stamp}"));
    std::fs::create_dir_all(&dir).map_err(|e| format!("无法创建目录 {}: {e}", dir.display()))?;
    let mut warnings = Vec::new();

    if opts.json {
        let json = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("report.json"), json).map_err(|e| e.to_string())?;
    }
    if opts.html {
        std::fs::write(dir.join("report.html"), html(r)).map_err(|e| e.to_string())?;
    }
    if opts.csv {
        let csv_dir = dir.join("csv");
        let _ = std::fs::create_dir_all(&csv_dir);
        for (name, content) in csv_tables(r) {
            if let Err(e) = std::fs::write(csv_dir.join(name), content) {
                warnings.push(format!("{name}: {e}"));
            }
        }
    }
    if opts.evtx {
        let ev_dir = dir.join("evtx");
        let _ = std::fs::create_dir_all(&ev_dir);
        for ch in [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Windows PowerShell",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-WMI-Activity/Operational",
        ] {
            let name = ch.replace(['/', ' '], "_") + ".evtx";
            if let Err(e) = eventlog::export_evtx(ch, &ev_dir.join(&name)) {
                warnings.push(format!("{ch}: {e}"));
            }
        }
    }
    if opts.evidence {
        let ev = dir.join("evidence");
        let _ = std::fs::create_dir_all(&ev);
        for (name, src) in files::evidence_text_files() {
            if let Err(e) = std::fs::copy(&src, ev.join(&name)) {
                warnings.push(format!("{name}: {e}"));
            }
        }
        // 本工具执行过的处置动作记录
        let actions = crate::actions::log_path();
        if actions.is_file() {
            if let Err(e) = std::fs::copy(&actions, ev.join("actions.log")) {
                warnings.push(format!("actions.log: {e}"));
            }
        }
        // 非微软计划任务 XML
        let tasks_root = PathBuf::from(format!("{}\\System32\\Tasks", util::system_root()));
        let task_dir = ev.join("tasks");
        for it in r.persistence.iter().filter(|i| i.kind == PersistKind::ScheduledTask) {
            if it.name.to_ascii_lowercase().starts_with("\\microsoft\\") {
                continue;
            }
            let src = tasks_root.join(it.name.trim_start_matches('\\'));
            if src.is_file() {
                let flat = it.name.trim_start_matches('\\').replace('\\', "_") + ".xml";
                let _ = std::fs::create_dir_all(&task_dir);
                let _ = std::fs::copy(&src, task_dir.join(flat));
            }
        }
        let mut net = String::from("协议\t本地地址\t远程地址\t状态\tPID\t进程\t路径\n");
        for c in &r.connections {
            let _ = writeln!(net, "{}\t{}:{}\t{}:{}\t{}\t{}\t{}\t{}", c.proto, c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.state, c.pid, c.process, c.path);
        }
        let _ = std::fs::write(ev.join("netstat.txt"), with_bom(&net));
        let mut dns = String::from("域名\t类型\t解析结果\tTTL\n");
        for d in &r.dns_cache {
            let _ = writeln!(dns, "{}\t{}\t{}\t{}", d.name, d.rtype, d.data, d.ttl);
        }
        let _ = std::fs::write(ev.join("dnscache.txt"), with_bom(&dns));
        let mut arp = String::from("IP 地址\tMAC 地址\t接口\t状态\t网关\n");
        for n in &r.neighbors {
            let _ = writeln!(arp, "{}\t{}\t{}\t{}\t{}", n.ip, n.mac, n.interface, n.state, if n.is_gateway { "是" } else { "" });
        }
        let _ = std::fs::write(ev.join("arp.txt"), with_bom(&arp));
        let mut ps = String::from("PID\tPPID\t进程\t用户\t启动时间\t签名\t路径\t命令行\n");
        for p in &r.processes {
            let _ = writeln!(ps, "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", p.pid, p.ppid, p.name, p.user, fmt(p.start_time), p.sign.label(), p.path, p.cmdline);
        }
        let _ = std::fs::write(ev.join("processes.txt"), with_bom(&ps));
    }

    // 清单与哈希
    let mut listed = Vec::new();
    collect_files(&dir, &dir, &mut listed);
    let mut manifest = format!(
        "LovelyWinInspect 证据清单\n主机: {}\n导出时间: {}\n\n文件\t大小\tSHA256\n",
        host,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    let mut out_files = Vec::new();
    for (rel, path, size) in &listed {
        let hash = util::sha256_file(path, u64::MAX);
        let _ = writeln!(manifest, "{rel}\t{size}\t{hash}");
        out_files.push((rel.clone(), *size));
    }
    let _ = std::fs::write(dir.join("manifest_sha256.txt"), with_bom(&manifest));
    Ok(ExportResult { dir, files: out_files, warnings })
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf, u64)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_files(root, &p, out);
        } else {
            let rel = p.strip_prefix(root).map(|x| x.display().to_string()).unwrap_or_default();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((rel, p, size));
        }
    }
}

fn with_bom(s: &str) -> Vec<u8> {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(s.as_bytes());
    v
}

fn fmt(t: Option<Time>) -> String {
    t.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

// ---------------------------------------------------------------- CSV

fn csv_line(fields: &[String]) -> String {
    let mut s = fields
        .iter()
        .map(|f| format!("\"{}\"", f.replace('"', "\"\"").replace(['\r', '\n'], " ")))
        .collect::<Vec<_>>()
        .join(",");
    s.push_str("\r\n");
    s
}

fn csv_tables(r: &ScanReport) -> Vec<(&'static str, Vec<u8>)> {
    let mut v = Vec::new();
    let table = |head: &[&str], rows: Vec<Vec<String>>| -> Vec<u8> {
        let mut s = csv_line(&head.iter().map(|h| h.to_string()).collect::<Vec<_>>());
        for row in rows {
            s.push_str(&csv_line(&row));
        }
        with_bom(&s)
    };
    v.push(("findings.csv", table(
        &["时间", "类型", "风险", "对象", "描述", "路径/目标", "ATT&CK 战术", "技术", "详情", "处置建议"],
        r.findings.iter().map(|f| vec![fmt(f.time), f.category.label().into(), f.severity.label().into(), f.object.clone(), f.title.clone(), f.target.clone(), f.tactic.map(|t| t.label().to_string()).unwrap_or_default(), f.technique.clone(), f.detail.clone(), f.advice.clone()]).collect(),
    )));
    v.push(("baseline.csv", table(
        &["编号", "分类", "检查项", "期望值", "当前值", "结果", "风险", "加固建议"],
        r.baseline.iter().map(|b| vec![b.id.clone(), b.group.clone(), b.title.clone(), b.expected.clone(), b.actual.clone(), b.status.label().into(), b.severity.label().into(), b.advice.clone()]).collect(),
    )));
    v.push(("timeline.csv", table(
        &["时间", "来源", "风险", "战术", "事件", "详情"],
        r.timeline.iter().map(|e| vec![e.time.format("%Y-%m-%d %H:%M:%S").to_string(), e.source.clone(), e.severity.label().into(), e.tactic.map(|t| t.label().to_string()).unwrap_or_default(), e.title.clone(), e.detail.clone()]).collect(),
    )));
    v.push(("processes.csv", table(
        &["PID", "PPID", "进程", "父进程", "用户", "启动时间", "签名", "外联数", "风险", "原因", "路径", "命令行"],
        r.processes.iter().map(|p| vec![p.pid.to_string(), p.ppid.to_string(), p.name.clone(), p.parent_name.clone(), p.user.clone(), fmt(p.start_time), p.sign.label().into(), p.net_conns.to_string(), p.risk.label().into(), p.reasons.join("；"), p.path.clone(), p.cmdline.clone()]).collect(),
    )));
    v.push(("connections.csv", table(
        &["协议", "本地地址", "本地端口", "远程地址", "远程端口", "域名(DNS 缓存)", "状态", "PID", "进程", "外联", "风险", "原因", "路径"],
        r.connections.iter().map(|c| vec![c.proto.clone(), c.local_addr.clone(), c.local_port.to_string(), c.remote_addr.clone(), c.remote_port.to_string(), c.domain.clone(), c.state.clone(), c.pid.to_string(), c.process.clone(), if c.external { "是" } else { "否" }.into(), c.risk.label().into(), c.reasons.join("；"), c.path.clone()]).collect(),
    )));
    v.push(("dns_cache.csv", table(
        &["域名", "类型", "解析结果", "TTL", "风险", "原因"],
        r.dns_cache.iter().map(|d| vec![d.name.clone(), d.rtype.clone(), d.data.clone(), d.ttl.to_string(), d.risk.label().into(), d.reasons.join("；")]).collect(),
    )));
    v.push(("neighbors.csv", table(
        &["IP 地址", "MAC 地址", "接口", "状态", "静态", "网关", "风险", "原因"],
        r.neighbors.iter().map(|n| vec![n.ip.clone(), n.mac.clone(), n.interface.clone(), n.state.clone(), if n.is_static { "是" } else { "否" }.into(), if n.is_gateway { "是" } else { "否" }.into(), n.risk.label().into(), n.reasons.join("；")]).collect(),
    )));
    if let Some(list) = &r.shadow_copies {
        v.push(("shadow_copies.csv", table(
            &["ID", "卷", "设备对象", "创建时间"],
            list.iter().map(|s| vec![s.id.clone(), s.volume.clone(), s.device.clone(), fmt(s.created)]).collect(),
        )));
    }
    v.push(("persistence.csv", table(
        &["类型", "名称", "位置", "命令", "目标文件", "签名", "启用", "时间", "风险", "原因", "附加信息"],
        r.persistence.iter().map(|i| vec![i.kind.label().into(), i.name.clone(), i.location.clone(), i.command.clone(), i.image.clone(), i.sign.label().into(), if i.enabled { "是" } else { "否" }.into(), fmt(i.time), i.risk.label().into(), i.reasons.join("；"), i.extra.clone()]).collect(),
    )));
    v.push(("accounts.csv", table(
        &["用户名", "全名", "RID", "管理员", "禁用", "最后登录", "登录次数", "密码使用天数", "所属组", "风险", "原因"],
        r.accounts.iter().map(|a| vec![a.name.clone(), a.full_name.clone(), a.rid.to_string(), if a.is_admin { "是" } else { "否" }.into(), if a.disabled { "是" } else { "否" }.into(), fmt(a.last_logon), a.num_logons.to_string(), a.pwd_age_days.to_string(), a.groups.join(", "), a.risk.label().into(), a.reasons.join("；")]).collect(),
    )));
    v.push(("events.csv", table(
        &["时间", "通道", "事件ID", "事件", "用户", "来源IP", "登录类型", "进程", "详情", "风险"],
        r.events.iter().map(|e| vec![fmt(e.time), e.channel.clone(), e.event_id.to_string(), e.title.clone(), e.user.clone(), e.source_ip.clone(), e.logon_type.clone(), e.process.clone(), e.detail.clone(), e.severity.label().into()]).collect(),
    )));
    v.push(("files.csv", table(
        &["类型", "文件名", "路径", "大小", "创建时间", "修改时间", "签名", "SHA256", "说明", "下载来源", "备用数据流", "风险", "原因"],
        r.files.iter().map(|f| vec![f.kind.label().into(), f.name.clone(), f.path.clone(), f.size.to_string(), fmt(f.created), fmt(f.modified), f.sign.label().into(), f.sha256.clone(), f.note.clone(), f.origin.clone(), f.streams.join("; "), f.risk.label().into(), f.reasons.join("；")]).collect(),
    )));
    v
}

// ---------------------------------------------------------------- HTML

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn sev_tag(s: Severity) -> String {
    let cls = match s {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
        Severity::Info => "info",
    };
    format!("<span class=\"tag {cls}\">{}</span>", s.label())
}

fn table_html(head: &[&str], rows: impl Iterator<Item = Vec<String>>) -> String {
    let mut s = String::from("<div class=\"tw\"><table><thead><tr>");
    for h in head {
        let _ = write!(s, "<th>{}</th>", esc(h));
    }
    s.push_str("</tr></thead><tbody>");
    for row in rows {
        s.push_str("<tr>");
        for cell in row {
            let _ = write!(s, "<td>{cell}</td>");
        }
        s.push_str("</tr>");
    }
    s.push_str("</tbody></table></div>");
    s
}

pub fn html(r: &ScanReport) -> String {
    let h = &r.host;
    let score = r.baseline_score().map(|s| format!("{s}%")).unwrap_or("-".into());
    let mut body = String::new();
    let _ = write!(
        body,
        "<header>{}<h1>LovelyWinInspect 应急响应报告</h1><p>主机 <b>{}</b> · {} {} ({}) · IP {} · 采集时间 {} · 回溯 {} 天</p></header>",
        crate::assets::LOGO_SMALL_PNG
            .map(|b| format!("<img class=\"logo\" alt=\"logo\" src=\"data:image/png;base64,{}\">", base64(b)))
            .unwrap_or_default(),
        esc(&h.hostname), esc(&h.os_name), esc(&h.os_version), esc(&h.build), esc(&h.ip), fmt(r.finished.or(r.started)), r.lookback_days
    );
    let _ = write!(
        body,
        "<section class=\"stats\"><div><b>{}</b><span>高危及以上发现</span></div><div><b>{}</b><span>基线合规率</span></div><div><b>{}</b><span>可疑持久化项</span></div><div><b>{}</b><span>外联连接</span></div><div><b>{}</b><span>时间线事件</span></div></section>",
        r.count_findings(Severity::High),
        score,
        r.persistence.iter().filter(|p| p.risk >= Severity::Medium).count(),
        r.connections.iter().filter(|c| c.external && c.state != "LISTEN").count(),
        r.timeline.len()
    );

    body.push_str("<h2>主机信息</h2>");
    body.push_str(&table_html(&["项目", "值"], [
        ("主机名", h.hostname.clone()), ("操作系统", format!("{} {} ({})", h.os_name, h.os_version, h.build)), ("系统类型", h.arch.clone()),
        ("IP / MAC", format!("{} / {}", h.ip, h.mac)), ("工作组/域", h.domain.clone()), ("当前用户", h.current_user.clone()),
        ("启动时间", fmt(h.boot_time)), ("安装时间", fmt(h.install_date)), ("时区", h.timezone.clone()), ("安全软件", format!("{} (实时防护: {})", h.av_product, if h.av_realtime == Some(true) { "开启" } else { "关闭" })),
    ].into_iter().map(|(k, v)| vec![esc(k), esc(&v)])));

    if !r.log_gaps.is_empty() {
        let _ = write!(body, "<p class=\"warn\">⚠ 审计/日志配置不完整，日志类结论可能缺失：{}</p>", esc(&r.log_gaps.join("；")));
    }
    body.push_str("<h2>调查发现</h2>");
    body.push_str(&table_html(&["时间", "类型", "风险", "对象", "描述", "路径/目标", "战术", "处置建议"], r.findings.iter().map(|f| vec![
        fmt(f.time), f.category.label().into(), sev_tag(f.severity), esc(&f.object), esc(&f.title), esc(&f.target), f.tactic.map(|t| t.label()).unwrap_or("-").into(), esc(&f.advice),
    ])));

    body.push_str("<h2>入侵时间线</h2>");
    body.push_str(&table_html(&["时间", "来源", "风险", "战术", "事件", "详情"], r.timeline.iter().filter(|e| e.severity >= Severity::Low).take(1500).map(|e| vec![
        e.time.format("%Y-%m-%d %H:%M:%S").to_string(), esc(&e.source), sev_tag(e.severity), e.tactic.map(|t| t.label()).unwrap_or("-").into(), esc(&e.title), esc(&e.detail.chars().take(300).collect::<String>()),
    ])));

    body.push_str("<h2>安全基线核查</h2>");
    body.push_str(&table_html(&["编号", "分类", "检查项", "期望值", "当前值", "结果", "加固建议"], r.baseline.iter().map(|b| {
        let cls = match b.status { CheckStatus::Pass => "pass", CheckStatus::Fail => "high", CheckStatus::Warn => "med", CheckStatus::Unknown => "info" };
        vec![esc(&b.id), esc(&b.group), esc(&b.title), esc(&b.expected), esc(&b.actual), format!("<span class=\"tag {cls}\">{}</span>", b.status.label()), esc(&b.advice)]
    })));

    body.push_str("<h2>可疑进程</h2>");
    body.push_str(&table_html(&["PID", "进程", "风险", "签名", "用户", "父进程", "原因", "路径 / 命令行"], r.processes.iter().filter(|p| p.risk >= Severity::Low).map(|p| vec![
        p.pid.to_string(), esc(&p.name), sev_tag(p.risk), p.sign.label().into(), esc(&p.user), esc(&p.parent_name), esc(&p.reasons.join("；")), format!("{}<br><small>{}</small>", esc(&p.path), esc(&p.cmdline)),
    ])));

    body.push_str("<h2>外联连接</h2>");
    body.push_str(&table_html(&["协议", "本地", "远程", "状态", "进程", "风险", "原因"], r.connections.iter().filter(|c| c.external && c.state != "LISTEN").map(|c| vec![
        esc(&c.proto),
        format!("{}:{}", esc(&c.local_addr), c.local_port),
        format!("{}:{}{}", esc(&c.remote_addr), c.remote_port, if c.domain.is_empty() { String::new() } else { format!("<br><small>{}</small>", esc(&c.domain)) }),
        esc(&c.state), format!("{} ({})", esc(&c.process), c.pid), sev_tag(c.risk), esc(&c.reasons.join("；")),
    ])));

    body.push_str("<h2>ARP / 邻居表</h2>");
    body.push_str(&table_html(&["IP 地址", "MAC 地址", "接口", "状态", "网关", "风险", "说明"], r.neighbors.iter().map(|n| vec![
        esc(&n.ip), esc(&n.mac), esc(&n.interface), esc(&n.state), if n.is_gateway { "是" } else { "" }.into(), sev_tag(n.risk), esc(&n.reasons.join("；")),
    ])));

    let dns_shown = 500;
    let _ = write!(body, "<h2>DNS 缓存（共 {} 条{}）</h2>", r.dns_cache.len(), if r.dns_cache.len() > dns_shown { format!("，此处列出前 {dns_shown} 条，完整内容见 CSV") } else { String::new() });
    body.push_str(&table_html(&["域名", "类型", "解析结果", "TTL", "风险", "原因"], r.dns_cache.iter().take(dns_shown).map(|d| vec![
        esc(&d.name), esc(&d.rtype), esc(&d.data), d.ttl.to_string(), sev_tag(d.risk), esc(&d.reasons.join("；")),
    ])));

    body.push_str("<h2>持久化项（低风险及以上 / 非微软）</h2>");
    body.push_str(&table_html(&["类型", "名称", "风险", "签名", "命令", "原因", "时间"], r.persistence.iter().filter(|i| noteworthy_persist(i)).map(|i| vec![
        i.kind.label().into(), esc(&i.name), sev_tag(i.risk), i.sign.label().into(), esc(&i.command), esc(&i.reasons.join("；")), fmt(i.time),
    ])));

    body.push_str("<h2>账户</h2>");
    body.push_str(&table_html(&["用户名", "RID", "管理员", "状态", "最后登录", "所属组", "风险", "原因"], r.accounts.iter().map(|a| vec![
        esc(&a.name), a.rid.to_string(), if a.is_admin { "是" } else { "否" }.into(), if a.disabled { "禁用" } else { "启用" }.into(), fmt(a.last_logon), esc(&a.groups.join(", ")), sev_tag(a.risk), esc(&a.reasons.join("；")),
    ])));

    body.push_str("<h2>当前会话</h2>");
    body.push_str(&table_html(&["类型", "会话", "用户", "状态", "客户端", "来源地址", "风险", "说明"], r.sessions.iter().map(|s| vec![
        esc(&s.kind), s.id.to_string(), esc(&s.user), esc(&s.state), esc(&s.client), esc(&s.client_ip), sev_tag(s.risk), esc(&s.reasons.join("；")),
    ])));

    body.push_str("<h2>文件痕迹（低风险及以上）</h2>");
    body.push_str(&table_html(&["类型", "文件", "风险", "修改时间", "SHA256", "原因"], r.files.iter().filter(|f| f.risk >= Severity::Low).map(|f| {
        let mut extra = Vec::new();
        if !f.origin.is_empty() {
            extra.push(format!("下载自 {}", f.origin));
        }
        if !f.streams.is_empty() {
            extra.push(format!("备用数据流: {}", f.streams.join(", ")));
        }
        let path = if extra.is_empty() { esc(&f.path) } else { format!("{}<br><small>{}</small>", esc(&f.path), esc(&extra.join(" · "))) };
        vec![f.kind.label().into(), path, sev_tag(f.risk), fmt(f.modified), esc(&f.sha256), esc(&f.reasons.join("；"))]
    })));

    format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LovelyWinInspect 报告 - {}</title><style>
body{{font-family:"Microsoft YaHei UI","Segoe UI",sans-serif;margin:0;background:#f4f6fa;color:#1f2329;font-size:13px}}
header{{background:#1f6feb;color:#fff;padding:24px 32px}}header .logo{{float:left;width:52px;height:52px;border-radius:12px;margin-right:14px;background:#fff}}header h1{{margin:0 0 6px;font-size:22px}}header p{{margin:0;opacity:.9}}
main{{padding:16px 32px 48px}}@media(max-width:700px){{main{{padding:12px 16px 32px}}header{{padding:18px 16px}}}}h2{{font-size:16px;margin:28px 0 10px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}}.stats div{{background:#fff;border:1px solid #e4e8f0;border-radius:10px;padding:14px 16px}}.stats b{{display:block;font-size:26px}}.stats span{{color:#646a73}}
.tw{{overflow-x:auto;border:1px solid #e4e8f0;border-radius:8px;background:#fff}}table{{width:100%;min-width:760px;border-collapse:collapse;background:#fff}}th{{background:#f7f8fb;color:#646a73;font-weight:500;text-align:left;padding:8px 10px;border-bottom:1px solid #e4e8f0}}td{{padding:7px 10px;border-bottom:1px solid #eef1f6;vertical-align:top;word-break:break-all}}small{{color:#8f959e}}
.warn{{background:#fff1e0;color:#b45309;border-radius:8px;padding:10px 14px;margin:16px 0 0}}.tag{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;white-space:nowrap}}.crit{{background:#efe9ff;color:#7c4dff}}.high{{background:#fdecec;color:#e5484d}}.med{{background:#fff1e0;color:#e8730c}}.low{{background:#e6eeff;color:#3370ff}}.info{{background:#eff1f5;color:#646a73}}.pass{{background:#e3f6e8;color:#2ea043}}
</style></head><body>{}</body></html>"#,
        esc(&h.hostname),
        body.replacen("</header>", "</header><main>", 1) + "</main>"
    )
}

pub fn noteworthy_persist(i: &PersistItem) -> bool {
    if i.risk >= Severity::Low {
        return true;
    }
    match i.kind {
        PersistKind::Service => false,
        PersistKind::ScheduledTask => !i.name.to_ascii_lowercase().starts_with("\\microsoft\\"),
        PersistKind::Lsa | PersistKind::BootExecute | PersistKind::Accessibility | PersistKind::Winlogon | PersistKind::RootCert => false,
        _ => true,
    }
}
