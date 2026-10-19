//! 数据列表页：进程、网络、启动项、账户、日志、文件、注册表。
//!
//! 每个列表只负责筛选与各列内容；搜索、排序、点击详情、右键菜单、选中与标记由
//! `listkit` 统一处理。

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use gpui::{AnyElement, Context, FontWeight, IntoElement, ParentElement, Styled, div, prelude::*, px};

use super::app::{AppView, Detail, DetailExtra, EventFilter, NetFilter, Page};
use super::components::*;
use super::listkit::{ListId, SortVal, refine};
use super::menu::{self, MenuItem};
use crate::model::*;
use crate::report::noteworthy_persist;
use crate::theme::{Theme, theme};

fn list_page(t: &Theme, title: &str, subtitle: &str, search: AnyElement, toolbar: impl IntoElement, list: impl IntoElement) -> gpui::Div {
    div()
        .size_full()
        .p(px(20.))
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(
            div()
                .flex()
                .items_end()
                .gap_4()
                .child(div().flex_1().min_w_0().child(page_title(t, title, subtitle)))
                .child(search),
        )
        .child(toolbar)
        .child(list)
}

fn reasons_text(r: &[String]) -> String {
    if r.is_empty() { "-".into() } else { r.join("；") }
}

fn sev(s: Severity) -> SortVal {
    SortVal::N(s as i64)
}

// ---------------------------------------------------------------- 进程

const PROC_COLS: &[Col] = &[
    col("PID", 64.),
    col("进程名", 180.),
    col("风险", 60.),
    col("签名", 84.),
    col("用户", 190.),
    col("父进程", 150.),
    col("启动时间", 150.),
    flex_col("路径 / 研判依据"),
];

/// 进程树视图：缩进占用名称列宽度，父子关系由树表达，因此去掉“父进程”列。
const PROC_TREE_COLS: &[Col] = &[
    col("PID", 64.),
    col("进程名", 320.),
    col("风险", 60.),
    col("签名", 84.),
    col("用户", 190.),
    col("启动时间", 150.),
    flex_col("路径 / 研判依据"),
];

fn proc_detail(p: &ProcessInfo) -> Detail {
    Detail::new(format!("{} ({})", p.name, p.pid), p.path.clone(), Some(p.risk))
        .field("研判依据", reasons_text(&p.reasons))
        .field("命令行", p.cmdline.clone())
        .field("路径", p.path.clone())
        .field("父进程", format!("{} ({})", if p.parent_name.is_empty() { "已退出" } else { &p.parent_name }, p.ppid))
        .field("用户", p.user.clone())
        .field("启动时间", fmt_time(p.start_time))
        .field("数字签名", p.sign.label())
        .field("外联连接数", p.net_conns.to_string())
        .field("线程 / 内存", format!("{} 线程 / {}", p.threads, fmt_size(p.memory_kb * 1024)))
}

fn proc_hay(p: &ProcessInfo) -> String {
    format!("{} {} {} {} {} {} {} {}", p.pid, p.name, p.path, p.cmdline, p.user, p.parent_name, p.sign.label(), p.reasons.join(" "))
}

fn proc_key(p: &ProcessInfo, col: usize) -> SortVal {
    match col {
        0 => SortVal::N(p.pid as i64),
        1 => SortVal::s(&p.name),
        2 => sev(p.risk),
        3 => SortVal::s(p.sign.label()),
        4 => SortVal::s(&p.user),
        5 => SortVal::s(&p.parent_name),
        6 => SortVal::t(p.start_time),
        _ => SortVal::s(&p.path),
    }
}

/// 进程树中的一行。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeRow {
    pub index: usize,
    pub depth: u16,
    pub has_children: bool,
}

/// 按父子关系把进程排成树。父进程必须早于子进程启动，否则视为 PID 被复用（父进程已退出）。
/// `keep` 为 false 的节点只在其后代需要显示时作为上下文保留；`collapsed` 中的 PID 不展开子节点。
pub fn process_tree(procs: &[ProcessInfo], keep: impl Fn(usize) -> bool, collapsed: &HashSet<u32>) -> Vec<TreeRow> {
    let by_pid: HashMap<u32, usize> = procs.iter().enumerate().map(|(i, p)| (p.pid, i)).collect();
    let parent: Vec<Option<usize>> = procs
        .iter()
        .map(|p| {
            let &pi = by_pid.get(&p.ppid)?;
            let pp = &procs[pi];
            let older = match (pp.start_time, p.start_time) {
                (Some(a), Some(b)) => a <= b,
                _ => true,
            };
            (pp.pid != p.pid && older).then_some(pi)
        })
        .collect();

    // 需要显示的节点 = 命中的节点及其所有祖先
    let mut include = vec![false; procs.len()];
    for i in 0..procs.len() {
        if !keep(i) {
            continue;
        }
        let mut cur = Some(i);
        let mut guard = 0;
        while let Some(c) = cur {
            if include[c] && c != i {
                break;
            }
            include[c] = true;
            cur = parent[c];
            guard += 1;
            if guard > procs.len() {
                break;
            }
        }
    }

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); procs.len()];
    for (i, p) in parent.iter().enumerate() {
        if let Some(p) = p
            && include[i]
        {
            children[*p].push(i);
        }
    }
    let order = |v: &mut Vec<usize>| v.sort_by(|&a, &b| procs[a].start_time.cmp(&procs[b].start_time).then(procs[a].pid.cmp(&procs[b].pid)));
    for c in children.iter_mut() {
        order(c);
    }
    let mut roots: Vec<usize> = (0..procs.len()).filter(|&i| include[i] && parent[i].is_none()).collect();
    order(&mut roots);

    let mut out = Vec::new();
    let mut visited = vec![false; procs.len()];
    fn walk(
        i: usize,
        depth: u16,
        procs: &[ProcessInfo],
        children: &[Vec<usize>],
        collapsed: &HashSet<u32>,
        visited: &mut [bool],
        out: &mut Vec<TreeRow>,
    ) {
        if visited[i] {
            return;
        }
        visited[i] = true;
        out.push(TreeRow { index: i, depth, has_children: !children[i].is_empty() });
        if collapsed.contains(&procs[i].pid) {
            // 折叠的子树仍标记为已访问，避免被当作孤立节点重新列出
            let mut stack = children[i].clone();
            while let Some(c) = stack.pop() {
                if !visited[c] {
                    visited[c] = true;
                    stack.extend(children[c].iter().copied());
                }
            }
            return;
        }
        for &c in &children[i] {
            walk(c, depth + 1, procs, children, collapsed, visited, out);
        }
    }
    for r in roots {
        walk(r, 0, procs, &children, collapsed, &mut visited, &mut out);
    }
    // 处于环中的节点（异常数据）作为根补上
    for i in 0..procs.len() {
        if include[i] && !visited[i] {
            walk(i, 0, procs, &children, collapsed, &mut visited, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------- 网络

const NET_COLS: &[Col] = &[
    col("协议", 56.),
    col("本地地址", 200.),
    col("远程地址", 230.),
    col("状态", 110.),
    col("PID", 64.),
    col("进程", 170.),
    col("风险", 60.),
    flex_col("路径 / 研判依据"),
];

fn conn_detail(c: &ConnInfo) -> Detail {
    Detail::new(
        if c.remote_addr.is_empty() { format!("{} {}:{}", c.proto, c.local_addr, c.local_port) } else { format!("{}:{}", c.remote_addr, c.remote_port) },
        format!("{} · {} ({})", c.state, c.process, c.pid),
        Some(c.risk),
    )
    .field("研判依据", reasons_text(&c.reasons))
    .field("协议", c.proto.clone())
    .field("本地地址", format!("{}:{}", c.local_addr, c.local_port))
    .field("远程地址", if c.remote_addr.is_empty() { "-".into() } else { format!("{}:{}", c.remote_addr, c.remote_port) })
    .field("域名（DNS 缓存）", c.domain.clone())
    .field("是否外联", if c.external { "是（公网地址）" } else { "否" })
    .field("状态", c.state.clone())
    .field("进程", format!("{} ({})", c.process, c.pid))
    .field("进程路径", c.path.clone())
}

fn conn_hay(c: &ConnInfo) -> String {
    format!(
        "{} {}:{} {}:{} {} {} {} {} {} {}",
        c.proto, c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.domain, c.state, c.pid, c.process, c.path, c.reasons.join(" ")
    )
}

fn conn_key(c: &ConnInfo, col: usize) -> SortVal {
    match col {
        0 => SortVal::s(&c.proto),
        1 => SortVal::S(format!("{}:{:05}", c.local_addr, c.local_port)),
        2 => SortVal::S(format!("{}:{:05}", c.remote_addr, c.remote_port)),
        3 => SortVal::s(&c.state),
        4 => SortVal::N(c.pid as i64),
        5 => SortVal::s(&c.process),
        6 => sev(c.risk),
        _ => SortVal::s(&c.path),
    }
}

const DNS_COLS: &[Col] = &[
    col("域名", 320.),
    col("类型", 64.),
    col("解析结果", 300.),
    col("TTL", 80.),
    col("风险", 60.),
    flex_col("研判依据"),
];

fn dns_detail(d: &DnsCacheEntry) -> Detail {
    Detail::new(d.name.clone(), format!("DNS 缓存 · {}", d.rtype), Some(d.risk))
        .field("研判依据", reasons_text(&d.reasons))
        .field("记录类型", d.rtype.clone())
        .field("解析结果", d.data.clone())
        .field("剩余 TTL", format!("{} 秒", d.ttl))
}

fn dns_key(d: &DnsCacheEntry, col: usize) -> SortVal {
    match col {
        0 => SortVal::s(&d.name),
        1 => SortVal::s(&d.rtype),
        2 => SortVal::s(&d.data),
        3 => SortVal::N(d.ttl as i64),
        4 => sev(d.risk),
        _ => SortVal::S(d.reasons.join(" ")),
    }
}

const NEIGHBOR_COLS: &[Col] = &[
    col("IP 地址", 250.),
    col("MAC 地址", 150.),
    col("接口", 200.),
    col("状态", 70.),
    col("风险", 60.),
    flex_col("研判依据 / 说明"),
];

fn neighbor_detail(n: &NeighborEntry) -> Detail {
    Detail::new(n.ip.clone(), format!("{} · {}", n.mac, n.interface), Some(n.risk))
        .field("研判依据", reasons_text(&n.reasons))
        .field("MAC 地址", n.mac.clone())
        .field("接口", n.interface.clone())
        .field("状态", format!("{}{}", n.state, if n.is_static { "（静态绑定）" } else { "" }))
        .field("是否网关", if n.is_gateway { "是" } else { "否" })
}

fn neighbor_key(n: &NeighborEntry, col: usize) -> SortVal {
    match col {
        0 => SortVal::s(&n.ip),
        1 => SortVal::s(&n.mac),
        2 => SortVal::s(&n.interface),
        3 => SortVal::s(&n.state),
        4 => sev(n.risk),
        _ => SortVal::S(n.reasons.join(" ")),
    }
}

// ---------------------------------------------------------------- 启动项

const PERSIST_COLS: &[Col] = &[
    col("类型", 120.),
    col("名称", 230.),
    flex_col("命令 / 路径"),
    col("签名", 84.),
    col("状态", 56.),
    col("时间", 150.),
    col("风险", 60.),
];

fn persist_detail(i: &PersistItem) -> Detail {
    Detail::new(i.name.clone(), i.kind.label(), Some(i.risk))
        .field("研判依据", reasons_text(&i.reasons))
        .field(if i.kind == PersistKind::RootCert { "证书信息" } else { "命令" }, i.command.clone())
        .field("目标文件", i.image.clone())
        .field("数字签名", i.sign.label())
        .field("位置", i.location.clone())
        .field("附加信息", i.extra.clone())
        .field("状态", if i.enabled { "启用" } else { "禁用" })
        .field("创建/修改时间", fmt_time(i.time))
}

fn persist_hay(i: &PersistItem) -> String {
    format!("{} {} {} {} {} {} {}", i.kind.label(), i.name, i.command, i.image, i.location, i.extra, i.reasons.join(" "))
}

fn persist_key(i: &PersistItem, col: usize) -> SortVal {
    match col {
        0 => SortVal::s(i.kind.label()),
        1 => SortVal::s(&i.name),
        2 => SortVal::s(if i.command.is_empty() { &i.location } else { &i.command }),
        3 => SortVal::s(i.sign.label()),
        4 => SortVal::N(i.enabled as i64),
        5 => SortVal::t(i.time),
        _ => sev(i.risk),
    }
}

// ---------------------------------------------------------------- 日志

const EVENT_COLS: &[Col] = &[
    col("时间", 150.),
    col("事件ID", 62.),
    col("通道", 92.),
    col("事件", 210.),
    col("用户", 180.),
    col("来源 IP", 130.),
    flex_col("详情"),
    col("风险", 60.),
];

fn event_detail(e: &EventRecord) -> Detail {
    Detail::new(e.title.clone(), format!("{} · 事件 {}", e.channel, e.event_id), Some(e.severity))
        .field("时间", fmt_time(e.time))
        .field("用户", e.user.clone())
        .field("来源 IP", e.source_ip.clone())
        .field("登录类型", e.logon_type.clone())
        .field("进程 / 映像", e.process.clone())
        .field("详情", e.detail.clone())
        .field("战术阶段", e.tactic.map(|t| format!("{} ({})", t.label(), t.attack_id())).unwrap_or_default())
}

fn event_hay(e: &EventRecord) -> String {
    format!("{} {} {} {} {} {} {} {}", e.event_id, e.channel, e.title, e.user, e.source_ip, e.logon_type, e.process, e.detail)
}

fn event_key(e: &EventRecord, col: usize) -> SortVal {
    match col {
        0 => SortVal::t(e.time),
        1 => SortVal::N(e.event_id as i64),
        2 => SortVal::s(&e.channel),
        3 => SortVal::s(&e.title),
        4 => SortVal::s(&e.user),
        5 => SortVal::s(&e.source_ip),
        6 => SortVal::s(&e.detail),
        _ => sev(e.severity),
    }
}

// ---------------------------------------------------------------- 文件

const FILE_COLS: &[Col] = &[
    col("类型", 130.),
    col("文件名", 220.),
    flex_col("说明 / 路径"),
    col("大小", 80.),
    col("修改时间", 150.),
    col("签名", 84.),
    col("风险", 60.),
];

fn file_detail(f: &FileArtifact) -> Detail {
    Detail::new(f.name.clone(), f.kind.label(), Some(f.risk))
        .field("研判依据", reasons_text(&f.reasons))
        .field("说明", f.note.clone())
        .field("下载来源（Zone.Identifier）", f.origin.clone())
        .field("备用数据流", f.streams.join("\n"))
        .field("路径", f.path.clone())
        .field("大小", fmt_size(f.size))
        .field("创建时间", fmt_time(f.created))
        .field("修改时间", fmt_time(f.modified))
        .field("数字签名", f.sign.label())
        .field("SHA256", f.sha256.clone())
}

fn file_hay(f: &FileArtifact) -> String {
    format!("{} {} {} {} {} {} {}", f.kind.label(), f.name, f.path, f.note, f.origin, f.sha256, f.reasons.join(" "))
}

fn file_key(f: &FileArtifact, col: usize) -> SortVal {
    match col {
        0 => SortVal::s(f.kind.label()),
        1 => SortVal::s(&f.name),
        2 => SortVal::s(&f.path),
        3 => SortVal::N(f.size as i64),
        4 => SortVal::t(f.modified),
        5 => SortVal::s(f.sign.label()),
        _ => sev(f.risk),
    }
}

// ---------------------------------------------------------------- 注册表取证

const REG_COLS: &[Col] = &[
    col("分类", 120.),
    col("名称", 260.),
    flex_col("值 / 说明"),
    col("用户", 70.),
    col("时间", 150.),
    col("风险", 60.),
];

fn reg_detail(r: &RegItem) -> Detail {
    Detail::new(r.name.clone(), r.category.label(), Some(r.risk))
        .field("研判依据", reasons_text(&r.reasons))
        .field("值", r.value.clone())
        .field("说明", r.note.clone())
        .field("注册表位置", r.location.clone())
        .field("所属用户 (RID)", r.user.clone())
        .field("时间", fmt_time(r.time))
}

fn reg_hay(r: &RegItem) -> String {
    format!("{} {} {} {} {} {}", r.category.label(), r.name, r.value, r.note, r.location, r.reasons.join(" "))
}

fn reg_key(r: &RegItem, col: usize) -> SortVal {
    match col {
        0 => SortVal::s(r.category.label()),
        1 => SortVal::s(&r.name),
        2 => SortVal::s(&r.value),
        3 => SortVal::s(&r.user),
        4 => SortVal::t(r.time),
        _ => sev(r.risk),
    }
}

// ---------------------------------------------------------------- 详情 / 菜单 / 标记分发

impl AppView {
    /// 记录的稳定标识：由能唯一确定对象的字段组成，重新排查后仍能对应。
    pub fn mark_key(&self, list: ListId, i: usize) -> Option<String> {
        let r = &self.report;
        Some(match list {
            ListId::Proc => {
                let p = r.processes.get(i)?;
                format!("proc|{}|{}", p.pid, p.path.to_lowercase())
            }
            ListId::Net => {
                let c = r.connections.get(i)?;
                format!("conn|{}|{}:{}|{}:{}|{}", c.proto, c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.pid)
            }
            ListId::Dns => {
                let d = r.dns_cache.get(i)?;
                format!("dns|{}|{}|{}", d.name.to_lowercase(), d.rtype, d.data)
            }
            ListId::Arp => {
                let n = r.neighbors.get(i)?;
                format!("arp|{}|{}", n.ip, n.mac)
            }
            ListId::Persist => {
                let it = r.persistence.get(i)?;
                format!("persist|{:?}|{}|{}", it.kind, it.location, it.name)
            }
            ListId::Event => {
                let e = r.events.get(i)?;
                format!("event|{}|{}|{}|{}|{}", e.channel, e.event_id, fmt_time(e.time), e.user, e.source_ip)
            }
            ListId::File => {
                let f = r.files.get(i)?;
                format!("file|{:?}|{}", f.kind, f.path.to_lowercase())
            }
            ListId::Reg => {
                let it = r.registry.get(i)?;
                format!("reg|{}|{}", it.location, it.name)
            }
            ListId::Fs => return self.fs_mark_key(i),
            ListId::Quarantine => return None,
            ListId::Finding => {
                let f = r.findings.get(i)?;
                format!("finding|{:?}|{}|{}", f.category, f.object, f.title)
            }
            ListId::Timeline => {
                let e = r.timeline.get(i)?;
                format!("tl|{}|{}|{}", e.time.timestamp(), e.source, e.title)
            }
        })
    }

    pub fn item_menu(&self, list: ListId, i: usize) -> Vec<MenuItem> {
        let r = &self.report;
        match list {
            ListId::Proc => r.processes.get(i).map(menu::process_menu),
            ListId::Net => r.connections.get(i).map(|c| menu::conn_menu(c, &self.blocked_ips)),
            ListId::Dns => r.dns_cache.get(i).map(|d| menu::dns_menu(d, &self.blocked_ips)),
            ListId::Arp => r.neighbors.get(i).map(menu::neighbor_menu),
            ListId::Persist => r.persistence.get(i).map(|it| menu::persist_menu(i, it)),
            ListId::Event => r.events.get(i).map(|e| menu::event_menu(e, &self.blocked_ips)),
            ListId::File => r.files.get(i).map(menu::file_menu),
            ListId::Reg => r.registry.get(i).map(menu::reg_menu),
            ListId::Fs => Some(self.fs_menu(i)),
            ListId::Quarantine => Some(self.quarantine_menu(i)),
            ListId::Finding => r.findings.get(i).map(|f| {
                let mut v = Vec::new();
                if std::path::Path::new(&f.target).exists() {
                    v.extend(menu::file_items(&f.target));
                } else {
                    v.extend(menu::copy_item("copy", "目标", &f.target));
                }
                v.extend(menu::copy_item("copy", "处置建议", &f.advice));
                v
            }),
            ListId::Timeline => r.timeline.get(i).map(|e| menu::copy_item("copy", "详情", &e.detail).into_iter().collect()),
        }
        .unwrap_or_default()
    }

    pub fn item_detail(&self, list: ListId, i: usize) -> Option<Detail> {
        let r = &self.report;
        let (d, category) = match list {
            ListId::Proc => {
                let p = r.processes.get(i)?;
                (proc_detail(p).extra(DetailExtra::Modules(p.pid)), "进程")
            }
            ListId::Net => (conn_detail(r.connections.get(i)?), "网络连接"),
            ListId::Dns => (dns_detail(r.dns_cache.get(i)?), "DNS 缓存"),
            ListId::Arp => (neighbor_detail(r.neighbors.get(i)?), "ARP / 邻居表"),
            ListId::Persist => (persist_detail(r.persistence.get(i)?), "启动项"),
            ListId::Event => (event_detail(r.events.get(i)?), "日志"),
            ListId::File => {
                let f = r.files.get(i)?;
                let d = file_detail(f);
                let d = if std::path::Path::new(&f.path).is_file() { d.extra(DetailExtra::Preview(f.path.clone())) } else { d };
                (d, "文件痕迹")
            }
            ListId::Reg => (reg_detail(r.registry.get(i)?), "注册表"),
            ListId::Fs => (self.fs_detail(i)?, "文件管理"),
            ListId::Finding => (super::overview::finding_detail(r.findings.get(i)?), "调查发现"),
            ListId::Timeline => (super::timeline::timeline_detail(r.timeline.get(i)?), "入侵时间线"),
            ListId::Quarantine => return self.quarantine_detail(i).map(|d| d.actions(self.item_menu(list, i))),
        };
        let d = d.actions(self.item_menu(list, i));
        Some(match self.mark_key(list, i) {
            Some(k) => d.markable(k, category),
            None => d,
        })
    }
}

impl AppView {
    pub fn render_processes(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let query = self.query(Page::Process, cx);
        let sus_only = self.f_proc_suspicious;
        let tree = self.proc_tree;
        let sus = r.processes.iter().filter(|p| p.risk >= Severity::Low).count();
        let unsigned = r.processes.iter().filter(|p| p.sign == SignState::Unsigned).count();

        let idx: Vec<usize> = if tree {
            let keep = |i: usize| {
                let p = &r.processes[i];
                (!sus_only || p.risk >= Severity::Low) && super::listkit::matches_query(&proc_hay(p), &query)
            };
            let rows = process_tree(&r.processes, keep, &self.proc_collapsed);
            self.proc_depth = rows.iter().map(|row| (row.index, (row.depth, row.has_children))).collect();
            rows.into_iter().map(|row| row.index).collect()
        } else {
            let mut idx: Vec<usize> = (0..r.processes.len()).filter(|&i| !sus_only || r.processes[i].risk >= Severity::Low).collect();
            idx.sort_by(|&a, &b| {
                let (pa, pb) = (&r.processes[a], &r.processes[b]);
                pb.risk.cmp(&pa.risk).then(pa.name.to_lowercase().cmp(&pb.name.to_lowercase()))
            });
            refine(idx, &r.processes, &query, self.sort_of(ListId::Proc), proc_hay, proc_key)
        };

        let toolbar = div()
            .flex()
            .items_center()
            .gap_2()
            .child(chip(&t, "p-sus", format!("需关注 ({sus})"), sus_only).on_click(cx.listener(|this, _, _, cx| {
                this.f_proc_suspicious = true;
                cx.notify();
            })))
            .child(chip(&t, "p-all", format!("全部进程 ({})", r.processes.len()), !sus_only).on_click(cx.listener(|this, _, _, cx| {
                this.f_proc_suspicious = false;
                cx.notify();
            })))
            .child(div().w(px(1.)).h(px(18.)).bg(t.border).mx_1())
            .child(chip(&t, "p-view-list", "列表", !tree).on_click(cx.listener(|this, _, _, cx| {
                this.proc_tree = false;
                cx.notify();
            })))
            .child(
                chip(&t, "p-view-tree", "进程树", tree)
                    .tooltip(tooltip("按父子关系展示；筛选或搜索时保留命中进程的祖先链"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.proc_tree = true;
                        cx.notify();
                    })),
            )
            .when(tree, |d| {
                d.child(small_button(&t, "p-expand-all", "chevron-down", "全部展开").on_click(cx.listener(|this, _, _, cx| {
                    this.proc_collapsed.clear();
                    cx.notify();
                })))
            })
            .child(div().flex_1())
            .child(badge(format!("未签名 {unsigned}"), t.red, t.red_soft))
            .child(badge(format!("中危及以上 {}", r.processes.iter().filter(|p| p.risk >= Severity::Medium).count()), t.orange, t.orange_soft));
        let search = self.search_box(Page::Process, cx);
        let empty = if tree { "没有符合条件的进程" } else { "未发现需要关注的进程" };
        let cols = if tree { PROC_TREE_COLS } else { PROC_COLS };
        let list = self.virtual_table(&t, ListId::Proc, cols, Rc::new(idx), empty, cx, move |this, i, ix, t, cx| {
            let p = &this.report.processes[i];
            let name_cell = if tree {
                let (depth, has_children) = this.proc_depth.get(&i).copied().unwrap_or((0, false));
                let collapsed = this.proc_collapsed.contains(&p.pid);
                let pid = p.pid;
                div()
                    .w_full()
                    .flex()
                    .items_center()
                    .gap_1()
                    .pl(px(depth as f32 * 14.))
                    .child(if has_children {
                        div()
                            .id(("tree-toggle", ix))
                            .flex_none()
                            .size(px(16.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .rounded(px(3.))
                            .hover(|s| s.bg(gpui::black().opacity(0.06)))
                            .child(icon(if collapsed { "chevron-right" } else { "chevron-down" }, 12., t.text_muted))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                if !this.proc_collapsed.remove(&pid) {
                                    this.proc_collapsed.insert(pid);
                                }
                                cx.notify();
                            }))
                            .into_any_element()
                    } else {
                        div().flex_none().size(px(16.)).into_any_element()
                    })
                    .child(div().flex_1().min_w_0().truncate().font_weight(FontWeight::MEDIUM).child(p.name.clone()))
                    .into_any_element()
            } else {
                div().w_full().truncate().font_weight(FontWeight::MEDIUM).child(p.name.clone()).into_any_element()
            };
            let mut cells = vec![
                mono_cell(t, p.pid.to_string()),
                name_cell,
                sev_badge(t, p.risk).into_any_element(),
                sign_badge(t, p.sign).into_any_element(),
                muted_cell(t, p.user.clone()),
            ];
            if !tree {
                cells.push(muted_cell(t, if p.parent_name.is_empty() { format!("({})", p.ppid) } else { p.parent_name.clone() }));
            }
            cells.push(muted_cell(t, fmt_time(p.start_time)));
            cells.push(muted_cell(t, if p.reasons.is_empty() { p.path.clone() } else { p.reasons.join("；") }));
            table_row(t, ("proc", ix), cols, cells)
        });
        list_page(&t, "进程分析", "进程路径、签名、父子关系与命令行参数研判（点击行查看详情与加载模块）", search, toolbar, list)
    }

    pub fn render_network(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let f = self.f_net;
        let query = self.query(Page::Network, cx);
        let conn_match = |c: &ConnInfo, nf: NetFilter| match nf {
            NetFilter::External => c.external && c.state != "LISTEN",
            NetFilter::Listen => c.state == "LISTEN" || (c.proto.starts_with("UDP") && c.remote_addr.is_empty()),
            NetFilter::Suspicious => c.risk >= Severity::Medium,
            NetFilter::All => true,
            NetFilter::Dns | NetFilter::Neighbors => false,
        };
        let count = |nf: NetFilter| -> usize {
            match nf {
                NetFilter::Dns => r.dns_cache.len(),
                NetFilter::Neighbors => r.neighbors.len(),
                _ => r.connections.iter().filter(|c| conn_match(c, nf)).count(),
            }
        };
        let gw_alert = r.neighbors.iter().filter(|n| n.is_gateway && n.risk >= Severity::Medium).count();
        let dns_flag = r.dns_cache.iter().filter(|d| d.risk >= Severity::Low).count();
        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .children(
                [(NetFilter::External, "外联连接"), (NetFilter::Suspicious, "可疑连接"), (NetFilter::Listen, "监听端口"), (NetFilter::All, "全部")]
                    .into_iter()
                    .enumerate()
                    .map(|(i, (nf, label))| {
                        chip(&t, ("net-f", i), format!("{label} ({})", count(nf)), f == nf).on_click(cx.listener(move |this, _, _, cx| {
                            this.f_net = nf;
                            this.selected = None;
                            cx.notify();
                        }))
                    }),
            )
            .child(div().w(px(1.)).h(px(18.)).bg(t.border).mx_1())
            .children([(NetFilter::Dns, "DNS 缓存"), (NetFilter::Neighbors, "ARP / 邻居表")].into_iter().enumerate().map(|(i, (nf, label))| {
                chip(&t, ("net-c", i), format!("{label} ({})", count(nf)), f == nf).on_click(cx.listener(move |this, _, _, cx| {
                    this.f_net = nf;
                    this.selected = None;
                    cx.notify();
                }))
            }))
            .child(div().flex_1())
            .when(gw_alert > 0, |d| d.child(badge(format!("网关 MAC 异常 {gw_alert}"), t.red, t.red_soft)))
            .when(dns_flag > 0, |d| d.child(badge(format!("DNS 解析需关注 {dns_flag}"), t.orange, t.orange_soft)));
        let search = self.search_box(Page::Network, cx);
        let (list, subtitle) = match f {
            NetFilter::Dns => {
                let idx = refine(
                    (0..r.dns_cache.len()).collect(),
                    &r.dns_cache,
                    &query,
                    self.sort_of(ListId::Dns),
                    |d| format!("{} {} {} {}", d.name, d.rtype, d.data, d.reasons.join(" ")),
                    dns_key,
                );
                let list = self.virtual_table(&t, ListId::Dns, DNS_COLS, Rc::new(idx), "未读取到 DNS 缓存（DNS Client 服务可能未运行）", cx, |this, i, ix, t, _cx| {
                    let d = &this.report.dns_cache[i];
                    table_row(
                        t,
                        ("dns", ix),
                        DNS_COLS,
                        vec![
                            div().w_full().truncate().font_weight(FontWeight::MEDIUM).child(d.name.clone()).into_any_element(),
                            muted_cell(t, d.rtype.clone()),
                            mono_cell(t, d.data.clone()),
                            muted_cell(t, if d.ttl == 0 { "-".to_string() } else { format!("{} 秒", d.ttl) }),
                            sev_badge(t, d.risk).into_any_element(),
                            muted_cell(t, reasons_text(&d.reasons)),
                        ],
                    )
                });
                (list, "本机 DNS 客户端缓存（只读取缓存，不发起任何查询），用于还原近期解析过的域名")
            }
            NetFilter::Neighbors => {
                let idx = refine(
                    (0..r.neighbors.len()).collect(),
                    &r.neighbors,
                    &query,
                    self.sort_of(ListId::Arp),
                    |n| format!("{} {} {} {} {}", n.ip, n.mac, n.interface, n.state, n.reasons.join(" ")),
                    neighbor_key,
                );
                let list = self.virtual_table(&t, ListId::Arp, NEIGHBOR_COLS, Rc::new(idx), "未读取到 ARP / 邻居表", cx, |this, i, ix, t, _cx| {
                    let n = &this.report.neighbors[i];
                    table_row(
                        t,
                        ("arp", ix),
                        NEIGHBOR_COLS,
                        vec![
                            div()
                                .w_full()
                                .flex()
                                .items_center()
                                .gap_2()
                                .when(n.is_gateway, |d| d.child(badge("网关", t.blue, t.blue_soft)))
                                .child(mono_cell(t, n.ip.clone()))
                                .into_any_element(),
                            mono_cell(t, n.mac.clone()),
                            muted_cell(t, n.interface.clone()),
                            muted_cell(t, n.state.clone()),
                            sev_badge(t, n.risk).into_any_element(),
                            muted_cell(t, reasons_text(&n.reasons)),
                        ],
                    )
                });
                (list, "ARP / IPv6 邻居表快照，核对网关 MAC 是否与其他地址重复（ARP 欺骗迹象）")
            }
            _ => {
                let mut idx: Vec<usize> = (0..r.connections.len()).filter(|&i| conn_match(&r.connections[i], f)).collect();
                idx.sort_by(|&a, &b| {
                    let (ca, cb) = (&r.connections[a], &r.connections[b]);
                    cb.risk.cmp(&ca.risk).then(cb.external.cmp(&ca.external)).then(ca.local_port.cmp(&cb.local_port))
                });
                let idx = refine(idx, &r.connections, &query, self.sort_of(ListId::Net), conn_hay, conn_key);
                let list = self.virtual_table(&t, ListId::Net, NET_COLS, Rc::new(idx), "没有符合条件的连接", cx, |this, i, ix, t, _cx| {
                    let c = &this.report.connections[i];
                    let remote = if c.remote_addr.is_empty() { "-".into() } else { format!("{}:{}", c.remote_addr, c.remote_port) };
                    let blocked = this.blocked_ips.contains(&c.remote_addr);
                    table_row(
                        t,
                        ("net", ix),
                        NET_COLS,
                        vec![
                            muted_cell(t, c.proto.clone()),
                            mono_cell(t, format!("{}:{}", c.local_addr, c.local_port)),
                            div()
                                .w_full()
                                .flex()
                                .items_center()
                                .gap_1()
                                .when(blocked, |d| d.child(icon("ban", 13., t.red)))
                                .when(c.external && !blocked, |d| d.child(icon("globe", 13., t.blue)))
                                .child(
                                    div()
                                        .w_full()
                                        .flex()
                                        .flex_col()
                                        .child(mono_cell(t, remote))
                                        .when(!c.domain.is_empty(), |d| d.child(div().w_full().truncate().text_size(px(11.5)).text_color(t.text_faint).child(c.domain.clone()))),
                                )
                                .into_any_element(),
                            muted_cell(t, if c.state.is_empty() { "-".to_string() } else { c.state.clone() }),
                            mono_cell(t, c.pid.to_string()),
                            text_cell(c.process.clone()),
                            sev_badge(t, c.risk).into_any_element(),
                            muted_cell(t, if c.reasons.is_empty() { c.path.clone() } else { c.reasons.join("；") }),
                        ],
                    )
                });
                (list, "TCP/UDP 连接与监听端口，关联进程、DNS 缓存域名并标记公网外联；右键可用防火墙封禁远程 IP")
            }
        };
        list_page(&t, "网络连接", subtitle, search, toolbar, list)
    }

    pub fn render_persistence(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let kind = self.f_persist_kind;
        let all = self.f_persist_all;
        let query = self.query(Page::Persistence, cx);
        let mut idx: Vec<usize> = (0..r.persistence.len())
            .filter(|&i| {
                let it = &r.persistence[i];
                kind.map(|k| it.kind == k).unwrap_or(true) && (all || noteworthy_persist(it))
            })
            .collect();
        idx.sort_by(|&a, &b| {
            let (x, y) = (&r.persistence[a], &r.persistence[b]);
            y.risk.cmp(&x.risk).then(y.time.cmp(&x.time))
        });
        let idx = refine(idx, &r.persistence, &query, self.sort_of(ListId::Persist), persist_hay, persist_key);
        let mut kinds: Vec<(PersistKind, usize)> = Vec::new();
        for it in &r.persistence {
            if !all && !noteworthy_persist(it) {
                continue;
            }
            match kinds.iter_mut().find(|(k, _)| *k == it.kind) {
                Some(e) => e.1 += 1,
                None => kinds.push((it.kind, 1)),
            }
        }
        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .child(chip(&t, "ps-focus", "重点关注", !all).on_click(cx.listener(|this, _, _, cx| {
                this.f_persist_all = false;
                cx.notify();
            })))
            .child(chip(&t, "ps-all", format!("全部 ({})", r.persistence.len()), all).on_click(cx.listener(|this, _, _, cx| {
                this.f_persist_all = true;
                cx.notify();
            })))
            .child(div().w(px(1.)).h(px(18.)).bg(t.border).mx_1())
            .child(chip(&t, "pk-all", "全部类型", kind.is_none()).on_click(cx.listener(|this, _, _, cx| {
                this.f_persist_kind = None;
                cx.notify();
            })))
            .children(kinds.into_iter().enumerate().map(|(i, (k, n))| {
                chip(&t, ("pk", i), format!("{} {n}", k.label()), kind == Some(k)).on_click(cx.listener(move |this, _, _, cx| {
                    this.f_persist_kind = Some(k);
                    cx.notify();
                }))
            }));
        let search = self.search_box(Page::Persistence, cx);
        let list = self.virtual_table(&t, ListId::Persist, PERSIST_COLS, Rc::new(idx), "没有需要关注的启动项", cx, |this, i, ix, t, _cx| {
            let it = &this.report.persistence[i];
            table_row(
                t,
                ("ps", ix),
                PERSIST_COLS,
                vec![
                    muted_cell(t, it.kind.label()),
                    div().w_full().truncate().font_weight(FontWeight::MEDIUM).child(it.name.clone()).into_any_element(),
                    div()
                        .w_full()
                        .flex()
                        .flex_col()
                        .child(mono_cell(t, if it.command.is_empty() { it.location.clone() } else { it.command.clone() }))
                        .when(!it.reasons.is_empty(), |d| {
                            let (fg, _) = t.severity(it.risk);
                            d.child(div().w_full().truncate().text_size(px(11.5)).text_color(fg).child(it.reasons.join("；")))
                        })
                        .into_any_element(),
                    if it.image.is_empty() { muted_cell(t, "-") } else { sign_badge(t, it.sign).into_any_element() },
                    muted_cell(t, if it.enabled { "启用" } else { "禁用" }),
                    muted_cell(t, fmt_time(it.time)),
                    sev_badge(t, it.risk).into_any_element(),
                ],
            )
        });
        list_page(&t, "启动项排查", "注册表自启动、服务、计划任务、启动目录、映像劫持、WMI 订阅、受信任根证书等；右键可停止服务、删除计划任务", search, toolbar, list)
    }

    pub fn render_events(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let f = self.f_event;
        let query = self.query(Page::EventLog, cx);
        let idx: Vec<usize> = (0..r.events.len()).filter(|&i| f.matches(&r.events[i])).collect();
        let idx = refine(idx, &r.events, &query, self.sort_of(ListId::Event), event_hay, event_key);
        let gaps = r.log_gaps.clone();
        let toolbar = div().flex().flex_wrap().items_center().gap_2().children(EventFilter::ALL.iter().enumerate().map(|(i, (ef, label))| {
            let ef = *ef;
            let n = r.events.iter().filter(|e| ef.matches(e)).count();
            chip(&t, ("ev-f", i), format!("{label} ({n})"), f == ef).on_click(cx.listener(move |this, _, _, cx| {
                this.f_event = ef;
                cx.notify();
            }))
        }));
        let search = self.search_box(Page::EventLog, cx);
        let list = self.virtual_table(&t, ListId::Event, EVENT_COLS, Rc::new(idx), "回溯周期内没有此类事件（或未开启对应审计）", cx, |this, i, ix, t, _cx| {
            let e = &this.report.events[i];
            table_row(
                t,
                ("ev", ix),
                EVENT_COLS,
                vec![
                    muted_cell(t, fmt_time(e.time)),
                    mono_cell(t, e.event_id.to_string()),
                    muted_cell(t, e.channel.clone()),
                    div().w_full().truncate().font_weight(FontWeight::MEDIUM).child(e.title.clone()).into_any_element(),
                    muted_cell(t, e.user.clone()),
                    mono_cell(t, e.source_ip.clone()),
                    muted_cell(t, [e.logon_type.as_str(), e.detail.as_str(), e.process.as_str()].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" · ")),
                    sev_badge(t, e.severity).into_any_element(),
                ],
            )
        });
        let toolbar = div()
            .flex()
            .flex_col()
            .gap(px(10.))
            .when(!gaps.is_empty(), |d| d.child(notice(&t, "审计/日志配置不完整，部分事件可能未被记录", &gaps)))
            .child(toolbar);
        list_page(&t, "日志分析", &format!("近 {} 天的登录、账户变更、服务/任务、日志清除、RDP、PowerShell 与 Defender 关键事件", r.lookback_days.max(1)), search, toolbar, list)
    }

    pub fn render_files(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let kind = self.f_file_kind;
        let sus_only = self.f_file_suspicious;
        let query = self.query(Page::File, cx);
        let mut idx: Vec<usize> = (0..r.files.len())
            .filter(|&i| {
                let f = &r.files[i];
                kind.map(|k| f.kind == k).unwrap_or(true) && (!sus_only || f.risk >= Severity::Low)
            })
            .collect();
        idx.sort_by(|&a, &b| {
            let (x, y) = (&r.files[a], &r.files[b]);
            y.risk.cmp(&x.risk).then(y.modified.cmp(&x.modified))
        });
        let idx = refine(idx, &r.files, &query, self.sort_of(ListId::File), file_hay, file_key);
        let kinds = [
            ArtifactKind::RecentFile,
            ArtifactKind::WebChange,
            ArtifactKind::Prefetch,
            ArtifactKind::Bam,
            ArtifactKind::RecentDoc,
            ArtifactKind::RunMru,
            ArtifactKind::RdpOutbound,
            ArtifactKind::Software,
            ArtifactKind::Usb,
            ArtifactKind::AltStream,
            ArtifactKind::Hosts,
            ArtifactKind::PsHistory,
        ];
        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .child(chip(&t, "fk-all", format!("全部 ({})", r.files.len()), kind.is_none()).on_click(cx.listener(|this, _, _, cx| {
                this.f_file_kind = None;
                cx.notify();
            })))
            .children(kinds.into_iter().enumerate().filter_map(|(i, k)| {
                let n = r.files.iter().filter(|f| f.kind == k).count();
                (n > 0).then(|| {
                    chip(&t, ("fk", i), format!("{} {n}", k.label()), kind == Some(k)).on_click(cx.listener(move |this, _, _, cx| {
                        this.f_file_kind = Some(k);
                        cx.notify();
                    }))
                })
            }))
            .child(div().w(px(1.)).h(px(18.)).bg(t.border).mx_1())
            .child(chip(&t, "f-sus", "仅看需关注", sus_only).on_click(cx.listener(|this, _, _, cx| {
                this.f_file_suspicious = !this.f_file_suspicious;
                cx.notify();
            })));
        let search = self.search_box(Page::File, cx);
        let list = self.virtual_table(&t, ListId::File, FILE_COLS, Rc::new(idx), "没有符合条件的文件痕迹", cx, |this, i, ix, t, _cx| {
            let f = &this.report.files[i];
            table_row(
                t,
                ("file", ix),
                FILE_COLS,
                vec![
                    muted_cell(t, f.kind.label()),
                    div().w_full().truncate().font_weight(FontWeight::MEDIUM).child(f.name.clone()).into_any_element(),
                    muted_cell(t, if f.reasons.is_empty() { if f.note.is_empty() { f.path.clone() } else { f.note.clone() } } else { f.reasons.join("；") }),
                    muted_cell(t, fmt_size(f.size)),
                    muted_cell(t, fmt_time(f.modified)),
                    if f.sign == SignState::NotChecked { muted_cell(t, "-") } else { sign_badge(t, f.sign).into_any_element() },
                    sev_badge(t, f.risk).into_any_element(),
                ],
            )
        });
        list_page(&t, "文件排查", "临时/公共目录新增文件（含下载来源与备用数据流）、Web 目录变更、Prefetch 执行痕迹、最近访问、Hosts 与 PowerShell 历史", search, toolbar, list)
    }

    pub fn render_registry(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();
        let cat = self.f_reg_cat;
        let query = self.query(Page::Registry, cx);
        let mut idx: Vec<usize> = (0..r.registry.len())
            .filter(|&i| cat.map(|c| r.registry[i].category == c).unwrap_or(true))
            .collect();
        idx.sort_by(|&a, &b| {
            let (x, y) = (&r.registry[a], &r.registry[b]);
            y.risk.cmp(&x.risk).then(y.time.cmp(&x.time))
        });
        let idx = refine(idx, &r.registry, &query, self.sort_of(ListId::Reg), reg_hay, reg_key);
        let toolbar = div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap_2()
            .child(chip(&t, "rc-all", format!("全部 ({})", r.registry.len()), cat.is_none()).on_click(cx.listener(|this, _, _, cx| {
                this.f_reg_cat = None;
                cx.notify();
            })))
            .children(RegCategory::ALL.into_iter().enumerate().filter_map(|(i, c)| {
                let n = r.registry.iter().filter(|x| x.category == c).count();
                (n > 0).then(|| {
                    chip(&t, ("rc", i), format!("{} {n}", c.label()), cat == Some(c)).on_click(cx.listener(move |this, _, _, cx| {
                        this.f_reg_cat = Some(c);
                        cx.notify();
                    }))
                })
            }));
        let search = self.search_box(Page::Registry, cx);
        let list = self.virtual_table(&t, ListId::Reg, REG_COLS, Rc::new(idx), "未读取到注册表痕迹（部分位置需要管理员权限）", cx, |this, i, ix, t, _cx| {
            let it = &this.report.registry[i];
            table_row(
                t,
                ("reg", ix),
                REG_COLS,
                vec![
                    muted_cell(t, it.category.label()),
                    div().w_full().truncate().font_weight(FontWeight::MEDIUM).child(one_line(&it.name)).into_any_element(),
                    muted_cell(t, if it.value.is_empty() { it.note.clone() } else { it.value.clone() }),
                    muted_cell(t, if it.user.is_empty() { "-".to_string() } else { it.user.clone() }),
                    muted_cell(t, fmt_time(it.time)),
                    sev_badge(t, it.risk).into_any_element(),
                ],
            )
        });
        list_page(
            &t,
            "注册表取证",
            "程序启动记录 (UserAssist)、ShimCache、最近文档、地址栏与搜索历史、网络连接历史、Office 信任文档等",
            search,
            toolbar,
            list,
        )
    }
}

impl AppView {
    pub fn render_accounts(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = theme(cx);
        let r = self.report.clone();

        const ACC_COLS: &[Col] = &[
            col("用户名", 170.),
            col("RID", 60.),
            col("权限", 76.),
            col("状态", 64.),
            col("最后登录", 150.),
            col("登录次数", 70.),
            col("密码已用", 76.),
            col("风险", 60.),
            flex_col("研判依据 / 所属组"),
        ];
        let acc_rows: Vec<AnyElement> = r
            .accounts
            .iter()
            .enumerate()
            .map(|(i, a)| {
                table_row(
                    &t,
                    ("acc", i),
                    ACC_COLS,
                    vec![
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(icon("user", 15., if a.is_admin { t.orange } else { t.text_muted }))
                            .child(div().truncate().font_weight(FontWeight::MEDIUM).child(a.name.clone()))
                            .into_any_element(),
                        mono_cell(&t, a.rid.to_string()),
                        if a.is_admin { badge("管理员", t.orange, t.orange_soft).into_any_element() } else { muted_cell(&t, "普通用户") },
                        if a.disabled { muted_cell(&t, "禁用") } else { badge("启用", t.green, t.green_soft).into_any_element() },
                        muted_cell(&t, fmt_time(a.last_logon)),
                        muted_cell(&t, a.num_logons.to_string()),
                        muted_cell(&t, format!("{} 天", a.pwd_age_days)),
                        sev_badge(&t, a.risk).into_any_element(),
                        muted_cell(&t, if a.reasons.is_empty() { a.groups.join(", ") } else { a.reasons.join("；") }),
                    ],
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    let a = &this.report.accounts[i];
                    let d = Detail::new(a.name.clone(), if a.full_name.is_empty() { a.comment.clone() } else { a.full_name.clone() }, Some(a.risk))
                        .field("研判依据", reasons_text(&a.reasons))
                        .field("RID", a.rid.to_string())
                        .field("所属组", a.groups.join(", "))
                        .field("状态", format!("{}{}", if a.disabled { "禁用" } else { "启用" }, if a.locked { "（已锁定）" } else { "" }))
                        .field("最后登录", fmt_time(a.last_logon))
                        .field("登录次数 / 错误口令次数", format!("{} / {}", a.num_logons, a.bad_pw_count))
                        .field("密码已使用", format!("{} 天", a.pwd_age_days))
                        .field("密码永不过期", if a.pwd_never_expires { "是" } else { "否" })
                        .field("允许空密码", if a.pwd_not_required { "是" } else { "否" })
                        .field("创建时间（来自 4720 日志）", fmt_time(a.created))
                        .field("描述", a.comment.clone());
                    this.show(d, cx);
                }))
                .into_any_element()
            })
            .collect();

        // 当前会话
        const SS_COLS: &[Col] = &[col("类型", 110.), col("会话", 70.), col("用户", 220.), col("状态", 110.), col("客户端", 180.), col("来源地址", 160.), col("风险", 60.), flex_col("说明")];
        let ss_rows: Vec<AnyElement> = r
            .sessions
            .iter()
            .enumerate()
            .map(|(i, s)| {
                table_row(
                    &t,
                    ("ss", i),
                    SS_COLS,
                    vec![
                        muted_cell(&t, s.kind.clone()),
                        mono_cell(&t, if s.kind == "SMB 共享访问" { "-".to_string() } else { s.id.to_string() }),
                        text_cell(s.user.clone()),
                        muted_cell(&t, s.state.clone()),
                        muted_cell(&t, if s.client.is_empty() { s.station.clone() } else { s.client.clone() }),
                        mono_cell(&t, if s.client_ip.is_empty() { "-".to_string() } else { s.client_ip.clone() }),
                        sev_badge(&t, s.risk).into_any_element(),
                        muted_cell(&t, reasons_text(&s.reasons)),
                    ],
                )
                .into_any_element()
            })
            .collect();

        // 组成员（只展示有成员的组）
        const GM_COLS: &[Col] = &[col("本地组", 220.), flex_col("成员"), col("类型", 100.)];
        let gm_rows: Vec<AnyElement> = r
            .group_members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let admin = crate::collect::baseline::is_admin_group(&m.group) || m.group.contains("Remote Desktop");
                table_row(
                    &t,
                    ("gm", i),
                    GM_COLS,
                    vec![
                        div()
                            .w_full()
                            .truncate()
                            .text_color(if admin { t.orange } else { t.text })
                            .child(m.group.clone())
                            .into_any_element(),
                        text_cell(m.member.clone()),
                        muted_cell(&t, m.kind.clone()),
                    ],
                )
                .into_any_element()
            })
            .collect();

        // 登录来源统计
        let mut stat: HashMap<String, (usize, usize, Option<Time>, Vec<String>)> = HashMap::new();
        for e in r.events.iter().filter(|e| matches!(e.event_id, 4624 | 4625 | 1149)) {
            let key = if e.source_ip.is_empty() { "本地".to_string() } else { e.source_ip.clone() };
            let ent = stat.entry(key).or_insert((0, 0, None, Vec::new()));
            if e.event_id == 4625 { ent.1 += 1 } else { ent.0 += 1 }
            ent.2 = ent.2.max(e.time);
            if !ent.3.contains(&e.user) && ent.3.len() < 6 {
                ent.3.push(e.user.clone());
            }
        }
        let mut stat: Vec<_> = stat.into_iter().collect();
        stat.sort_by_key(|(_, (ok, fail, _, _))| std::cmp::Reverse(fail + ok));
        const LS_COLS: &[Col] = &[col("来源", 200.), col("成功", 70.), col("失败", 70.), col("最近时间", 150.), flex_col("涉及账户")];
        let ls_rows: Vec<AnyElement> = stat
            .iter()
            .take(50)
            .enumerate()
            .map(|(i, (ip, (ok, fail, last, users)))| {
                let public = ip != "本地" && !crate::collect::util::is_private_ip_str(ip);
                table_row(
                    &t,
                    ("ls", i),
                    LS_COLS,
                    vec![
                        div()
                            .w_full()
                            .flex()
                            .items_center()
                            .gap_1()
                            .when(public, |d| d.child(icon("globe", 13., t.red)))
                            .child(mono_cell(&t, ip.clone()))
                            .into_any_element(),
                        text_cell(ok.to_string()),
                        div().text_color(if *fail >= 10 { t.red } else { t.text }).child(fail.to_string()).into_any_element(),
                        muted_cell(&t, fmt_time(*last)),
                        muted_cell(&t, users.join(", ")),
                    ],
                )
                .into_any_element()
            })
            .collect();

        let section = |title: &str, cols: &'static [Col], rows: Vec<AnyElement>, empty: &str| {
            let is_empty = rows.is_empty();
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(section_header(&t, title))
                .child(
                    card(&t)
                        .overflow_hidden()
                        .child(table_header(&t, cols))
                        .children(rows)
                        .when(is_empty, |d| d.child(empty_state(&t, "info", empty.to_string()))),
                )
        };

        div()
            .id("page-accounts")
            .size_full()
            .overflow_y_scroll()
            .child(
                div()
                    .w_full()
                    .flex_none()
                    .p(px(20.))
                    .flex()
                    .flex_col()
                    .gap(px(18.))
            .child(page_title(&t, "账户与登录", "本地账户、隐藏/新建账户、组成员与登录来源统计"))
            .child(section("本地账户", ACC_COLS, acc_rows, "未读取到本地账户"))
            .child(section("当前会话（终端服务 / SMB）", SS_COLS, ss_rows, "当前没有其他会话"))
            .child(section("登录来源统计（4624 / 4625 / 1149）", LS_COLS, ls_rows, "回溯周期内无登录记录或无权限读取安全日志"))
            .child(section("本地组成员", GM_COLS, gm_rows, "未读取到组成员")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32, secs: i64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: format!("p{pid}"),
            start_time: crate::collect::util::unix_to_local(1_700_000_000 + secs, 0),
            ..Default::default()
        }
    }

    #[test]
    fn tree_nests_children_under_parents() {
        let procs = vec![p(1, 0, 0), p(2, 1, 10), p(3, 2, 20), p(4, 1, 5)];
        let rows = process_tree(&procs, |_| true, &HashSet::new());
        let order: Vec<(u32, u16)> = rows.iter().map(|r| (procs[r.index].pid, r.depth)).collect();
        assert_eq!(order, vec![(1, 0), (4, 1), (2, 1), (3, 2)]);
        assert!(rows[0].has_children);
    }

    #[test]
    fn tree_treats_reused_pid_as_orphan() {
        // 父进程 PID 10 比子进程启动得晚：PID 已被复用，子进程应作为根
        let procs = vec![p(10, 0, 100), p(20, 10, 50)];
        let rows = process_tree(&procs, |_| true, &HashSet::new());
        assert!(rows.iter().all(|r| r.depth == 0));
    }

    #[test]
    fn tree_keeps_ancestors_of_matches_and_collapses() {
        let procs = vec![p(1, 0, 0), p(2, 1, 10), p(3, 2, 20), p(5, 0, 1)];
        let rows = process_tree(&procs, |i| procs[i].pid == 3, &HashSet::new());
        let pids: Vec<u32> = rows.iter().map(|r| procs[r.index].pid).collect();
        assert_eq!(pids, vec![1, 2, 3]);
        let collapsed: HashSet<u32> = [2].into_iter().collect();
        let rows = process_tree(&procs, |_| true, &collapsed);
        let pids: Vec<u32> = rows.iter().map(|r| procs[r.index].pid).collect();
        assert_eq!(pids, vec![1, 2, 5]);
    }

    #[test]
    fn tree_survives_cycles() {
        let procs = vec![p(1, 2, 0), p(2, 1, 0)];
        let rows = process_tree(&procs, |_| true, &HashSet::new());
        assert_eq!(rows.len(), 2);
    }
}
