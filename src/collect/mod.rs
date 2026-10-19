//! 采集调度：按阶段执行，每个阶段写入 ScanReport 并返回一行摘要。

pub mod accounts;
pub mod baseline;
mod baseline_ext;
mod certs;
pub mod eventlog;
pub mod files;
pub mod host;
pub mod lnk;
pub mod network;
mod network_ext;
pub mod persistence;
mod persistence_ext;
mod artifacts_ext;
pub mod sessions;
pub mod process;
pub mod signature;
pub mod util;

use crate::model::{ScanReport, Stage};

pub fn run_stage(stage: Stage, report: &mut ScanReport) -> String {
    let since = util::days_ago(report.lookback_days);
    match stage {
        Stage::Host => {
            report.host = host::collect();
            format!("{} / {}", report.host.hostname, report.host.os_name)
        }
        Stage::Process => {
            report.processes = process::collect();
            format!("已采集 {} 个进程", report.processes.len())
        }
        Stage::Network => {
            report.connections = network::collect(&report.processes);
            report.dns_cache = network_ext::dns_cache();
            report.neighbors = network_ext::neighbors(&report.host.adapters);
            network_ext::annotate_domains(&mut report.connections, &report.dns_cache);
            let ext = report.connections.iter().filter(|c| c.external).count();
            format!(
                "{} 条连接 / {} 条外联 / DNS 缓存 {} / 邻居 {}",
                report.connections.len(),
                ext,
                report.dns_cache.len(),
                report.neighbors.len()
            )
        }
        Stage::Persistence => {
            report.persistence = persistence::collect(since);
            format!("已采集 {} 项", report.persistence.len())
        }
        Stage::Account => {
            let (accounts, members) = accounts::collect();
            report.accounts = accounts;
            report.group_members = members;
            report.sessions = sessions::collect();
            format!("{} 个账户 / {} 个会话", report.accounts.len(), report.sessions.len())
        }
        Stage::EventLog => {
            let c = eventlog::collect(report.lookback_days);
            report.errors.extend(c.errors.into_iter().map(|e| format!("日志: {e}")));
            report.events = c.events;
            format!("关键事件 {} 条", report.events.len())
        }
        Stage::File => {
            report.files = files::collect(since);
            report.shadow_copies = artifacts_ext::shadow_copies();
            match &report.shadow_copies {
                Some(s) => format!("文件痕迹 {} 条 / 卷影副本 {} 个", report.files.len(), s.len()),
                None => format!("文件痕迹 {} 条", report.files.len()),
            }
        }
        Stage::Baseline => {
            report.baseline = baseline::run(report);
            let fail = report
                .baseline
                .iter()
                .filter(|c| c.status == crate::model::CheckStatus::Fail)
                .count();
            format!("{} 项检查 / {} 项不符合", report.baseline.len(), fail)
        }
        Stage::Analysis => {
            crate::analysis::analyze(report);
            format!("发现 {} 条线索", report.findings.len())
        }
    }
}
