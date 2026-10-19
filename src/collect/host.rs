//! 主机基础信息。

use windows::Win32::NetworkManagement::NetManagement::{
    NETSETUP_JOIN_STATUS, NetApiBufferFree, NetGetJoinInformation, NetSetupDomainName,
};
use windows::Win32::System::SystemInformation::{
    ComputerNamePhysicalDnsHostname, GetComputerNameExW, GetTickCount64,
};
use windows::core::{PCWSTR, PWSTR};

use super::util::*;
use super::{network, process};
use crate::model::HostInfo;

pub fn collect() -> HostInfo {
    let mut h = HostInfo::default();

    unsafe {
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        if GetComputerNameExW(ComputerNamePhysicalDnsHostname, Some(PWSTR(buf.as_mut_ptr())), &mut len).is_ok() {
            h.hostname = from_wide(&buf);
        }
        let mut name = PWSTR::null();
        let mut status = NETSETUP_JOIN_STATUS::default();
        if NetGetJoinInformation(PCWSTR::null(), &mut name, &mut status) == 0 {
            h.domain = pwstr(name);
            h.is_domain = status == NetSetupDomainName;
            NetApiBufferFree(Some(name.0 as *const _));
        }
        let up_ms = GetTickCount64();
        h.uptime_secs = up_ms / 1000;
        h.boot_time = Some(chrono::Local::now() - chrono::Duration::milliseconds(up_ms as i64));
    }
    if h.hostname.is_empty() {
        h.hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
    }

    let cv = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    if let Some(key) = reg_open("HKLM", cv) {
        let build = key_str(&key, "CurrentBuild").unwrap_or_default();
        let ubr = key_dword(&key, "UBR").unwrap_or(0);
        let mut product = key_str(&key, "ProductName").unwrap_or_else(|| "Windows".into());
        if build.parse::<u32>().unwrap_or(0) >= 22000 {
            product = product.replace("Windows 10", "Windows 11");
        }
        h.os_name = product;
        h.os_version = key_str(&key, "DisplayVersion")
            .or_else(|| key_str(&key, "ReleaseId"))
            .unwrap_or_default();
        h.build = if ubr > 0 { format!("{build}.{ubr}") } else { build };
        if let Some(ts) = key_dword(&key, "InstallDate") {
            h.install_date = unix_to_local(ts as i64, 0);
        }
    }
    h.arch = match std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default().as_str() {
        "AMD64" => "64 位操作系统 (x64)".into(),
        "ARM64" => "64 位操作系统 (ARM64)".into(),
        "x86" => "32 位操作系统 (x86)".into(),
        other => other.to_string(),
    };
    h.timezone = reg_str(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
        "TimeZoneKeyName",
    )
    .unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();
    let dom = std::env::var("USERDOMAIN").unwrap_or_default();
    h.current_user = if dom.is_empty() { user } else { format!("{dom}\\{user}") };
    h.is_admin = process::is_elevated();

    h.adapters = network::adapters();
    let primary = h
        .adapters
        .iter()
        .find(|a| a.up && a.physical && !a.gateways.is_empty())
        .or_else(|| h.adapters.iter().find(|a| a.up && !a.ips.is_empty()));
    if let Some(primary) = primary {
        h.ip = primary
            .ips
            .iter()
            .find(|ip| ip.contains('.'))
            .or(primary.ips.first())
            .cloned()
            .unwrap_or_default();
        h.mac = primary.mac.clone();
    }

    // 安全软件状态
    let ps = r#"
$o = @{}
try { $s = Get-MpComputerStatus; $o.rtp = [bool]$s.RealTimeProtectionEnabled; $o.av = [bool]$s.AntivirusEnabled } catch {}
try { $o.products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { @{ name = [string]$_.displayName; on = ((([int]$_.productState) -shr 12) -band 0x3) -ne 0 } }) } catch {}
$o | ConvertTo-Json -Compress
"#;
    if let Some(out) = run_powershell(ps) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(out.trim()) {
            let defender_rtp = v.get("rtp").and_then(|x| x.as_bool());
            let items: Vec<serde_json::Value> = match v.get("products") {
                Some(serde_json::Value::Array(a)) => a.clone(),
                Some(o @ serde_json::Value::Object(_)) => vec![o.clone()],
                _ => vec![],
            };
            let name = |x: &serde_json::Value| x.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let on: Vec<String> = items
                .iter()
                .filter(|x| x.get("on").and_then(|b| b.as_bool()).unwrap_or(false))
                .map(name)
                .collect();
            // 安全中心里存在启用状态的产品即视为实时防护开启（第三方杀软启用后 Defender 转为被动模式）
            h.av_product = if on.is_empty() { items.iter().map(name).collect::<Vec<_>>().join(" / ") } else { on.join(" / ") };
            h.av_realtime = if !on.is_empty() { Some(true) } else { defender_rtp };
        }
    }
    if h.av_product.is_empty() {
        h.av_product = "Microsoft Defender".into();
    }
    if h.av_realtime.is_none() {
        let disabled = reg_dword(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring",
        );
        h.av_realtime = Some(disabled != Some(1));
    }
    h
}
