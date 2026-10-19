//! 网络缓存快照：DNS 客户端缓存（只读本地缓存，不发起查询）与 ARP / IPv6 邻居表。

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::Dns::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_UNSPEC, NlnsPermanent, SOCKADDR};
use windows::core::{PCWSTR, PWSTR};

use super::network::sockaddr_ip;
use super::util::*;
use crate::model::{AdapterInfo, ConnInfo, DnsCacheEntry, NeighborEntry, Severity};

// ---------------------------------------------------------------- DNS 缓存

/// DnsGetCacheDataTable 返回的缓存表项（未公开结构，与 DNS_RECORD 头部布局一致）。
#[repr(C)]
struct CacheEntry {
    next: *mut CacheEntry,
    name: PWSTR,
    rtype: u16,
    data_len: u16,
    flags: u32,
}

#[link(name = "dnsapi.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    fn DnsGetCacheDataTable(table: *mut *mut CacheEntry) -> i32;
}

fn type_label(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        n => format!("TYPE{n}"),
    }
}

unsafe fn record_data(r: &DNS_RECORDW) -> String {
    unsafe {
        match r.wType {
            1 => Ipv4Addr::from(r.Data.A.IpAddress.to_ne_bytes()).to_string(),
            28 => Ipv6Addr::from(r.Data.AAAA.Ip6Address.IP6Byte).to_string(),
            2 | 5 | 12 => pwstr(r.Data.PTR.pNameHost),
            15 => format!("{} (优先级 {})", pwstr(r.Data.MX.pNameExchange), r.Data.MX.wPreference),
            33 => format!("{}:{}", pwstr(r.Data.SRV.pNameTarget), r.Data.SRV.wPort),
            _ => "-".into(),
        }
    }
}

pub(super) fn dns_cache() -> Vec<DnsCacheEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    unsafe {
        let mut head: *mut CacheEntry = std::ptr::null_mut();
        if DnsGetCacheDataTable(&mut head) == 0 {
            return out;
        }
        // 缓存表的释放方式未公开，这里不释放（每次扫描只调用一次，占用很小）
        let mut cur = head;
        while !cur.is_null() && out.len() < 5000 {
            let e = &*cur;
            cur = e.next;
            let name = pwstr(e.name);
            if name.is_empty() {
                continue;
            }
            let w = wide(&name);
            let mut res: *mut DNS_RECORDA = std::ptr::null_mut();
            // DNS_QUERY_NO_WIRE_QUERY：只读缓存，不产生任何网络请求
            let st = DnsQuery_W(PCWSTR(w.as_ptr()), DNS_TYPE(e.rtype), DNS_QUERY_NO_WIRE_QUERY, None, &mut res, None);
            if st.0 != 0 {
                // 查不到具体记录时仍保留缓存表中的域名（说明近期解析过）
                let data = match st.0 {
                    9003 | 9501 => "(无记录 / 域名不存在)",
                    9701 => "(记录已过期)",
                    _ => "(无法读取记录)",
                };
                if seen.insert((name.to_ascii_lowercase(), e.rtype, String::new())) {
                    out.push(DnsCacheEntry { name, rtype: type_label(e.rtype), data: data.into(), ..Default::default() });
                }
                continue;
            }
            let mut r = res as *const DNS_RECORDW;
            while !r.is_null() {
                let rec = &*r;
                r = rec.pNext;
                let rname = pwstr(rec.pName);
                let data = record_data(rec);
                if !seen.insert((rname.to_ascii_lowercase(), rec.wType, data.clone())) {
                    continue;
                }
                let mut entry = DnsCacheEntry {
                    name: if rname.is_empty() { name.clone() } else { rname },
                    rtype: type_label(rec.wType),
                    data,
                    ttl: rec.dwTtl,
                    ..Default::default()
                };
                assess_dns(&mut entry);
                out.push(entry);
            }
            if !res.is_null() {
                DnsFree(Some(res as *const _), DnsFreeRecordList);
            }
        }
    }
    out.sort_by(|a, b| b.risk.cmp(&a.risk).then(a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase())));
    out
}

fn assess_dns(e: &mut DnsCacheEntry) {
    if e.rtype != "A" && e.rtype != "AAAA" {
        return;
    }
    let lower = e.name.to_ascii_lowercase();
    let local = e.data.parse::<IpAddr>().map(|ip| is_private_ip(&ip)).unwrap_or(false);
    if local && UPDATE_DOMAINS.iter().any(|d| lower.contains(d)) {
        e.risk = Severity::Low;
        e.reasons.push("系统更新/安全服务域名被解析到本地或内网地址".into());
    }
}

/// 用 DNS 缓存为连接的远程地址补充域名（沿 CNAME 链回溯到最初查询的名称）。
pub(super) fn annotate_domains(conns: &mut [ConnInfo], dns: &[DnsCacheEntry]) {
    let mut alias: HashMap<String, String> = HashMap::new();
    let mut by_ip: HashMap<String, String> = HashMap::new();
    for e in dns {
        match e.rtype.as_str() {
            "CNAME" => {
                alias.entry(e.data.to_ascii_lowercase()).or_insert_with(|| e.name.clone());
            }
            "A" | "AAAA" => {
                by_ip.entry(e.data.clone()).or_insert_with(|| e.name.clone());
            }
            _ => {}
        }
    }
    let top = |mut n: String| {
        for _ in 0..8 {
            match alias.get(&n.to_ascii_lowercase()) {
                Some(p) if !p.eq_ignore_ascii_case(&n) => n = p.clone(),
                _ => break,
            }
        }
        n
    };
    for c in conns.iter_mut().filter(|c| !c.remote_addr.is_empty()) {
        let key = match c.remote_addr.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()),
            Ok(ip) => ip.to_string(),
            Err(_) => continue,
        };
        if let Some(n) = by_ip.get(&key) {
            c.domain = top(n.clone());
        }
    }
}

// ---------------------------------------------------------------- ARP / 邻居表

fn state_label(s: i32) -> &'static str {
    match s {
        0 => "不可达",
        1 => "未完成",
        2 => "探测中",
        3 => "延迟",
        4 => "过期",
        5 => "可达",
        6 => "静态",
        _ => "未知",
    }
}

fn interface_alias(luid: &NET_LUID_LH) -> String {
    let mut buf = [0u16; 257];
    let r = unsafe { ConvertInterfaceLuidToAlias(luid, &mut buf) };
    if r.0 == 0 { from_wide(&buf) } else { String::new() }
}

pub(super) fn neighbors(adapters: &[AdapterInfo]) -> Vec<NeighborEntry> {
    let gateways: HashSet<&str> = adapters.iter().flat_map(|a| a.gateways.iter().map(|g| g.as_str())).collect();
    let mut out: Vec<NeighborEntry> = Vec::new();
    // 每条记录所在接口，用于按接口比较 MAC
    let mut iface: Vec<u32> = Vec::new();
    let mut names: HashMap<u32, String> = HashMap::new();
    unsafe {
        let mut table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        if GetIpNetTable2(AF_UNSPEC, &mut table).0 != 0 || table.is_null() {
            return out;
        }
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for r in rows {
            let len = (r.PhysicalAddressLength as usize).min(r.PhysicalAddress.len());
            let mac = &r.PhysicalAddress[..len];
            // 跳过无 MAC、广播与组播条目
            if mac.is_empty() || mac.iter().all(|b| *b == 0) || mac.iter().all(|b| *b == 0xFF) || mac[0] & 1 == 1 {
                continue;
            }
            let Some(ip) = sockaddr_ip(&r.Address as *const _ as *const SOCKADDR) else { continue };
            if ip.is_multicast() || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast()) {
                continue;
            }
            let ip_s = ip.to_string();
            let interface = names.entry(r.InterfaceIndex).or_insert_with(|| interface_alias(&r.InterfaceLuid)).clone();
            out.push(NeighborEntry {
                is_gateway: gateways.contains(ip_s.as_str()),
                ip: ip_s,
                mac: mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-"),
                interface,
                state: state_label(r.State.0).into(),
                is_static: r.State == NlnsPermanent,
                ..Default::default()
            });
            iface.push(r.InterfaceIndex);
        }
        FreeMibTable(table as *const _);
    }

    // 同一接口上多个 IPv4 地址对应同一 MAC
    let mut groups: HashMap<(u32, String), Vec<usize>> = HashMap::new();
    for (i, n) in out.iter().enumerate() {
        if n.ip.parse::<Ipv4Addr>().is_ok() {
            groups.entry((iface[i], n.mac.clone())).or_default().push(i);
        }
    }
    for idx in groups.values().filter(|v| v.len() > 1) {
        let gw: Vec<String> = idx.iter().filter(|&&i| out[i].is_gateway).map(|&i| out[i].ip.clone()).collect();
        for &i in idx {
            let others: Vec<String> = idx.iter().filter(|&&j| j != i).map(|&j| out[j].ip.clone()).collect();
            let n = &mut out[i];
            if n.is_gateway {
                n.risk = n.risk.max(Severity::Medium);
                n.reasons.push(format!("网关 MAC 同时对应 {}（可能存在 ARP 欺骗，也可能是同一路由设备的多个地址）", others.join(", ")));
            } else if !gw.is_empty() {
                n.risk = n.risk.max(Severity::Low);
                n.reasons.push(format!("与网关 {} 使用相同 MAC", gw.join(", ")));
            } else {
                n.reasons.push(format!("与 {} 使用相同 MAC", others.join(", ")));
            }
        }
    }
    out.sort_by(|a, b| {
        b.risk
            .cmp(&a.risk)
            .then(b.is_gateway.cmp(&a.is_gateway))
            .then(a.interface.cmp(&b.interface))
            .then(a.ip.parse::<IpAddr>().ok().cmp(&b.ip.parse::<IpAddr>().ok()))
    });
    out
}
