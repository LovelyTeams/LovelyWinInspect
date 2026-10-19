//! 网络连接（TCP/UDP，含 IPv6）与网卡信息。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

use super::util::{is_private_ip, pwstr};
use crate::model::{AdapterInfo, ConnInfo, ProcessInfo};

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

fn table_buf(f: impl Fn(Option<*mut core::ffi::c_void>, &mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size = 0u32;
    f(None, &mut size);
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 16];
        size = (buf.len() * 8) as u32;
        let r = f(Some(buf.as_mut_ptr() as *mut _), &mut size);
        if r == 0 {
            return Some(buf);
        }
        if r != 122 {
            // 不是 ERROR_INSUFFICIENT_BUFFER
            return None;
        }
    }
    None
}

unsafe fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    unsafe {
        let base = buf.as_ptr() as *const u8;
        let n = *(base as *const u32) as usize;
        // dwNumEntries 之后按行结构体对齐
        let align = align_of::<T>().max(4);
        let first = base.add(align.max(4)) as *const T;
        let cap = (buf.len() * 8 - align) / size_of::<T>();
        (0..n.min(cap)).map(|i| *first.add(i)).collect()
    }
}

pub fn collect(procs: &[ProcessInfo]) -> Vec<ConnInfo> {
    let pmap: HashMap<u32, &ProcessInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let mut out = Vec::new();

    let push = |out: &mut Vec<ConnInfo>, proto: &str, la: IpAddr, lp: u16, ra: Option<IpAddr>, rp: u16, state: &str, pid: u32| {
        let (process, path) = pmap
            .get(&pid)
            .map(|p| (p.name.clone(), p.path.clone()))
            .unwrap_or_else(|| (if pid == 4 { "System".into() } else { String::new() }, String::new()));
        let external = ra.map(|r| !is_private_ip(&r)).unwrap_or(false);
        out.push(ConnInfo {
            proto: proto.into(),
            local_addr: la.to_string(),
            local_port: lp,
            remote_addr: ra.map(|r| r.to_string()).unwrap_or_default(),
            remote_port: rp,
            state: state.into(),
            pid,
            process,
            path,
            external,
            ..Default::default()
        });
    };

    unsafe {
        if let Some(buf) = table_buf(|p, s| GetExtendedTcpTable(p, s, true, AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)) {
            for r in rows::<MIB_TCPROW_OWNER_PID>(&buf) {
                let la = IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr)));
                let ra = IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)));
                let st = tcp_state(r.dwState);
                let ra = if st == "LISTEN" { None } else { Some(ra) };
                push(&mut out, "TCP", la, port(r.dwLocalPort), ra, port(r.dwRemotePort), st, r.dwOwningPid);
            }
        }
        if let Some(buf) = table_buf(|p, s| GetExtendedTcpTable(p, s, true, AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)) {
            for r in rows::<MIB_TCP6ROW_OWNER_PID>(&buf) {
                let la = IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr));
                let ra = IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr));
                let st = tcp_state(r.dwState);
                let ra = if st == "LISTEN" { None } else { Some(ra) };
                push(&mut out, "TCP6", la, port(r.dwLocalPort), ra, port(r.dwRemotePort), st, r.dwOwningPid);
            }
        }
        if let Some(buf) = table_buf(|p, s| GetExtendedUdpTable(p, s, true, AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)) {
            for r in rows::<MIB_UDPROW_OWNER_PID>(&buf) {
                let la = IpAddr::V4(Ipv4Addr::from(u32::from_be(r.dwLocalAddr)));
                push(&mut out, "UDP", la, port(r.dwLocalPort), None, 0, "", r.dwOwningPid);
            }
        }
        if let Some(buf) = table_buf(|p, s| GetExtendedUdpTable(p, s, true, AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)) {
            for r in rows::<MIB_UDP6ROW_OWNER_PID>(&buf) {
                let la = IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr));
                push(&mut out, "UDP6", la, port(r.dwLocalPort), None, 0, "", r.dwOwningPid);
            }
        }
    }
    out
}

pub(super) unsafe fn sockaddr_ip(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    unsafe {
        match (*sa).sa_family {
            f if f == AF_INET => {
                let v4 = &*(sa as *const SOCKADDR_IN);
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.S_un.S_addr))))
            }
            f if f == AF_INET6 => {
                let v6 = &*(sa as *const SOCKADDR_IN6);
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

pub fn adapters() -> Vec<AdapterInfo> {
    let mut out = Vec::new();
    unsafe {
        let flags = GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER
            | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut size = 32 * 1024u32;
        let mut buf = vec![0u64; size as usize / 8];
        let mut r = GetAdaptersAddresses(0, flags, None, Some(buf.as_mut_ptr() as *mut _), &mut size);
        if r == 111 {
            // ERROR_BUFFER_OVERFLOW
            buf = vec![0u64; size as usize / 8 + 16];
            r = GetAdaptersAddresses(0, flags, None, Some(buf.as_mut_ptr() as *mut _), &mut size);
        }
        if r != 0 {
            return out;
        }
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = &*cur;
            if a.IfType != 24 {
                // 24 = 软件回环
                let mut info = AdapterInfo {
                    name: pwstr(a.FriendlyName),
                    description: pwstr(a.Description),
                    up: a.OperStatus == IfOperStatusUp,
                    // 6 = 以太网, 71 = 无线；排除虚拟/隧道网卡
                    physical: (a.IfType == 6 || a.IfType == 71) && a.PhysicalAddressLength > 0,
                    ..Default::default()
                };
                let mlen = (a.PhysicalAddressLength as usize).min(8);
                info.mac = a.PhysicalAddress[..mlen]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join("-");
                let mut u = a.FirstUnicastAddress;
                while !u.is_null() {
                    if let Some(ip) = sockaddr_ip((*u).Address.lpSockaddr) {
                        info.ips.push(ip.to_string());
                    }
                    u = (*u).Next;
                }
                let mut g = a.FirstGatewayAddress;
                while !g.is_null() {
                    if let Some(ip) = sockaddr_ip((*g).Address.lpSockaddr) {
                        info.gateways.push(ip.to_string());
                    }
                    g = (*g).Next;
                }
                out.push(info);
            }
            cur = a.Next;
        }
    }
    // 有网关且启用的网卡排在前面
    out.sort_by_key(|a| (!a.up, a.gateways.is_empty(), !a.physical));
    out
}
