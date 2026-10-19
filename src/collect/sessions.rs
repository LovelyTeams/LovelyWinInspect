//! 当前会话：终端服务会话（控制台 / RDP）与入站 SMB 会话。

use std::ffi::c_void;

use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Storage::FileSystem::{NetSessionEnum, SESSION_INFO_10};
use windows::Win32::System::RemoteDesktop::*;
use windows::core::{PCWSTR, PWSTR};

use super::util::{is_private_ip_str, pwstr};
use crate::model::{SessionInfo, Severity};

fn state_label(s: WTS_CONNECTSTATE_CLASS) -> &'static str {
    match s.0 {
        0 => "活动",
        1 => "已连接",
        2 => "正在连接",
        3 => "影子会话",
        4 => "已断开",
        5 => "空闲",
        6 => "监听",
        7 => "重置",
        8 => "异常",
        9 => "初始化",
        _ => "未知",
    }
}

unsafe fn query_str(id: u32, class: WTS_INFO_CLASS) -> String {
    unsafe {
        let mut buf = PWSTR::null();
        let mut len = 0u32;
        if WTSQuerySessionInformationW(None, id, class, &mut buf, &mut len).is_err() || buf.is_null() {
            return String::new();
        }
        let s = pwstr(buf);
        WTSFreeMemory(buf.0 as *mut c_void);
        s
    }
}

unsafe fn query_client_ip(id: u32) -> String {
    unsafe {
        let mut buf = PWSTR::null();
        let mut len = 0u32;
        if WTSQuerySessionInformationW(None, id, WTSClientAddress, &mut buf, &mut len).is_err() || buf.is_null() {
            return String::new();
        }
        let addr = &*(buf.0 as *const WTS_CLIENT_ADDRESS);
        let ip = match addr.AddressFamily {
            // AF_INET：地址位于 Address[2..6]
            2 => format!("{}.{}.{}.{}", addr.Address[2], addr.Address[3], addr.Address[4], addr.Address[5]),
            23 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&addr.Address[2..18]);
                std::net::Ipv6Addr::from(b).to_string()
            }
            _ => String::new(),
        };
        WTSFreeMemory(buf.0 as *mut c_void);
        ip
    }
}

pub fn collect() -> Vec<SessionInfo> {
    let mut out = Vec::new();
    unsafe {
        let mut ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(None, 0, 1, &mut ptr, &mut count).is_ok() && !ptr.is_null() {
            for s in std::slice::from_raw_parts(ptr, count as usize) {
                let user = query_str(s.SessionId, WTSUserName);
                if user.is_empty() {
                    continue;
                }
                let domain = query_str(s.SessionId, WTSDomainName);
                let station = pwstr(s.pWinStationName);
                let client = query_str(s.SessionId, WTSClientName);
                let ip = query_client_ip(s.SessionId);
                let mut info = SessionInfo {
                    kind: if station.to_ascii_lowercase().starts_with("rdp") { "远程桌面".into() } else { "本地/控制台".into() },
                    id: s.SessionId,
                    user: if domain.is_empty() { user } else { format!("{domain}\\{user}") },
                    state: state_label(s.State).into(),
                    station,
                    client,
                    client_ip: ip.clone(),
                    ..Default::default()
                };
                if !ip.is_empty() && !is_private_ip_str(&ip) {
                    info.risk = Severity::Medium;
                    info.reasons.push("来自公网地址的远程桌面会话".into());
                }
                out.push(info);
            }
            WTSFreeMemory(ptr as *mut c_void);
        }

        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        if NetSessionEnum(PCWSTR::null(), PCWSTR::null(), PCWSTR::null(), 10, &mut buf, u32::MAX, &mut read, &mut total, None) == 0
            && !buf.is_null()
        {
            for s in std::slice::from_raw_parts(buf as *const SESSION_INFO_10, read as usize) {
                let client = pwstr(s.sesi10_cname).trim_start_matches('\\').to_string();
                let mut info = SessionInfo {
                    kind: "SMB 共享访问".into(),
                    user: pwstr(s.sesi10_username),
                    state: format!("空闲 {} 秒", s.sesi10_idle_time),
                    client: client.clone(),
                    client_ip: client.clone(),
                    active_secs: s.sesi10_time as u64,
                    ..Default::default()
                };
                if !client.is_empty() && client.parse::<std::net::IpAddr>().is_ok() && !is_private_ip_str(&client) {
                    info.risk = Severity::Medium;
                    info.reasons.push("来自公网地址的 SMB 会话".into());
                }
                out.push(info);
            }
            NetApiBufferFree(Some(buf as *const _));
        }
    }
    out
}
