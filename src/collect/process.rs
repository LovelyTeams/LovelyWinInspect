//! 进程枚举：Toolhelp 快照 + 逐进程查询路径、命令行、用户、启动时间与签名。

use std::collections::HashMap;
use std::ffi::c_void;

use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Security::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::*;
use windows::core::{PCWSTR, PWSTR};

use super::signature;
use super::util::{filetime_to_local, from_wide};
use crate::model::ProcessInfo;

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub fn collect() -> Vec<ProcessInfo> {
    let mut list = Vec::new();
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return list;
    };
    let snap = Handle(snap);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut sid_cache: HashMap<Vec<u8>, String> = HashMap::new();
    let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) }.is_ok();
    while ok {
        let mut p = ProcessInfo {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name: from_wide(&entry.szExeFile),
            threads: entry.cntThreads,
            ..Default::default()
        };
        if p.pid == 0 {
            p.name = "System Idle Process".into();
        } else if p.pid == 4 {
            p.user = "NT AUTHORITY\\SYSTEM".into();
        }
        if p.pid > 4 {
            fill_details(&mut p, &mut sid_cache);
        }
        list.push(p);
        ok = unsafe { Process32NextW(snap.0, &mut entry) }.is_ok();
    }

    let names: HashMap<u32, String> = list.iter().map(|p| (p.pid, p.name.clone())).collect();
    let starts: HashMap<u32, _> = list.iter().map(|p| (p.pid, p.start_time)).collect();
    for p in &mut list {
        if let Some(n) = names.get(&p.ppid) {
            // 父进程 PID 可能已被复用：父进程启动时间晚于子进程时视为已退出
            let parent_newer = matches!(
                (starts.get(&p.ppid).copied().flatten(), p.start_time),
                (Some(ps), Some(cs)) if ps > cs
            );
            if !parent_newer {
                p.parent_name = n.clone();
            }
        }
        if !p.path.is_empty() {
            p.sign = signature::check(&p.path);
        }
    }
    list
}

fn fill_details(p: &mut ProcessInfo, sid_cache: &mut HashMap<Vec<u8>, String>) {
    let Ok(h) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid) }) else {
        return;
    };
    let h = Handle(h);
    unsafe {
        // 映像路径
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        if QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .is_ok()
        {
            p.path = String::from_utf16_lossy(&buf[..size as usize]);
        }

        // 启动时间
        let mut c = FILETIME::default();
        let mut e = FILETIME::default();
        let mut k = FILETIME::default();
        let mut u = FILETIME::default();
        if GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u).is_ok() {
            p.start_time = filetime_to_local(c);
        }

        // 内存
        let mut mem = PROCESS_MEMORY_COUNTERS {
            cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        if K32GetProcessMemoryInfo(h.0, &mut mem, mem.cb).as_bool() {
            p.memory_kb = (mem.WorkingSetSize / 1024) as u64;
        }

        p.cmdline = query_cmdline(h.0).unwrap_or_default();
        p.user = query_user(h.0, sid_cache).unwrap_or_default();
    }
}

unsafe fn query_cmdline(h: HANDLE) -> Option<String> {
    unsafe {
        let mut len: u32 = 0;
        let _ = NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut len,
        );
        if len == 0 || len > 1 << 20 {
            return None;
        }
        // 以 u64 对齐分配，内容为 UNICODE_STRING + 字符串数据
        let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
        let status = NtQueryInformationProcess(
            h,
            ProcessCommandLineInformation,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * 8) as u32,
            &mut len,
        );
        if status.is_err() {
            return None;
        }
        #[repr(C)]
        struct UnicodeString {
            length: u16,
            maximum_length: u16,
            buffer: *const u16,
        }
        let us = &*(buf.as_ptr() as *const UnicodeString);
        if us.buffer.is_null() || us.length == 0 {
            return None;
        }
        let slice = std::slice::from_raw_parts(us.buffer, (us.length / 2) as usize);
        Some(String::from_utf16_lossy(slice))
    }
}

unsafe fn query_user(h: HANDLE, cache: &mut HashMap<Vec<u8>, String>) -> Option<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(h, TOKEN_QUERY, &mut token).ok()?;
        let token = Handle(token);
        let mut buf = vec![0u64; 64];
        let mut ret = 0u32;
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            (buf.len() * 8) as u32,
            &mut ret,
        )
        .ok()?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_to_name(tu.User.Sid, cache)
    }
}

/// # Safety
/// `sid` 必须是有效 SID 指针。
pub unsafe fn sid_to_name(sid: PSID, cache: &mut HashMap<Vec<u8>, String>) -> Option<String> {
    unsafe {
        let len = GetLengthSid(sid) as usize;
        let key = std::slice::from_raw_parts(sid.0 as *const u8, len).to_vec();
        if let Some(n) = cache.get(&key) {
            return Some(n.clone());
        }
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let mut nl = name.len() as u32;
        let mut dl = domain.len() as u32;
        let mut use_ = SID_NAME_USE::default();
        let result = if LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut nl,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut dl,
            &mut use_,
        )
        .is_ok()
        {
            let d = from_wide(&domain);
            let n = from_wide(&name);
            if d.is_empty() { n } else { format!("{d}\\{n}") }
        } else {
            sid_string(sid).unwrap_or_default()
        };
        cache.insert(key, result.clone());
        Some(result)
    }
}

/// # Safety
/// `sid` 必须是有效 SID 指针。
pub unsafe fn sid_string(sid: PSID) -> Option<String> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    unsafe {
        let mut out = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut out).ok()?;
        let s = out.to_string().ok();
        LocalFree(Some(HLOCAL(out.0 as *mut c_void)));
        s
    }
}

/// 当前进程是否以管理员权限（已提升）运行。
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let token = Handle(token);
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok()
            && elev.TokenIsElevated != 0
    }
}

/// 为当前进程启用指定特权（如 SeSecurityPrivilege / SeBackupPrivilege）。
pub fn enable_privilege(name: PCWSTR) -> bool {
    use windows::Win32::Foundation::LUID;
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }
        let token = Handle(token);
        let mut luid = LUID::default();
        if LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid).is_err() {
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None).is_ok()
    }
}
