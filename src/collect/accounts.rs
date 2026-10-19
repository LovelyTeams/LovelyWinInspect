//! 本地账户、组成员与密码/锁定策略。

use std::collections::HashMap;

use windows::Win32::NetworkManagement::NetManagement::*;
use windows::Win32::Security::PSID;
use windows::core::PCWSTR;

use super::process::sid_to_name;
use super::util::{pwstr, reg_open, reg_subkeys, unix_to_local};
use crate::model::{Account, GroupMember};

const MAX_PREFERRED: u32 = u32::MAX;

#[derive(Clone, Debug, Default)]
pub struct PasswordPolicy {
    pub min_len: u32,
    pub max_age_days: Option<u32>,
    pub min_age_days: u32,
    pub history: u32,
    pub lockout_threshold: u32,
    pub lockout_duration_min: Option<u32>,
    pub lockout_window_min: u32,
}

pub fn collect() -> (Vec<Account>, Vec<GroupMember>) {
    let members = group_members();
    let mut accounts = Vec::new();
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let r = NetUserEnum(
            PCWSTR::null(),
            3,
            FILTER_NORMAL_ACCOUNT,
            &mut buf,
            MAX_PREFERRED,
            &mut read,
            &mut total,
            None,
        );
        if (r == 0 || r == 234) && !buf.is_null() {
            let arr = std::slice::from_raw_parts(buf as *const USER_INFO_3, read as usize);
            for u in arr {
                let name = pwstr(u.usri3_name);
                let flags = u.usri3_flags.0;
                let mut a = Account {
                    name: name.clone(),
                    full_name: pwstr(u.usri3_full_name),
                    comment: pwstr(u.usri3_comment),
                    rid: u.usri3_user_id,
                    disabled: flags & UF_ACCOUNTDISABLE.0 != 0,
                    locked: flags & UF_LOCKOUT.0 != 0,
                    pwd_never_expires: flags & UF_DONT_EXPIRE_PASSWD.0 != 0,
                    pwd_not_required: flags & UF_PASSWD_NOTREQD.0 != 0,
                    last_logon: unix_to_local(u.usri3_last_logon as i64, 0),
                    num_logons: u.usri3_num_logons,
                    bad_pw_count: u.usri3_bad_pw_count,
                    pwd_age_days: u.usri3_password_age / 86400,
                    ..Default::default()
                };
                let lname = name.to_ascii_lowercase();
                for m in &members {
                    let mem = m.member.to_ascii_lowercase();
                    if mem == lname || mem.ends_with(&format!("\\{lname}")) {
                        a.groups.push(m.group.clone());
                    }
                }
                a.is_admin = u.usri3_priv == USER_PRIV_ADMIN;
                accounts.push(a);
            }
            NetApiBufferFree(Some(buf as *const _));
        }
    }

    // 以 SYSTEM 权限运行时可读取 SAM，对比发现 NetUserEnum 看不到的隐藏账户
    if let Some(k) = reg_open("HKLM", r"SAM\SAM\Domains\Account\Users\Names") {
        let known: Vec<String> = accounts.iter().map(|a| a.name.to_ascii_lowercase()).collect();
        for n in reg_subkeys(&k) {
            if !known.contains(&n.to_ascii_lowercase()) {
                accounts.push(Account {
                    name: n,
                    comment: "仅存在于 SAM 注册表中".into(),
                    reasons: vec!["NetUserEnum 不可见的隐藏账户".into()],
                    ..Default::default()
                });
            }
        }
    }
    (accounts, members)
}

fn group_members() -> Vec<GroupMember> {
    let mut out = Vec::new();
    let mut sid_cache: HashMap<Vec<u8>, String> = HashMap::new();
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        if NetLocalGroupEnum(PCWSTR::null(), 0, &mut buf, MAX_PREFERRED, &mut read, &mut total, None) != 0
            || buf.is_null()
        {
            return out;
        }
        let groups: Vec<String> = std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_0, read as usize)
            .iter()
            .map(|g| pwstr(g.lgrpi0_name))
            .collect();
        NetApiBufferFree(Some(buf as *const _));

        for g in groups {
            let gw = super::util::wide(&g);
            let mut mbuf: *mut u8 = std::ptr::null_mut();
            let mut mread = 0u32;
            let mut mtotal = 0u32;
            if NetLocalGroupGetMembers(
                PCWSTR::null(),
                PCWSTR(gw.as_ptr()),
                2,
                &mut mbuf,
                MAX_PREFERRED,
                &mut mread,
                &mut mtotal,
                None,
            ) != 0
                || mbuf.is_null()
            {
                continue;
            }
            let arr = std::slice::from_raw_parts(mbuf as *const LOCALGROUP_MEMBERS_INFO_2, mread as usize);
            for m in arr {
                let mut name = pwstr(m.lgrmi2_domainandname);
                if name.is_empty() && !m.lgrmi2_sid.0.is_null() {
                    name = sid_to_name(PSID(m.lgrmi2_sid.0), &mut sid_cache).unwrap_or_default();
                }
                let kind = match m.lgrmi2_sidusage.0 {
                    1 => "用户",
                    2 | 4 | 5 => "组",
                    6 => "已删除账户",
                    _ => "其他",
                };
                out.push(GroupMember { group: g.clone(), member: name, kind: kind.into() });
            }
            NetApiBufferFree(Some(mbuf as *const _));
        }
    }
    out
}

pub fn password_policy() -> Option<PasswordPolicy> {
    unsafe {
        let mut p = PasswordPolicy::default();
        let mut buf: *mut u8 = std::ptr::null_mut();
        if NetUserModalsGet(PCWSTR::null(), 0, &mut buf) != 0 || buf.is_null() {
            return None;
        }
        let m0 = &*(buf as *const USER_MODALS_INFO_0);
        p.min_len = m0.usrmod0_min_passwd_len;
        p.max_age_days = if m0.usrmod0_max_passwd_age == u32::MAX {
            None
        } else {
            Some(m0.usrmod0_max_passwd_age / 86400)
        };
        p.min_age_days = m0.usrmod0_min_passwd_age / 86400;
        p.history = m0.usrmod0_password_hist_len;
        NetApiBufferFree(Some(buf as *const _));

        let mut buf: *mut u8 = std::ptr::null_mut();
        if NetUserModalsGet(PCWSTR::null(), 3, &mut buf) == 0 && !buf.is_null() {
            let m3 = &*(buf as *const USER_MODALS_INFO_3);
            p.lockout_threshold = m3.usrmod3_lockout_threshold;
            p.lockout_duration_min = if m3.usrmod3_lockout_duration == u32::MAX {
                None
            } else {
                Some(m3.usrmod3_lockout_duration / 60)
            };
            p.lockout_window_min = m3.usrmod3_lockout_observation_window / 60;
            NetApiBufferFree(Some(buf as *const _));
        }
        Some(p)
    }
}

/// 网络共享列表 (名称, 路径, 备注)。
pub fn shares() -> Vec<(String, String, String)> {
    use windows::Win32::Storage::FileSystem::{NetShareEnum, SHARE_INFO_2};
    let mut out = Vec::new();
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        if NetShareEnum(PCWSTR::null(), 2, &mut buf, MAX_PREFERRED, &mut read, &mut total, None) == 0
            && !buf.is_null()
        {
            for s in std::slice::from_raw_parts(buf as *const SHARE_INFO_2, read as usize) {
                out.push((pwstr(s.shi2_netname), pwstr(s.shi2_path), pwstr(s.shi2_remark)));
            }
            NetApiBufferFree(Some(buf as *const _));
        }
    }
    out
}
