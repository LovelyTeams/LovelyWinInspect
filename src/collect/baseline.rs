//! 安全基线核查：账户策略、审计策略、安全选项、网络服务、系统防护、日志配置。

use std::collections::HashMap;

use windows::Win32::Security::Authentication::Identity::{
    AUDIT_POLICY_INFORMATION, AuditFree, AuditQuerySystemPolicy,
};
use windows::Win32::Security::SE_SECURITY_NAME;
use windows::core::GUID;

use super::accounts::{password_policy, shares};
use super::process::enable_privilege;
use super::util::*;
use crate::model::{BaselineCheck, CheckStatus, ScanReport, Severity};

pub(super) struct Builder(pub(super) Vec<BaselineCheck>);

impl Builder {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn add(
        &mut self,
        id: &str,
        group: &str,
        title: &str,
        expected: &str,
        actual: impl Into<String>,
        status: CheckStatus,
        severity: Severity,
        advice: &str,
    ) {
        self.0.push(BaselineCheck {
            id: id.into(),
            group: group.into(),
            title: title.into(),
            expected: expected.into(),
            actual: actual.into(),
            status,
            severity,
            advice: advice.into(),
        });
    }
}

pub(super) fn pass_if(ok: bool, fail: CheckStatus) -> CheckStatus {
    if ok { CheckStatus::Pass } else { fail }
}

/// secedit 导出的本地安全策略 (节 -> 键 -> 值)。
fn secedit() -> Option<HashMap<String, HashMap<String, String>>> {
    let tmp = std::env::temp_dir().join(format!("lwi_secpol_{}.inf", std::process::id()));
    let path = tmp.display().to_string();
    run_hidden("secedit.exe", &["/export", "/cfg", &path, "/areas", "SECURITYPOLICY", "USER_RIGHTS", "/quiet"])?;
    let text = read_text_any(&tmp)?;
    let _ = std::fs::remove_file(&tmp);
    let mut map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].to_string();
        } else if let Some((k, v)) = l.split_once('=') {
            map.entry(section.clone())
                .or_default()
                .insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    Some(map)
}

fn audit_policy(guids: &[GUID]) -> Option<Vec<u32>> {
    enable_privilege(SE_SECURITY_NAME);
    unsafe {
        let mut ptr: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
        if !AuditQuerySystemPolicy(guids, &mut ptr) || ptr.is_null() {
            return None;
        }
        let v = std::slice::from_raw_parts(ptr, guids.len())
            .iter()
            .map(|p| p.AuditingInformation)
            .collect();
        AuditFree(ptr as *const _);
        Some(v)
    }
}

fn audit_label(v: u32) -> &'static str {
    match v & 3 {
        3 => "成功和失败",
        1 => "成功",
        2 => "失败",
        _ => "无审核",
    }
}

pub fn run(report: &ScanReport) -> Vec<BaselineCheck> {
    let mut b = Builder(Vec::new());
    let sec = secedit();
    let sa = sec.as_ref().and_then(|s| s.get("System Access"));
    let rights = sec.as_ref().and_then(|s| s.get("Privilege Rights"));
    let sa_u32 = |k: &str| sa.and_then(|m| m.get(k)).and_then(|v| v.parse::<i64>().ok());

    // ============================================================ 账户策略
    let g = "账户策略";
    let pol = password_policy();
    match sa_u32("PasswordComplexity") {
        Some(v) => b.add("ACC-01", g, "密码必须符合复杂性要求", "已启用", if v == 1 { "已启用" } else { "已禁用" }, pass_if(v == 1, CheckStatus::Fail), Severity::High, "secpol.msc → 账户策略 → 密码策略 → 启用“密码必须符合复杂性要求”"),
        None => b.add("ACC-01", g, "密码必须符合复杂性要求", "已启用", "需管理员权限读取", CheckStatus::Unknown, Severity::High, "以管理员身份运行后重新检测"),
    }
    if let Some(p) = &pol {
        b.add("ACC-02", g, "密码长度最小值", "≥ 8 个字符", format!("{} 个字符", p.min_len), pass_if(p.min_len >= 8, CheckStatus::Fail), Severity::High, "将“密码长度最小值”设置为 8 位或以上");
        let (txt, ok) = match p.max_age_days {
            None => ("永不过期".to_string(), false),
            Some(0) => ("永不过期".to_string(), false),
            Some(d) => (format!("{d} 天"), d <= 90),
        };
        b.add("ACC-03", g, "密码最长使用期限", "≤ 90 天", txt, pass_if(ok, CheckStatus::Warn), Severity::Medium, "将“密码最长使用期限”设置为 90 天以内");
        b.add("ACC-04", g, "强制密码历史", "≥ 5 个", format!("{} 个", p.history), pass_if(p.history >= 5, CheckStatus::Warn), Severity::Low, "将“强制密码历史”设置为 5 个或以上");
        let th = p.lockout_threshold;
        b.add("ACC-05", g, "账户锁定阈值", "1 ~ 5 次无效登录", if th == 0 { "不锁定".into() } else { format!("{th} 次") }, pass_if(th > 0 && th <= 5, CheckStatus::Fail), Severity::High, "设置账户锁定阈值为 5 次以内，防范口令暴力破解");
        let dur = p.lockout_duration_min;
        let (txt, ok) = match dur {
            None => ("需管理员解锁".to_string(), true),
            Some(m) => (format!("{m} 分钟"), m >= 15),
        };
        b.add("ACC-06", g, "账户锁定时间", "≥ 15 分钟", if th == 0 { "未启用锁定".to_string() } else { txt }, pass_if(th > 0 && ok, CheckStatus::Warn), Severity::Medium, "将“账户锁定时间”设置为 15 分钟或以上");
    }
    if let Some(v) = sa_u32("ClearTextPassword") {
        b.add("ACC-07", g, "用可还原的加密来储存密码", "已禁用", if v == 0 { "已禁用" } else { "已启用" }, pass_if(v == 0, CheckStatus::Fail), Severity::High, "禁用“用可还原的加密来储存密码”");
    }
    if let Some(v) = sa_u32("LSAAnonymousNameLookup") {
        b.add("ACC-08", g, "允许匿名 SID/名称转换", "已禁用", if v == 0 { "已禁用" } else { "已启用" }, pass_if(v == 0, CheckStatus::Fail), Severity::Medium, "安全选项中禁用“网络访问: 允许匿名 SID/名称转换”");
    }
    let guest = report.accounts.iter().find(|a| a.rid == 501);
    if let Some(gu) = guest {
        b.add("ACC-09", g, "Guest 来宾账户", "已禁用", if gu.disabled { "已禁用" } else { "已启用" }, pass_if(gu.disabled, CheckStatus::Fail), Severity::High, "执行 net user guest /active:no 禁用来宾账户");
    }
    if let Some(adm) = report.accounts.iter().find(|a| a.rid == 500) {
        let renamed = !adm.name.eq_ignore_ascii_case("Administrator");
        let ok = renamed || adm.disabled;
        b.add("ACC-10", g, "内置管理员账户", "已重命名或已禁用", format!("{}{}", adm.name, if adm.disabled { "（已禁用）" } else { "（启用中）" }), pass_if(ok, CheckStatus::Warn), Severity::Low, "重命名内置 Administrator 账户，降低被定向爆破风险");
    }
    let no_pwd: Vec<&str> = report.accounts.iter().filter(|a| a.pwd_not_required && !a.disabled).map(|a| a.name.as_str()).collect();
    b.add("ACC-11", g, "允许空密码的启用账户", "无", if no_pwd.is_empty() { "无".to_string() } else { no_pwd.join(", ") }, pass_if(no_pwd.is_empty(), CheckStatus::Fail), Severity::High, "为相关账户设置强口令并取消 PASSWD_NOTREQD 标志: net user <用户> /passwordreq:yes");
    let never: Vec<&str> = report.accounts.iter().filter(|a| a.pwd_never_expires && !a.disabled).map(|a| a.name.as_str()).collect();
    b.add("ACC-12", g, "密码永不过期的启用账户", "无", if never.is_empty() { "无".to_string() } else { never.join(", ") }, pass_if(never.is_empty(), CheckStatus::Warn), Severity::Low, "取消“密码永不过期”，或确保此类账户使用高强度口令");
    let admins: Vec<String> = report
        .group_members
        .iter()
        .filter(|m| is_admin_group(&m.group))
        .map(|m| m.member.clone())
        .collect();
    b.add("ACC-13", g, "Administrators 组成员", "≤ 2 个（最小化授权）", format!("{} 个: {}", admins.len(), admins.join(", ")), pass_if(admins.len() <= 2, CheckStatus::Warn), Severity::Medium, "核查管理员组中每个成员的必要性，移除不需要的账户");

    // ============================================================ 审计策略
    let g = "审计策略";
    // (编号, 子类别 GUID, 期望 1=成功 2=失败 3=两者, 名称, 是否核心项)
    let subs: &[(&str, u128, u32, &str, bool)] = &[
        ("AUD-01", 0x0cce9215_69ae_11d9_bed3_505054503030, 3, "审核登录", true),
        ("AUD-02", 0x0cce923f_69ae_11d9_bed3_505054503030, 3, "审核凭据验证", true),
        ("AUD-03", 0x0cce9235_69ae_11d9_bed3_505054503030, 3, "审核用户账户管理", true),
        ("AUD-04", 0x0cce9237_69ae_11d9_bed3_505054503030, 1, "审核安全组管理", true),
        ("AUD-05", 0x0cce922b_69ae_11d9_bed3_505054503030, 1, "审核进程创建", true),
        ("AUD-06", 0x0cce922f_69ae_11d9_bed3_505054503030, 1, "审核策略更改", true),
        ("AUD-07", 0x0cce921b_69ae_11d9_bed3_505054503030, 1, "审核特殊登录", true),
        ("AUD-08", 0x0cce9227_69ae_11d9_bed3_505054503030, 3, "审核其他对象访问（计划任务）", true),
        ("AUD-09", 0x0cce9211_69ae_11d9_bed3_505054503030, 1, "审核安全系统扩展（服务安装）", true),
        ("AUD-10", 0x0cce9217_69ae_11d9_bed3_505054503030, 2, "审核账户锁定", true),
        ("AUD-13", 0x0cce9216_69ae_11d9_bed3_505054503030, 1, "审核注销", false),
        ("AUD-14", 0x0cce921c_69ae_11d9_bed3_505054503030, 3, "审核其他登录/注销事件（RDP 会话）", false),
        ("AUD-15", 0x0cce9228_69ae_11d9_bed3_505054503030, 3, "审核敏感特权使用", false),
        ("AUD-16", 0x0cce9230_69ae_11d9_bed3_505054503030, 1, "审核身份验证策略更改", false),
        ("AUD-17", 0x0cce9231_69ae_11d9_bed3_505054503030, 1, "审核授权策略更改", false),
        ("AUD-18", 0x0cce9210_69ae_11d9_bed3_505054503030, 1, "审核安全状态更改", false),
        ("AUD-19", 0x0cce9212_69ae_11d9_bed3_505054503030, 3, "审核系统完整性", false),
        ("AUD-20", 0x0cce9249_69ae_11d9_bed3_505054503030, 1, "审核组成员身份", false),
        ("AUD-21", 0x0cce923a_69ae_11d9_bed3_505054503030, 1, "审核其他账户管理事件", false),
        ("AUD-22", 0x0cce9245_69ae_11d9_bed3_505054503030, 3, "审核可移动存储", false),
        ("AUD-23", 0x0cce9248_69ae_11d9_bed3_505054503030, 1, "审核 PNP 活动（外接设备）", false),
    ];
    let guids: Vec<GUID> = subs.iter().map(|s| GUID::from_u128(s.1)).collect();
    let audit = audit_policy(&guids);
    for (i, (id, _, want, title, core)) in subs.iter().enumerate() {
        let expected = audit_label(*want);
        match &audit {
            Some(v) => {
                let got = v[i];
                let fail = if *core { CheckStatus::Fail } else { CheckStatus::Warn };
                let sev = if !*core { Severity::Low } else if *want == 3 { Severity::Medium } else { Severity::Low };
                b.add(id, g, title, expected, audit_label(got), pass_if(got & want == *want, fail), sev, &format!("auditpol /set /subcategory:\"{title}\" 开启 {expected} 审核，便于事后溯源"));
            }
            None => b.add(id, g, title, expected, "需管理员权限读取", CheckStatus::Unknown, Severity::Medium, "以管理员身份运行后重新检测"),
        }
    }
    let cmdline = reg_dword("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled").unwrap_or(0);
    b.add("AUD-11", g, "进程创建事件包含命令行", "已启用", if cmdline == 1 { "已启用" } else { "未启用" }, pass_if(cmdline == 1, CheckStatus::Warn), Severity::Medium, "组策略: 管理模板 → 系统 → 审核过程创建 → 启用“在过程创建事件中加入命令行”");
    let sbl = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging").unwrap_or(0);
    b.add("AUD-12", g, "PowerShell 脚本块日志", "已启用", if sbl == 1 { "已启用" } else { "未启用" }, pass_if(sbl == 1, CheckStatus::Warn), Severity::Medium, "组策略: Windows 组件 → Windows PowerShell → 启用“PowerShell 脚本块日志记录”");

    // ============================================================ 日志配置
    let g = "日志配置";
    for (id, ch, min_mb, sev) in [("LOG-01", "Security", 128u64, Severity::Medium), ("LOG-02", "System", 32, Severity::Low), ("LOG-03", "Application", 32, Severity::Low)] {
        let policy_kb = reg_dword("HKLM", &format!(r"SOFTWARE\Policies\Microsoft\Windows\EventLog\{ch}"), "MaxSize").map(|kb| kb as u64 * 1024);
        let size = policy_kb.or_else(|| reg_dword("HKLM", &format!(r"SYSTEM\CurrentControlSet\Services\EventLog\{ch}"), "MaxSize").map(|v| v as u64));
        match size {
            Some(bytes) => {
                let mb = bytes / (1024 * 1024);
                b.add(id, g, &format!("{ch} 日志最大大小"), &format!("≥ {min_mb} MB"), format!("{mb} MB"), pass_if(mb >= min_mb, CheckStatus::Warn), sev, &format!("事件查看器 → {ch} 属性 → 将日志最大大小调整到 {min_mb} MB 以上，保证日志留存 ≥ 180 天"));
            }
            None => b.add(id, g, &format!("{ch} 日志最大大小"), &format!("≥ {min_mb} MB"), "未读取到", CheckStatus::Unknown, sev, ""),
        }
    }

    // ============================================================ 安全选项
    let g = "安全选项";
    let sys_pol = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let lua = reg_dword("HKLM", sys_pol, "EnableLUA").unwrap_or(1);
    b.add("SEC-01", g, "用户账户控制 (UAC)", "已启用", if lua == 1 { "已启用" } else { "已禁用" }, pass_if(lua == 1, CheckStatus::Fail), Severity::High, "将 EnableLUA 设置为 1 并重启");
    let consent = reg_dword("HKLM", sys_pol, "ConsentPromptBehaviorAdmin").unwrap_or(5);
    b.add("SEC-02", g, "UAC 管理员提升提示", "非“不提示直接提升”", match consent { 0 => "不提示直接提升", 1 | 3 => "提示输入凭据", 2 | 4 => "提示同意", _ => "非 Windows 二进制提示同意" }, pass_if(consent != 0, CheckStatus::Fail), Severity::Medium, "将 ConsentPromptBehaviorAdmin 设置为 2 或 5");
    let lsa = r"SYSTEM\CurrentControlSet\Control\Lsa";
    let lm = reg_dword("HKLM", lsa, "LmCompatibilityLevel").unwrap_or(3);
    b.add("SEC-03", g, "LAN Manager 身份验证级别", "≥ 3（仅发送 NTLMv2）", format!("{lm}"), pass_if(lm >= 3, CheckStatus::Fail), Severity::Medium, "建议设置为 5：仅发送 NTLMv2 响应，拒绝 LM 和 NTLM");
    let nolm = reg_dword("HKLM", lsa, "NoLMHash").unwrap_or(1);
    b.add("SEC-04", g, "不存储 LAN Manager 哈希", "已启用", if nolm == 1 { "已启用" } else { "已禁用" }, pass_if(nolm == 1, CheckStatus::Fail), Severity::High, "将 NoLMHash 设置为 1");
    let ras = reg_dword("HKLM", lsa, "RestrictAnonymousSAM").unwrap_or(1);
    b.add("SEC-05", g, "禁止匿名枚举 SAM 账户", "已启用", if ras == 1 { "已启用" } else { "已禁用" }, pass_if(ras == 1, CheckStatus::Fail), Severity::Medium, "将 RestrictAnonymousSAM 设置为 1");
    let ra = reg_dword("HKLM", lsa, "RestrictAnonymous").unwrap_or(0);
    b.add("SEC-06", g, "禁止匿名枚举 SAM 账户和共享", "已启用", if ra >= 1 { "已启用" } else { "已禁用" }, pass_if(ra >= 1, CheckStatus::Warn), Severity::Medium, "将 RestrictAnonymous 设置为 1");
    let wd = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential").unwrap_or(0);
    b.add("SEC-07", g, "WDigest 明文凭据缓存", "已禁用", if wd == 1 { "已启用（内存中存在明文密码）" } else { "已禁用" }, pass_if(wd != 1, CheckStatus::Fail), Severity::High, "将 WDigest\\UseLogonCredential 设置为 0，避免内存中缓存明文凭据");
    let ppl = reg_dword("HKLM", lsa, "RunAsPPL").unwrap_or(0);
    b.add("SEC-08", g, "LSA 保护 (RunAsPPL)", "已启用", if ppl >= 1 { "已启用" } else { "未启用" }, pass_if(ppl >= 1, CheckStatus::Warn), Severity::Medium, "将 Lsa\\RunAsPPL 设置为 1，为 LSA 进程启用受保护进程保护");
    let wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    let auto = reg_str("HKLM", wl, "AutoAdminLogon").unwrap_or_default();
    let def_pwd = reg_str("HKLM", wl, "DefaultPassword").filter(|s| !s.is_empty());
    let auto_on = auto.trim() == "1";
    b.add("SEC-09", g, "自动登录 / 明文登录口令", "未启用", if auto_on { if def_pwd.is_some() { "已启用且注册表存在明文口令" } else { "已启用" } } else { "未启用" }, pass_if(!auto_on && def_pwd.is_none(), CheckStatus::Fail), Severity::High, "将 AutoAdminLogon 设置为 0 并删除 DefaultPassword 值");
    let timeout = reg_dword("HKLM", sys_pol, "InactivityTimeoutSecs");
    b.add("SEC-10", g, "交互式登录空闲锁定", "≤ 900 秒", timeout.map(|t| format!("{t} 秒")).unwrap_or_else(|| "未配置".into()), pass_if(matches!(timeout, Some(t) if t > 0 && t <= 900), CheckStatus::Warn), Severity::Low, "安全选项: 交互式登录: 计算机不活动限制 设置为 900 秒以内");
    let autorun = reg_dword("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun").unwrap_or(0x91);
    b.add("SEC-11", g, "关闭所有驱动器自动播放", "255 (0xFF)", format!("0x{autorun:X}"), pass_if(autorun == 0xFF, CheckStatus::Warn), Severity::Low, "将 NoDriveTypeAutoRun 设置为 0xFF，防范 U 盘病毒");
    let blank = reg_dword("HKLM", lsa, "LimitBlankPasswordUse").unwrap_or(1);
    b.add("SEC-12", g, "空密码账户仅限控制台登录", "已启用", if blank == 1 { "已启用" } else { "已禁用" }, pass_if(blank == 1, CheckStatus::Fail), Severity::High, "将 LimitBlankPasswordUse 设置为 1");
    let smbsig = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature").unwrap_or(0);
    b.add("SEC-13", g, "SMB 服务器强制签名", "已启用", if smbsig == 1 { "已启用" } else { "未启用" }, pass_if(smbsig == 1, CheckStatus::Warn), Severity::Low, "启用 SMB 签名可缓解 NTLM 中继攻击");
    if let Some(r) = rights {
        let dbg = r.get("SeDebugPrivilege").cloned().unwrap_or_default();
        let ok = dbg.split(',').all(|s| s.trim() == "*S-1-5-32-544" || s.trim().is_empty());
        b.add("SEC-14", g, "调试程序权限 (SeDebugPrivilege)", "仅 Administrators", if dbg.is_empty() { "无".to_string() } else { dbg.clone() }, pass_if(ok, CheckStatus::Fail), Severity::Medium, "用户权限分配 → 调试程序 仅保留 Administrators");
        let tcb = r.get("SeTcbPrivilege").cloned().unwrap_or_default();
        b.add("SEC-15", g, "以操作系统方式执行 (SeTcbPrivilege)", "无任何账户", if tcb.is_empty() { "无".to_string() } else { tcb.clone() }, pass_if(tcb.is_empty(), CheckStatus::Fail), Severity::High, "用户权限分配 → 以操作系统方式执行 应为空");
    }
    let last_user = reg_dword("HKLM", sys_pol, "DontDisplayLastUserName").unwrap_or(0);
    b.add("SEC-16", g, "登录界面不显示上次用户名", "已启用", if last_user == 1 { "已启用" } else { "未启用" }, pass_if(last_user == 1, CheckStatus::Warn), Severity::Low, "安全选项: 交互式登录: 不显示最后的用户名");

    // ============================================================ 网络与服务
    let g = "网络与服务";
    let smb1_server = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
    let srv_exists = reg_open("HKLM", r"SYSTEM\CurrentControlSet\Services\srv").is_some();
    let smb1_client = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start");
    let smb1_on = (srv_exists && smb1_server != Some(0)) || matches!(smb1_client, Some(s) if s != 4);
    b.add("NET-01", g, "SMBv1 协议", "已禁用", if smb1_on { "已启用" } else { "已禁用" }, pass_if(!smb1_on, CheckStatus::Fail), Severity::High, "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol，SMBv1 已被微软弃用");
    let ts = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
    let rdp_on = reg_dword("HKLM", ts, "fDenyTSConnections").unwrap_or(1) == 0;
    let rdp_tcp = format!(r"{ts}\WinStations\RDP-Tcp");
    let nla = reg_dword("HKLM", &rdp_tcp, "UserAuthentication").unwrap_or(1);
    let port = reg_dword("HKLM", &rdp_tcp, "PortNumber").unwrap_or(3389);
    b.add("NET-02", g, "远程桌面网络级身份验证 (NLA)", "RDP 关闭或已启用 NLA", if !rdp_on { "RDP 未开启".to_string() } else if nla == 1 { "RDP 已开启，已启用 NLA".to_string() } else { "RDP 已开启，未启用 NLA".to_string() }, pass_if(!rdp_on || nla == 1, CheckStatus::Fail), Severity::High, "系统属性 → 远程 → 勾选“仅允许运行使用网络级别身份验证的远程桌面的计算机连接”");
    b.add("NET-03", g, "远程桌面端口", "RDP 关闭或非默认端口", if rdp_on { format!("{port}") } else { "RDP 未开启".into() }, pass_if(!rdp_on || port != 3389, CheckStatus::Warn), Severity::Low, "修改默认 3389 端口并通过防火墙限制来源 IP");
    let svc_start = |n: &str| reg_dword("HKLM", &format!(r"SYSTEM\CurrentControlSet\Services\{n}"), "Start");
    let rr = svc_start("RemoteRegistry");
    b.add("NET-04", g, "远程注册表服务", "禁用", match rr { Some(4) => "禁用", Some(2) => "自动", Some(3) => "手动", None => "未安装", _ => "其他" }, pass_if(matches!(rr, Some(4) | None | Some(3)), CheckStatus::Fail), Severity::Medium, "sc config RemoteRegistry start= disabled");
    let risky: Vec<&str> = [("TlntSvr", "Telnet"), ("ftpsvc", "FTP"), ("SNMP", "SNMP"), ("SharedAccess", "ICS 网络共享"), ("simptcp", "简单 TCP/IP 服务")]
        .iter()
        .filter(|(n, _)| matches!(svc_start(n), Some(s) if s <= 2) && *n != "SharedAccess")
        .map(|(_, l)| *l)
        .collect();
    b.add("NET-05", g, "高危服务 (Telnet/FTP/SNMP)", "未安装或已禁用", if risky.is_empty() { "无".to_string() } else { risky.join(", ") }, pass_if(risky.is_empty(), CheckStatus::Fail), Severity::Medium, "停止并禁用不必要的明文协议服务");
    let fw = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    let mut fw_off = Vec::new();
    for (k, n) in [("DomainProfile", "域"), ("StandardProfile", "专用"), ("PublicProfile", "公用")] {
        let pol = reg_dword("HKLM", &format!(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\{k}"), "EnableFirewall");
        let v = pol.or_else(|| reg_dword("HKLM", &format!(r"{fw}\{k}"), "EnableFirewall")).unwrap_or(1);
        if v == 0 {
            fw_off.push(n);
        }
    }
    b.add("NET-06", g, "Windows 防火墙", "域/专用/公用 全部启用", if fw_off.is_empty() { "全部启用".to_string() } else { format!("{} 配置文件已关闭", fw_off.join("/")) }, pass_if(fw_off.is_empty(), CheckStatus::Fail), Severity::High, "netsh advfirewall set allprofiles state on");
    let winrm_unenc = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "AllowUnencrypted").unwrap_or(0);
    b.add("NET-07", g, "WinRM 允许未加密通信", "已禁用", if winrm_unenc == 1 { "已允许" } else { "已禁用" }, pass_if(winrm_unenc != 1, CheckStatus::Fail), Severity::Medium, "将 WinRM\\Service\\AllowUnencrypted 设置为 0");
    let llmnr = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
    b.add("NET-08", g, "LLMNR 多播名称解析", "已禁用", if llmnr == Some(0) { "已禁用" } else { "已启用" }, pass_if(llmnr == Some(0), CheckStatus::Warn), Severity::Low, "组策略: DNS 客户端 → 关闭多播名称解析");
    let all_shares = shares();
    let custom: Vec<String> = all_shares
        .iter()
        .filter(|(n, _, _)| {
            let u = n.to_ascii_uppercase();
            !(u == "IPC$" || u == "ADMIN$" || u == "PRINT$" || (u.len() == 2 && u.ends_with('$')))
        })
        .map(|(n, p, _)| format!("{n} ({p})"))
        .collect();
    b.add("NET-09", g, "非默认网络共享", "无", if custom.is_empty() { "无".to_string() } else { custom.join("; ") }, pass_if(custom.is_empty(), CheckStatus::Warn), Severity::Medium, "核查共享必要性与访问权限，删除不需要的共享: net share <名称> /delete");
    let auto_share = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareWks")
        .or_else(|| reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "AutoShareServer"));
    let admin_shares: Vec<&str> = all_shares.iter().filter(|(n, _, _)| n.ends_with('$') && n != "IPC$").map(|(n, _, _)| n.as_str()).collect();
    b.add("NET-10", g, "默认管理共享 (C$/ADMIN$)", "已关闭", if admin_shares.is_empty() { "已关闭".to_string() } else { admin_shares.join(", ") }, pass_if(admin_shares.is_empty() || auto_share == Some(0), CheckStatus::Warn), Severity::Low, "不需要远程管理时，将 AutoShareWks/AutoShareServer 设置为 0");
    let help = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp").unwrap_or(0);
    b.add("NET-11", g, "远程协助", "已禁用", if help == 1 { "已启用" } else { "已禁用" }, pass_if(help != 1, CheckStatus::Warn), Severity::Low, "系统属性 → 远程 → 取消“允许远程协助连接这台计算机”");
    let risky_ports: HashMap<u16, &str> = HashMap::from([(21, "FTP"), (23, "Telnet"), (135, "RPC"), (139, "NetBIOS"), (445, "SMB"), (1433, "MSSQL"), (3306, "MySQL"), (3389, "RDP"), (5985, "WinRM"), (5986, "WinRM"), (6379, "Redis"), (27017, "MongoDB"), (5900, "VNC")]);
    let mut exposed: Vec<String> = report
        .connections
        .iter()
        .filter(|c| c.state == "LISTEN" && (c.local_addr == "0.0.0.0" || c.local_addr == "::"))
        .filter_map(|c| risky_ports.get(&c.local_port).map(|n| format!("{}/{}", c.local_port, n)))
        .collect();
    exposed.sort();
    exposed.dedup();
    b.add("NET-12", g, "对所有地址监听的高危端口", "无或已通过防火墙限制", if exposed.is_empty() { "无".to_string() } else { exposed.join(", ") }, pass_if(exposed.is_empty(), CheckStatus::Warn), Severity::Medium, "关闭不必要的服务端口，或在防火墙中限制访问来源");

    // ============================================================ 系统防护
    let g = "系统防护";
    let rtp = report.host.av_realtime.unwrap_or(true);
    b.add("SYS-01", g, "杀毒软件实时防护", "已启用", if rtp { format!("已启用 ({})", report.host.av_product) } else { "已关闭".into() }, pass_if(rtp, CheckStatus::Fail), Severity::High, "开启 Defender 实时保护或确认第三方杀软正常运行");
    let dis_as = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware").unwrap_or(0);
    let dis_rt = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring").unwrap_or(0);
    b.add("SYS-02", g, "Defender 未被组策略禁用", "未禁用", if dis_as == 1 || dis_rt == 1 { "已被策略禁用" } else { "未禁用" }, pass_if(dis_as != 1 && dis_rt != 1, CheckStatus::Fail), Severity::High, "删除 Policies\\Microsoft\\Windows Defender 下的 DisableAntiSpyware/DisableRealtimeMonitoring");
    let mut excl = Vec::new();
    for (sub, label) in [("Paths", "路径"), ("Extensions", "扩展名"), ("Processes", "进程"), ("IpAddresses", "IP")] {
        for base in [r"SOFTWARE\Microsoft\Windows Defender\Exclusions", r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"] {
            if let Some(k) = reg_open("HKLM", &format!(r"{base}\{sub}")) {
                for (n, _) in reg_values(&k) {
                    excl.push(format!("{label}:{n}"));
                }
            }
        }
    }
    b.add("SYS-03", g, "Defender 排除项", "无（或均为业务必需）", if excl.is_empty() { "无".to_string() } else { excl.join("; ") }, pass_if(excl.is_empty(), CheckStatus::Warn), Severity::Medium, "逐条核实排除项的业务必要性，删除不需要的排除项");
    let tamper = reg_dword("HKLM", r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection");
    if let Some(t) = tamper {
        b.add("SYS-04", g, "Defender 篡改防护", "已启用", if t == 5 { "已启用" } else { "未启用" }, pass_if(t == 5, CheckStatus::Warn), Severity::Medium, "Windows 安全中心 → 病毒和威胁防护设置 → 开启篡改防护");
    }
    let no_au = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate").unwrap_or(0);
    b.add("SYS-05", g, "Windows 自动更新", "未被禁用", if no_au == 1 { "已被策略禁用" } else { "未禁用" }, pass_if(no_au != 1, CheckStatus::Warn), Severity::Medium, "恢复自动更新并及时安装安全补丁");
    let hotfix = run_powershell("$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { $h.HotFixID + '|' + $h.InstalledOn.ToString('yyyy-MM-dd') }");
    match hotfix.as_deref().map(str::trim).filter(|s| s.contains('|')) {
        Some(s) => {
            let (id, date) = s.split_once('|').unwrap_or(("", ""));
            let days = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
                .ok()
                .map(|d| (chrono::Local::now().date_naive() - d).num_days());
            b.add("SYS-06", g, "最近一次补丁安装", "90 天以内", format!("{id} 于 {date}"), pass_if(matches!(days, Some(d) if d <= 90), CheckStatus::Warn), Severity::Medium, "检查 Windows Update，安装最新累积更新");
        }
        None => b.add("SYS-06", g, "最近一次补丁安装", "90 天以内", "未获取到补丁信息", CheckStatus::Unknown, Severity::Medium, ""),
    }
    let psv2 = reg_str("HKLM", r"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine", "PowerShellVersion").unwrap_or_default();
    b.add("SYS-07", g, "PowerShell 2.0 引擎", "已移除", if psv2.starts_with('2') { "已安装（可被降级绕过日志）" } else { "未安装" }, pass_if(!psv2.starts_with('2'), CheckStatus::Warn), Severity::Low, "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root");
    let sb = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
    b.add("SYS-08", g, "UEFI 安全启动", "已启用", match sb { Some(1) => "已启用", Some(_) => "未启用", None => "不支持/未知" }, pass_if(sb == Some(1), CheckStatus::Warn), Severity::Low, "在固件设置中开启 Secure Boot，防范 Bootkit");

    super::baseline_ext::extend(&mut b, report, rights);
    b.0
}

pub fn is_admin_group(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "administrators" || n == "管理员" || n == "administratoren" || n == "administrateurs"
}
