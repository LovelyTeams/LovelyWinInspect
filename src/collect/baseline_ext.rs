//! 扩展基线项：参考 HardeningKitty / CIS / 微软安全基线及等保 2.0 常见检查脚本补充。
//! 域成员专属项仅在加域主机上检查，服务器专属项仅在 Server 系统上检查。

use std::collections::HashMap;

use super::accounts::password_policy;
use super::baseline::{Builder, pass_if};
use super::util::*;
use crate::model::{CheckStatus, PersistKind, ScanReport, Severity};

const LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
const LMW: &str = r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
const LMS: &str = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
const PSYS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const TSP: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
const RDP_TCP: &str = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

fn on_off(ok: bool, on: &str, off: &str) -> String {
    if ok { on.to_string() } else { off.to_string() }
}

fn opt_num(v: Option<u32>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "未配置".into())
}

/// 策略路径优先，其次原生路径。
fn policy_dword(policy: &str, native: &str, name: &str) -> Option<u32> {
    reg_dword("HKLM", policy, name).or_else(|| reg_dword("HKLM", native, name))
}

fn service_start(name: &str) -> Option<u32> {
    reg_dword("HKLM", &format!(r"SYSTEM\CurrentControlSet\Services\{name}"), "Start")
}

fn service_running(r: &ScanReport, name: &str) -> bool {
    r.persistence
        .iter()
        .any(|p| p.kind == PersistKind::Service && p.name.eq_ignore_ascii_case(name) && p.extra.contains("运行中"))
}

/// 用户权限分配中的 SID 是否都在允许集合内（secedit 格式：*S-1-5-32-544,*S-1-5-32-555）。
fn rights_subset(rights: Option<&HashMap<String, String>>, key: &str, allowed: &[&str]) -> Option<(bool, String)> {
    let r = rights?;
    let v = r.get(key).cloned().unwrap_or_default();
    let ok = v
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .all(|s| allowed.contains(&s));
    Some((ok, if v.is_empty() { "无".into() } else { v }))
}

fn sid_label(v: &str) -> String {
    v.split(',')
        .map(|s| match s.trim() {
            "*S-1-5-32-544" => "Administrators".to_string(),
            "*S-1-5-32-545" => "Users".to_string(),
            "*S-1-5-32-546" => "Guests".to_string(),
            "*S-1-5-32-551" => "Backup Operators".to_string(),
            "*S-1-5-32-555" => "Remote Desktop Users".to_string(),
            "*S-1-5-11" => "Authenticated Users".to_string(),
            "*S-1-1-0" => "Everyone".to_string(),
            "*S-1-5-113" => "本地账户".to_string(),
            other => other.trim_start_matches('*').to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn extend(b: &mut Builder, r: &ScanReport, rights: Option<&HashMap<String, String>>) {
    let is_domain = r.host.is_domain;
    let is_server = reg_str("HKLM", r"SYSTEM\CurrentControlSet\Control\ProductOptions", "ProductType")
        .map(|t| !t.eq_ignore_ascii_case("WinNT"))
        .unwrap_or(false);
    let rdp_on = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections").unwrap_or(1) == 0;

    // ============================================================ 账户策略
    let g = "账户策略";
    if let Some(p) = password_policy() {
        if p.lockout_threshold > 0 {
            b.add("ACC-14", g, "复位账户锁定计数器", "≥ 15 分钟", format!("{} 分钟", p.lockout_window_min), pass_if(p.lockout_window_min >= 15, CheckStatus::Warn), Severity::Low, "账户锁定策略 → 重置账户锁定计数器 设置为 15 分钟或以上");
        }
    }
    if is_domain {
        let laps_new = reg_dword("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "BackupDirectory").unwrap_or(0);
        let laps_old = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft Services\AdmPwd", "AdmPwdEnabled").unwrap_or(0);
        let ok = laps_new >= 1 || laps_old == 1;
        b.add("ACC-15", g, "本地管理员密码管理 (LAPS)", "已启用", on_off(ok, "已启用", "未启用"), pass_if(ok, CheckStatus::Warn), Severity::Medium, "启用 Windows LAPS，为每台主机生成随机且定期轮换的本地管理员密码，阻断横向移动");
    }

    // ============================================================ 审计策略
    let g = "审计策略";
    let force_sub = reg_dword("HKLM", LSA, "SCENoApplyLegacyAuditPolicy").unwrap_or(0);
    b.add("AUD-24", g, "强制使用审核子类别设置", "已启用", on_off(force_sub == 1, "已启用", "未启用"), pass_if(force_sub == 1, CheckStatus::Warn), Severity::Low, "安全选项: 审核: 强制审核策略子类别设置 → 启用，避免旧式类别策略覆盖子类别配置");
    let trans = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting").unwrap_or(0);
    let module = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging").unwrap_or(0);
    b.add("AUD-25", g, "PowerShell 模块日志 / 脚本转录", "均已启用", format!("模块日志:{} 转录:{}", on_off(module == 1, "开", "关"), on_off(trans == 1, "开", "关")), pass_if(module == 1 && trans == 1, CheckStatus::Warn), Severity::Low, "组策略: Windows PowerShell → 启用模块日志记录与 PowerShell 脚本转录，完整留存命令执行记录");

    // ============================================================ 日志配置
    let g = "日志配置";
    let mut overwrite_off = Vec::new();
    for ch in ["Security", "System", "Application"] {
        let ret = reg_str("HKLM", &format!(r"SOFTWARE\Policies\Microsoft\Windows\EventLog\{ch}"), "Retention")
            .or_else(|| reg_str("HKLM", &format!(r"SYSTEM\CurrentControlSet\Services\EventLog\{ch}"), "Retention"));
        // 0 = 按需覆盖；-1/其他 = 不覆盖或按天保留，日志写满后可能停止记录
        if let Some(v) = ret {
            if v.trim() != "0" {
                overwrite_off.push(ch);
            }
        }
    }
    b.add("LOG-04", g, "日志写满时的保留方式", "按需覆盖或自动归档", if overwrite_off.is_empty() { "按需覆盖".to_string() } else { format!("{} 设置为不覆盖/按天保留", overwrite_off.join("/")) }, pass_if(overwrite_off.is_empty(), CheckStatus::Warn), Severity::Low, "设置为按需覆盖并加大日志容量，或启用 AutoBackupLogFiles 自动归档，避免日志写满后停止记录");
    let auto_backup = ["Security", "System"].iter().any(|ch| {
        reg_dword("HKLM", &format!(r"SYSTEM\CurrentControlSet\Services\EventLog\{ch}"), "AutoBackupLogFiles") == Some(1)
            || reg_dword("HKLM", &format!(r"SOFTWARE\Policies\Microsoft\Windows\EventLog\{ch}"), "AutoBackupLogFiles") == Some(1)
    });
    b.add("LOG-05", g, "日志自动归档（留存 ≥ 180 天）", "已启用或已接入日志平台", on_off(auto_backup, "已启用自动归档", "未启用自动归档"), pass_if(auto_backup, CheckStatus::Warn), Severity::Low, "等保要求日志留存不少于 6 个月：启用自动归档或通过 WEF/Syslog 转发到日志平台");

    // ============================================================ 安全选项
    let g = "安全选项";
    let latfp = reg_dword("HKLM", PSYS, "LocalAccountTokenFilterPolicy").unwrap_or(0);
    b.add("SEC-17", g, "远程 UAC 限制本地账户", "LocalAccountTokenFilterPolicy = 0", if latfp == 1 { "已关闭限制 (=1)，本地管理员可远程获得完整令牌".to_string() } else { "已限制".to_string() }, pass_if(latfp != 1, CheckStatus::Fail), Severity::High, "删除或将 LocalAccountTokenFilterPolicy 设为 0，防止本地管理员凭据被用于远程横向登录");
    let rnsa = reg_dword("HKLM", LMS, "RestrictNullSessAccess").unwrap_or(1);
    let null_shares = reg_str("HKLM", LMS, "NullSessionShares").unwrap_or_default();
    let null_pipes = reg_str("HKLM", LMS, "NullSessionPipes").unwrap_or_default();
    let eia = reg_dword("HKLM", LSA, "EveryoneIncludesAnonymous").unwrap_or(0);
    let mut anon = Vec::new();
    if rnsa != 1 {
        anon.push("未限制匿名访问命名管道和共享".to_string());
    }
    if !null_shares.trim().is_empty() {
        anon.push(format!("匿名共享: {null_shares}"));
    }
    if !null_pipes.trim().is_empty() && !is_server {
        anon.push(format!("匿名管道: {null_pipes}"));
    }
    if eia == 1 {
        anon.push("Everyone 权限包含匿名用户".into());
    }
    b.add("SEC-18", g, "匿名访问命名管道与共享", "全部禁止", if anon.is_empty() { "已禁止".to_string() } else { anon.join("；") }, pass_if(anon.is_empty(), CheckStatus::Fail), Severity::High, "RestrictNullSessAccess=1，清空 NullSessionShares/NullSessionPipes，EveryoneIncludesAnonymous=0");
    let uac_items = [
        ("PromptOnSecureDesktop", 1u32, 1u32, "安全桌面提示"),
        ("EnableInstallerDetection", 1, 1, "安装程序检测"),
        ("EnableSecureUIAPaths", 1, 1, "仅提升安全位置的 UIAccess"),
        ("EnableVirtualization", 1, 1, "文件/注册表虚拟化"),
    ];
    let bad: Vec<&str> = uac_items
        .iter()
        .filter(|(n, default, want, _)| reg_dword("HKLM", PSYS, n).unwrap_or(*default) != *want)
        .map(|(_, _, _, l)| *l)
        .collect();
    b.add("SEC-19", g, "UAC 增强项", "全部启用", if bad.is_empty() { "全部启用".to_string() } else { format!("未启用: {}", bad.join(", ")) }, pass_if(bad.is_empty(), CheckStatus::Warn), Severity::Medium, "安全选项 → 用户账户控制 相关项全部启用");
    let msv = format!(r"{LSA}\MSV1_0");
    let cli = reg_dword("HKLM", &msv, "NTLMMinClientSec").unwrap_or(0);
    let srv = reg_dword("HKLM", &msv, "NTLMMinServerSec").unwrap_or(0);
    let want = 537_395_200u32; // 要求 NTLMv2 会话安全 + 128 位加密
    let ok = cli & want == want && srv & want == want;
    b.add("SEC-20", g, "NTLM SSP 最小会话安全", "要求 NTLMv2 + 128 位加密", format!("客户端 0x{cli:X} / 服务端 0x{srv:X}"), pass_if(ok, CheckStatus::Warn), Severity::Medium, "安全选项: 网络安全: 基于 NTLM SSP 的(包括安全 RPC)客户端/服务器的最小会话安全 → 要求 NTLMv2 会话安全和 128 位加密");
    let rrs = reg_str("HKLM", LSA, "RestrictRemoteSAM").unwrap_or_default();
    let force_guest = reg_dword("HKLM", LSA, "ForceGuest").unwrap_or(0);
    b.add("SEC-21", g, "限制远程调用 SAM / 经典共享模型", "已限制且为经典模型", format!("RestrictRemoteSAM: {} / 共享模型: {}", if rrs.is_empty() { "未配置" } else { "已配置" }, if force_guest == 0 { "经典" } else { "仅来宾" }), pass_if(force_guest == 0 && (!rrs.is_empty() || !is_server), CheckStatus::Warn), Severity::Medium, "安全选项: 网络访问: 限制允许远程调用 SAM 的客户端 仅 Administrators；本地账户共享和安全模型 → 经典");
    let ddc = reg_dword("HKLM", LSA, "DisableDomainCreds").unwrap_or(0);
    b.add("SEC-22", g, "不允许存储网络身份验证凭据", "已启用", on_off(ddc == 1, "已启用", "未启用"), pass_if(ddc == 1, CheckStatus::Warn), Severity::Low, "安全选项: 网络访问: 不允许存储网络身份验证的密码和凭据 → 启用");
    let custom_ssp = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCustomSSPsAPs");
    b.add("SEC-23", g, "禁止加载自定义 SSP/AP 到 LSASS", "已禁止", match custom_ssp { Some(0) => "已禁止".into(), Some(_) => "允许".into(), None => "未配置".to_string() }, pass_if(custom_ssp == Some(0), CheckStatus::Warn), Severity::Low, "组策略: 系统 → 本地安全机构 → 允许将自定义 SSP 和 AP 加载到 LSASS → 禁用");
    if is_domain {
        let cached = reg_str("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(10);
        b.add("SEC-24", g, "缓存登录凭据个数", "≤ 4", format!("{cached} 个"), pass_if(cached <= 4, CheckStatus::Warn), Severity::Medium, "安全选项: 交互式登录: 可被缓存的前次登录个数 设置为 4 或更少");
        let nl = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters";
        let ok = [("RequireSignOrSeal", 1u32), ("SealSecureChannel", 1), ("RequireStrongKey", 1)]
            .iter()
            .all(|(n, w)| reg_dword("HKLM", nl, n).unwrap_or(1) == *w);
        b.add("SEC-25", g, "域安全通道签名/加密", "全部启用", on_off(ok, "全部启用", "存在未启用项"), pass_if(ok, CheckStatus::Fail), Severity::Medium, "安全选项: 域成员: 对安全通道数据进行数字加密或签名(始终) 等相关项全部启用");
        let ldap = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\LDAP", "LDAPClientIntegrity").unwrap_or(1);
        b.add("SEC-26", g, "LDAP 客户端签名", "≥ 1 (协商签名)", ldap.to_string(), pass_if(ldap >= 1, CheckStatus::Fail), Severity::Medium, "安全选项: 网络安全: LDAP 客户端签名要求 → 协商签名");
    }
    if let Some((ok, v)) = rights_subset(rights, "SeRemoteInteractiveLogonRight", &["*S-1-5-32-544", "*S-1-5-32-555"]) {
        b.add("SEC-27", g, "允许通过远程桌面登录", "仅 Administrators / Remote Desktop Users", sid_label(&v), pass_if(ok, CheckStatus::Fail), Severity::Medium, "用户权限分配 → 允许通过远程桌面服务登录 仅保留管理员与远程桌面用户组");
    }
    if let Some(rr) = rights {
        let deny_net = rr.get("SeDenyNetworkLogonRight").cloned().unwrap_or_default();
        let ok = deny_net.contains("*S-1-5-32-546") || deny_net.to_ascii_lowercase().contains("guest");
        b.add("SEC-28", g, "拒绝来宾从网络访问", "包含 Guests", if deny_net.is_empty() { "未配置".into() } else { sid_label(&deny_net) }, pass_if(ok, CheckStatus::Warn), Severity::Low, "用户权限分配 → 拒绝从网络访问这台计算机 加入 Guests");
        let admin_like = ["*S-1-5-32-544", "*S-1-5-32-551", "*S-1-5-32-549", "*S-1-5-32-550"];
        let mut over = Vec::new();
        for (key, label) in [
            ("SeLoadDriverPrivilege", "加载驱动"),
            ("SeTakeOwnershipPrivilege", "取得所有权"),
            ("SeBackupPrivilege", "备份文件"),
            ("SeRestorePrivilege", "还原文件"),
            ("SeRemoteShutdownPrivilege", "远程关机"),
        ] {
            if let Some((false, v)) = rights_subset(rights, key, &admin_like) {
                over.push(format!("{label}: {}", sid_label(&v)));
            }
        }
        if rr.get("SeCreateTokenPrivilege").map(|v| !v.trim().is_empty()).unwrap_or(false) {
            over.push("创建令牌对象: 非空".into());
        }
        b.add("SEC-29", g, "高危特权分配", "仅管理员/对应运维组", if over.is_empty() { "符合".to_string() } else { over.join("；") }, pass_if(over.is_empty(), CheckStatus::Fail), Severity::High, "用户权限分配中加载驱动、取得所有权、备份/还原、远程关机 仅授予管理员；创建令牌对象 不授予任何账户");
    }
    let oracle = reg_dword("HKLM", &format!(r"{PSYS}\CredSSP\Parameters"), "AllowEncryptionOracle");
    b.add("SEC-30", g, "CredSSP 加密 Oracle 修正", "强制更新的客户端 (0) 或缓解 (1)", match oracle { Some(2) => "易受攻击 (2)".to_string(), Some(v) => v.to_string(), None => "默认（缓解）".into() }, pass_if(oracle != Some(2), CheckStatus::Fail), Severity::Medium, "组策略: 系统 → 凭据分配 → 加密 Oracle 修正 → 强制更新的客户端");
    let legal = reg_str("HKLM", PSYS, "LegalNoticeText").unwrap_or_default();
    b.add("SEC-31", g, "登录警告横幅", "已配置", on_off(!legal.trim().is_empty(), "已配置", "未配置"), pass_if(!legal.trim().is_empty(), CheckStatus::Warn), Severity::Low, "安全选项: 交互式登录: 试图登录的用户的消息标题/文本 配置合规告知");
    // 屏幕保护（已加载的用户配置）
    let mut ss_bad = Vec::new();
    if let Some(hku) = reg_open("HKU", "") {
        for sid in reg_subkeys(&hku).into_iter().filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes")) {
            let pol = format!(r"{sid}\Software\Policies\Microsoft\Windows\Control Panel\Desktop");
            let nat = format!(r"{sid}\Control Panel\Desktop");
            let get = |n: &str| reg_str("HKU", &pol, n).or_else(|| reg_str("HKU", &nat, n)).unwrap_or_default();
            let active = get("ScreenSaveActive").trim() == "1";
            let secure = get("ScreenSaverIsSecure").trim() == "1";
            let timeout: u32 = get("ScreenSaveTimeOut").trim().parse().unwrap_or(0);
            if !(active && secure && timeout > 0 && timeout <= 600) {
                ss_bad.push(sid.rsplit('-').next().unwrap_or("").to_string());
            }
        }
    }
    let inactivity = reg_dword("HKLM", PSYS, "InactivityTimeoutSecs").map(|t| t > 0 && t <= 900).unwrap_or(false);
    b.add("SEC-32", g, "屏幕保护密码锁定", "启用且 ≤ 600 秒", if ss_bad.is_empty() { "已启用".to_string() } else { format!("{} 个用户未启用 (RID {})", ss_bad.len(), ss_bad.join(",")) }, pass_if(ss_bad.is_empty() || inactivity, CheckStatus::Warn), Severity::Low, "启用带密码保护的屏幕保护程序，等待时间不超过 10 分钟");

    // ============================================================ 网络与服务
    let g = "网络与服务";
    let req = reg_dword("HKLM", LMW, "RequireSecuritySignature").unwrap_or(0);
    b.add("NET-13", g, "SMB 客户端强制签名", "已启用", on_off(req == 1, "已启用", "未启用"), pass_if(req == 1, CheckStatus::Warn), Severity::Medium, "安全选项: Microsoft 网络客户端: 对通信进行数字签名(始终) → 启用");
    let plain = reg_dword("HKLM", LMW, "EnablePlainTextPassword").unwrap_or(0);
    b.add("NET-14", g, "SMB 客户端发送明文密码", "已禁用", on_off(plain == 0, "已禁用", "已启用"), pass_if(plain == 0, CheckStatus::Fail), Severity::High, "安全选项: Microsoft 网络客户端: 将未加密的密码发送到第三方 SMB 服务器 → 禁用");
    let insecure_guest = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth")
        .or_else(|| reg_dword("HKLM", LMW, "AllowInsecureGuestAuth"))
        .unwrap_or(0);
    b.add("NET-15", g, "不安全的来宾登录 (SMB)", "已禁用", on_off(insecure_guest == 0, "已禁用", "已启用"), pass_if(insecure_guest == 0, CheckStatus::Fail), Severity::Medium, "组策略: 网络 → Lanman 工作站 → 启用不安全的来宾登录 → 禁用");
    let spooler = service_start("Spooler");
    let pnp = r"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
    let no_warn = reg_dword("HKLM", pnp, "NoWarningNoElevationOnInstall").unwrap_or(0);
    let restrict_drv = reg_dword("HKLM", pnp, "RestrictDriverInstallationToAdministrators").unwrap_or(1);
    let pn_ok = no_warn == 0 && restrict_drv == 1;
    let spool_ok = !is_server || matches!(spooler, Some(4) | None);
    b.add("NET-16", g, "打印后台处理程序 / 点打印", if is_server { "非打印服务器禁用 Spooler，且仅管理员可安装驱动" } else { "仅管理员可安装打印驱动" }, format!("Spooler 启动类型:{} / 驱动安装限制:{}", opt_num(spooler), on_off(pn_ok, "已限制", "未限制")), pass_if(spool_ok && pn_ok, CheckStatus::Fail), Severity::High, "非打印服务器: sc config Spooler start= disabled；点打印策略: RestrictDriverInstallationToAdministrators=1 且不关闭安装提示");
    let netbios_on: usize = reg_open("HKLM", r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces")
        .map(|k| {
            reg_subkeys(&k)
                .iter()
                .filter(|i| k.open_subkey(i).ok().and_then(|s| key_dword(&s, "NetbiosOptions")).unwrap_or(0) != 2)
                .count()
        })
        .unwrap_or(0);
    let nb_policy = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableNetbios");
    let nb_ok = nb_policy == Some(0) || netbios_on == 0;
    let mdns = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "EnableMDNS").unwrap_or(1);
    b.add("NET-17", g, "NetBIOS / mDNS 名称解析", "均已禁用", format!("NetBIOS:{} mDNS:{}", if nb_ok { "已禁用".to_string() } else { format!("{netbios_on} 个接口启用") }, on_off(mdns == 0, "已禁用", "已启用")), pass_if(nb_ok && mdns == 0, CheckStatus::Warn), Severity::Low, "网卡 TCP/IPv4 高级设置中禁用 NetBIOS over TCP/IP；Dnscache\\Parameters\\EnableMDNS=0，减少名称解析投毒面");
    let webclient = service_start("WebClient");
    b.add("NET-18", g, "WebClient (WebDAV) 服务", "禁用或未安装", match webclient { Some(4) => "禁用".into(), None => "未安装".into(), Some(s) => format!("启动类型 {s}") }, pass_if(matches!(webclient, Some(4) | None), CheckStatus::Warn), Severity::Low, "sc config WebClient start= disabled，避免 WebDAV 被用于凭据中继");
    if rdp_on {
        let enc = policy_dword(TSP, RDP_TCP, "MinEncryptionLevel").unwrap_or(2);
        let layer = policy_dword(TSP, RDP_TCP, "SecurityLayer").unwrap_or(2);
        let ok = enc >= 3 && layer == 2;
        b.add("NET-19", g, "远程桌面加密级别", "高级加密 (3) 且使用 TLS", format!("加密级别 {enc} / 安全层 {layer}"), pass_if(ok, CheckStatus::Warn), Severity::Medium, "组策略: 远程桌面会话主机 → 安全 → 设置客户端连接加密级别=高级别，要求使用 SSL 安全层");
        let idle = reg_dword("HKLM", TSP, "MaxIdleTime");
        let disc = reg_dword("HKLM", TSP, "MaxDisconnectionTime");
        let ok = matches!(idle, Some(t) if t > 0 && t <= 900_000) && matches!(disc, Some(t) if t > 0 && t <= 60_000);
        b.add("NET-20", g, "远程桌面会话超时", "空闲 ≤ 15 分钟、断开 ≤ 1 分钟后结束", format!("空闲:{} 断开:{}", idle.map(|t| format!("{} 分钟", t / 60000)).unwrap_or("未限制".into()), disc.map(|t| format!("{} 秒", t / 1000)).unwrap_or("未限制".into())), pass_if(ok, CheckStatus::Warn), Severity::Low, "组策略: 远程桌面会话主机 → 会话时间限制，满足等保“超时自动退出”要求");
    }
    let winrm = r"SOFTWARE\Policies\Microsoft\Windows\WinRM";
    let basic: Vec<&str> = [("Service", "服务端"), ("Client", "客户端")]
        .iter()
        .filter(|(k, _)| reg_dword("HKLM", &format!(r"{winrm}\{k}"), "AllowBasic") == Some(1))
        .map(|(_, l)| *l)
        .collect();
    b.add("NET-21", g, "WinRM 基本身份验证", "已禁用", if basic.is_empty() { "已禁用".to_string() } else { format!("{} 允许 Basic 认证", basic.join("/")) }, pass_if(basic.is_empty(), CheckStatus::Fail), Severity::Medium, "组策略: Windows 远程管理 → 允许基本身份验证 → 禁用");
    let autodisc = reg_dword("HKLM", LMS, "AutoDisconnect").unwrap_or(15);
    b.add("NET-22", g, "SMB 空闲会话断开", "≤ 15 分钟", format!("{autodisc} 分钟"), pass_if(autodisc <= 15, CheckStatus::Warn), Severity::Low, "安全选项: Microsoft 网络服务器: 暂停会话前所需的空闲时间 ≤ 15 分钟");
    let tcp = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
    let src_route = reg_dword("HKLM", tcp, "DisableIPSourceRouting");
    let icmp_redirect = reg_dword("HKLM", tcp, "EnableICMPRedirect").unwrap_or(1);
    let ok = src_route == Some(2) && icmp_redirect == 0;
    b.add("NET-23", g, "TCP/IP 协议栈加固", "禁用源路由 (2) 与 ICMP 重定向 (0)", format!("源路由:{} ICMP 重定向:{}", opt_num(src_route), icmp_redirect), pass_if(ok, CheckStatus::Warn), Severity::Low, "Tcpip\\Parameters: DisableIPSourceRouting=2, EnableICMPRedirect=0");

    // ============================================================ 系统防护
    let g = "系统防护";
    let aie_lm = reg_dword("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated").unwrap_or(0);
    let mut aie_users = Vec::new();
    if let Some(hku) = reg_open("HKU", "") {
        for sid in reg_subkeys(&hku).into_iter().filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes")) {
            if reg_dword("HKU", &format!(r"{sid}\Software\Policies\Microsoft\Windows\Installer"), "AlwaysInstallElevated") == Some(1) {
                aie_users.push(sid);
            }
        }
    }
    let aie = aie_lm == 1 || !aie_users.is_empty();
    b.add("SYS-09", g, "始终以提升权限安装 MSI", "已禁用", if aie { format!("已启用（计算机:{} 用户:{}）", aie_lm, aie_users.len()) } else { "已禁用".into() }, pass_if(!aie, CheckStatus::Fail), Severity::High, "删除 HKLM/HKCU 下 Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated，否则普通用户可通过 MSI 获得 SYSTEM 权限");
    let w32 = reg_str("HKLM", r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "Type").unwrap_or_default();
    let ntp_on = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient", "Enabled").unwrap_or(0) == 1;
    let time_ok = !w32.eq_ignore_ascii_case("NoSync") && ntp_on && (service_running(r, "W32Time") || service_start("W32Time") != Some(4));
    b.add("SYS-10", g, "系统时间同步", "已启用 NTP 同步", format!("同步类型:{} NTP 客户端:{}", if w32.is_empty() { "-" } else { &w32 }, on_off(ntp_on, "启用", "禁用")), pass_if(time_ok, CheckStatus::Warn), Severity::Low, "启用 Windows Time 服务并配置可信 NTP 源，保证日志时间可用于溯源");
    let sehop = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation").unwrap_or(0);
    let safedll = reg_dword("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager", "SafeDllSearchMode").unwrap_or(1);
    let padding = reg_dword("HKLM", r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config", "EnableCertPaddingCheck").unwrap_or(0);
    let mut miss = Vec::new();
    if sehop != 0 {
        miss.push("SEHOP 已关闭");
    }
    if safedll != 1 {
        miss.push("DLL 安全搜索模式已关闭");
    }
    if padding != 1 {
        miss.push("签名填充校验未启用");
    }
    b.add("SYS-11", g, "漏洞缓解杂项", "SEHOP / 安全 DLL 搜索 / 签名填充校验", if miss.is_empty() { "全部启用".to_string() } else { miss.join("；") }, pass_if(miss.is_empty(), CheckStatus::Warn), Severity::Low, "保持 SEHOP 与 SafeDllSearchMode 开启，设置 Wintrust\\Config\\EnableCertPaddingCheck=1（含 Wow6432Node）");

    // VBS / Credential Guard、BitLocker、ASR —— 通过 CIM 查询
    let ps = r#"
$o = @{}
try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; $o.vbs = [int]$dg.VirtualizationBasedSecurityStatus; $o.svc = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ }) } catch {}
try { $v = Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'"; if ($v) { $o.bl = [int]$v.ProtectionStatus } else { $o.bl = -1 } } catch { $o.bl = -2 }
try { $s = Get-MpComputerStatus; $o.mode = [string]$s.AMRunningMode } catch {}
try { $p = Get-MpPreference; $o.asr = @($p.AttackSurfaceReductionRules_Ids); $o.asra = @($p.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ }); $o.np = [int]$p.EnableNetworkProtection } catch {}
$o | ConvertTo-Json -Compress
"#;
    let v: serde_json::Value = run_powershell(ps)
        .and_then(|s| serde_json::from_str(s.trim()).ok())
        .unwrap_or(serde_json::Value::Null);
    let arr_i = |k: &str| -> Vec<i64> {
        match v.get(k) {
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_i64()).collect(),
            Some(x) => x.as_i64().into_iter().collect(),
            None => vec![],
        }
    };
    if let Some(vbs) = v.get("vbs").and_then(|x| x.as_i64()) {
        let svc = arr_i("svc");
        let cg = svc.contains(&1);
        let hvci = svc.contains(&2);
        b.add("SYS-12", g, "基于虚拟化的安全 / Credential Guard", "VBS 运行且启用凭据保护", format!("VBS:{} 凭据保护:{} HVCI:{}", match vbs { 2 => "运行中", 1 => "已配置未运行", _ => "未启用" }, on_off(cg, "开", "关"), on_off(hvci, "开", "关")), pass_if(vbs == 2 && cg, CheckStatus::Warn), if is_server { Severity::Medium } else { Severity::High }, "在支持的硬件上启用 VBS、Credential Guard 与内存完整性 (HVCI)，防止凭据被从 LSASS 内存窃取");
    }
    match v.get("bl").and_then(|x| x.as_i64()) {
        Some(1) => b.add("SYS-13", g, "系统盘 BitLocker 加密", "已开启保护", "已开启保护", CheckStatus::Pass, Severity::Medium, ""),
        Some(0) => b.add("SYS-13", g, "系统盘 BitLocker 加密", "已开启保护", "未加密或保护已暂停", CheckStatus::Warn, if is_server { Severity::Low } else { Severity::Medium }, "对系统盘启用 BitLocker（建议 XTS-AES），防止设备丢失导致数据与凭据泄露"),
        _ => {}
    }
    let defender_primary = v.get("mode").and_then(|m| m.as_str()).map(|m| m.eq_ignore_ascii_case("Normal")).unwrap_or(false);
    if defender_primary {
        let ids: Vec<String> = match v.get("asr") {
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase())).collect(),
            _ => vec![],
        };
        let acts = arr_i("asra");
        let enabled = |id: &str| ids.iter().position(|x| x == id).and_then(|i| acts.get(i)).map(|a| *a == 1).unwrap_or(false);
        let key_rules = [
            ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "阻止从 LSASS 窃取凭据"),
            ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "阻止 Office 创建子进程"),
            ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "阻止邮件中的可执行内容"),
            ("56a863a9-875e-4185-98a7-b882c64b5ce5", "阻止滥用易受攻击的驱动"),
            ("d1e49aac-8f56-4280-b9ba-993a6d77406c", "阻止源自 PsExec/WMI 的进程创建"),
        ];
        let off: Vec<&str> = key_rules.iter().filter(|(id, _)| !enabled(id)).map(|(_, l)| *l).collect();
        b.add("SYS-14", g, "Defender 攻击面减少 (ASR) 规则", "关键规则设为阻止", if off.is_empty() { "全部启用".to_string() } else { format!("{} 条未阻止: {}", off.len(), off.join(", ")) }, pass_if(off.is_empty(), CheckStatus::Warn), Severity::Medium, "通过组策略/Intune 将关键 ASR 规则设置为“阻止”模式");
        let np = v.get("np").and_then(|x| x.as_i64()).unwrap_or(0);
        b.add("SYS-15", g, "Defender 网络保护", "已启用 (阻止)", on_off(np == 1, "已启用", "未启用"), pass_if(np == 1, CheckStatus::Warn), Severity::Low, "Set-MpPreference -EnableNetworkProtection Enabled");
    }
    match &r.shadow_copies {
        Some(list) => {
            let actual = match list.iter().filter_map(|s| s.created).max() {
                Some(t) => format!("{} 个，最近一次 {}", list.len(), t.format("%Y-%m-%d %H:%M")),
                None if list.is_empty() => "无卷影副本".to_string(),
                None => format!("{} 个", list.len()),
            };
            b.add("SYS-16", g, "卷影副本 / 系统还原点", "至少保留 1 个", actual, pass_if(!list.is_empty(), CheckStatus::Warn), Severity::Low, "为系统盘开启系统保护或配置定期备份；若此前存在卷影副本而现在为空，需结合日志确认是否被人为清除");
        }
        None => b.add("SYS-16", g, "卷影副本 / 系统还原点", "至少保留 1 个", "需管理员权限读取", CheckStatus::Unknown, Severity::Low, "以管理员身份运行后重新检测"),
    }
}
