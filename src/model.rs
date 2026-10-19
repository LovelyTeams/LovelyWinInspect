//! 采集结果与研判结果的数据模型。所有类型都可序列化，便于导出 JSON 报告。

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

pub type Time = DateTime<Local>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "信息",
            Severity::Low => "低",
            Severity::Medium => "中",
            Severity::High => "高",
            Severity::Critical => "严重",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Category {
    Process,
    Network,
    Persistence,
    Account,
    EventLog,
    File,
    Baseline,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Process => "进程",
            Category::Network => "网络",
            Category::Persistence => "启动项",
            Category::Account => "账户",
            Category::EventLog => "日志",
            Category::File => "文件",
            Category::Baseline => "基线",
        }
    }
}

/// MITRE ATT&CK 战术阶段，用于入侵链还原。
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    CommandAndControl,
    Impact,
}

impl Tactic {
    pub const ALL: [Tactic; 10] = [
        Tactic::InitialAccess,
        Tactic::Execution,
        Tactic::Persistence,
        Tactic::PrivilegeEscalation,
        Tactic::DefenseEvasion,
        Tactic::CredentialAccess,
        Tactic::Discovery,
        Tactic::LateralMovement,
        Tactic::CommandAndControl,
        Tactic::Impact,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tactic::InitialAccess => "初始访问",
            Tactic::Execution => "执行",
            Tactic::Persistence => "持久化",
            Tactic::PrivilegeEscalation => "权限提升",
            Tactic::DefenseEvasion => "防御规避",
            Tactic::CredentialAccess => "凭据访问",
            Tactic::Discovery => "内网探测",
            Tactic::LateralMovement => "横向移动",
            Tactic::CommandAndControl => "命令控制",
            Tactic::Impact => "破坏影响",
        }
    }

    pub fn attack_id(self) -> &'static str {
        match self {
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::DefenseEvasion => "TA0005",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::CommandAndControl => "TA0011",
            Tactic::Impact => "TA0040",
        }
    }
}

/// 一条研判发现（展示在“调查发现”中）。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub time: Option<Time>,
    pub category: Category,
    pub severity: Severity,
    pub object: String,
    pub title: String,
    pub detail: String,
    pub target: String,
    pub tactic: Option<Tactic>,
    pub technique: String,
    pub advice: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SignState {
    #[default]
    NotChecked,
    Signed,
    Unsigned,
    Missing,
}

impl SignState {
    pub fn label(self) -> &'static str {
        match self {
            SignState::NotChecked => "未校验",
            SignState::Signed => "已签名",
            SignState::Unsigned => "未签名",
            SignState::Missing => "文件缺失",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub build: String,
    pub arch: String,
    pub ip: String,
    pub mac: String,
    pub domain: String,
    pub is_domain: bool,
    pub current_user: String,
    pub is_admin: bool,
    pub boot_time: Option<Time>,
    pub uptime_secs: u64,
    pub install_date: Option<Time>,
    pub timezone: String,
    pub av_product: String,
    pub av_realtime: Option<bool>,
    pub adapters: Vec<AdapterInfo>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub gateways: Vec<String>,
    pub up: bool,
    pub physical: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub parent_name: String,
    pub path: String,
    pub cmdline: String,
    pub user: String,
    pub start_time: Option<Time>,
    pub threads: u32,
    pub memory_kb: u64,
    pub sign: SignState,
    pub net_conns: u32,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnInfo {
    pub proto: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process: String,
    pub path: String,
    pub external: bool,
    /// 远程地址在本机 DNS 缓存中对应的域名
    #[serde(default)]
    pub domain: String,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

/// DNS 客户端缓存记录（仅读取本地缓存，不发起网络查询）。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    pub name: String,
    pub rtype: String,
    pub data: String,
    pub ttl: u32,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

/// ARP / IPv6 邻居表条目。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NeighborEntry {
    pub ip: String,
    pub mac: String,
    pub interface: String,
    pub state: String,
    pub is_static: bool,
    pub is_gateway: bool,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

/// 卷影副本（只读列举）。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShadowCopy {
    pub id: String,
    pub volume: String,
    pub device: String,
    pub created: Option<Time>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PersistKind {
    RunKey,
    Service,
    ScheduledTask,
    StartupFolder,
    Ifeo,
    Winlogon,
    AppInit,
    Lsa,
    Wmi,
    ComHijack,
    BootExecute,
    NetshHelper,
    Accessibility,
    FailureCommand,
    LogonScript,
    PsProfile,
    AppCertDlls,
    KnownDlls,
    Wow64,
    PrintMonitor,
    TimeProvider,
    ActiveSetup,
    FileAssoc,
    ScreenSaver,
    PortProxy,
    FirewallRule,
    RootCert,
}

impl PersistKind {
    pub fn label(self) -> &'static str {
        match self {
            PersistKind::RunKey => "注册表自启动",
            PersistKind::Service => "系统服务",
            PersistKind::ScheduledTask => "计划任务",
            PersistKind::StartupFolder => "启动文件夹",
            PersistKind::Ifeo => "映像劫持(IFEO)",
            PersistKind::Winlogon => "Winlogon",
            PersistKind::AppInit => "AppInit_DLLs",
            PersistKind::Lsa => "LSA 包",
            PersistKind::Wmi => "WMI 事件订阅",
            PersistKind::ComHijack => "COM 劫持",
            PersistKind::BootExecute => "BootExecute",
            PersistKind::NetshHelper => "Netsh Helper",
            PersistKind::Accessibility => "辅助功能后门",
            PersistKind::FailureCommand => "服务故障命令",
            PersistKind::LogonScript => "登录/组策略脚本",
            PersistKind::PsProfile => "PowerShell 配置文件",
            PersistKind::AppCertDlls => "AppCertDlls",
            PersistKind::KnownDlls => "KnownDlls 排除",
            PersistKind::Wow64 => "WOW64 模拟层",
            PersistKind::PrintMonitor => "打印监视器",
            PersistKind::TimeProvider => "时间提供程序",
            PersistKind::ActiveSetup => "Active Setup",
            PersistKind::FileAssoc => "文件关联",
            PersistKind::ScreenSaver => "屏幕保护程序",
            PersistKind::PortProxy => "端口转发",
            PersistKind::FirewallRule => "防火墙放行规则",
            PersistKind::RootCert => "受信任根证书",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistItem {
    pub kind: PersistKind,
    pub name: String,
    pub location: String,
    pub command: String,
    pub image: String,
    pub sign: SignState,
    pub enabled: bool,
    pub extra: String,
    pub time: Option<Time>,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub full_name: String,
    pub comment: String,
    pub rid: u32,
    pub is_admin: bool,
    pub disabled: bool,
    pub locked: bool,
    pub pwd_never_expires: bool,
    pub pwd_not_required: bool,
    pub last_logon: Option<Time>,
    pub num_logons: u32,
    pub bad_pw_count: u32,
    pub pwd_age_days: u32,
    pub groups: Vec<String>,
    pub created: Option<Time>,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GroupMember {
    pub group: String,
    pub member: String,
    pub kind: String,
}

/// 当前会话（终端服务会话 / 入站 SMB 会话）
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SessionInfo {
    pub kind: String,
    pub id: u32,
    pub user: String,
    pub state: String,
    pub station: String,
    pub client: String,
    pub client_ip: String,
    pub logon_time: Option<Time>,
    pub active_secs: u64,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventRecord {
    pub time: Option<Time>,
    pub channel: String,
    pub event_id: u32,
    pub title: String,
    pub user: String,
    pub source_ip: String,
    pub logon_type: String,
    pub process: String,
    pub detail: String,
    pub severity: Severity,
    pub tactic: Option<Tactic>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
    Unknown,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Pass => "符合",
            CheckStatus::Fail => "不符合",
            CheckStatus::Warn => "建议优化",
            CheckStatus::Unknown => "无法检测",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineCheck {
    pub id: String,
    pub group: String,
    pub title: String,
    pub expected: String,
    pub actual: String,
    pub status: CheckStatus,
    pub severity: Severity,
    pub advice: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    RecentFile,
    WebChange,
    Prefetch,
    RecentDoc,
    Hosts,
    PsHistory,
    Bam,
    RunMru,
    RdpOutbound,
    Software,
    Usb,
    AltStream,
}

impl ArtifactKind {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactKind::RecentFile => "新增可执行/脚本",
            ArtifactKind::WebChange => "Web 目录变更",
            ArtifactKind::Prefetch => "Prefetch 执行痕迹",
            ArtifactKind::RecentDoc => "最近访问",
            ArtifactKind::Hosts => "Hosts 记录",
            ArtifactKind::PsHistory => "PowerShell 历史",
            ArtifactKind::Bam => "BAM 执行记录",
            ArtifactKind::RunMru => "运行对话框记录",
            ArtifactKind::RdpOutbound => "RDP 外连记录",
            ArtifactKind::Software => "近期安装软件",
            ArtifactKind::Usb => "USB 设备记录",
            ArtifactKind::AltStream => "备用数据流",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileArtifact {
    pub kind: ArtifactKind,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub created: Option<Time>,
    pub modified: Option<Time>,
    pub sign: SignState,
    pub sha256: String,
    pub note: String,
    /// 下载来源（Zone.Identifier 中的 HostUrl / ReferrerUrl / ZoneId）
    #[serde(default)]
    pub origin: String,
    /// 除主数据流外的备用数据流（名称与大小）
    #[serde(default)]
    pub streams: Vec<String>,
    pub risk: Severity,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub time: Time,
    pub source: String,
    pub title: String,
    pub detail: String,
    pub severity: Severity,
    pub tactic: Option<Tactic>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Stage {
    Host,
    Process,
    Network,
    Persistence,
    Account,
    EventLog,
    File,
    Baseline,
    Analysis,
}

impl Stage {
    pub const ALL: [Stage; 9] = [
        Stage::Host,
        Stage::Process,
        Stage::Network,
        Stage::Persistence,
        Stage::Account,
        Stage::EventLog,
        Stage::File,
        Stage::Baseline,
        Stage::Analysis,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Stage::Host => "主机信息",
            Stage::Process => "进程信息",
            Stage::Network => "网络连接",
            Stage::Persistence => "持久化项",
            Stage::Account => "账户信息",
            Stage::EventLog => "系统日志",
            Stage::File => "文件痕迹",
            Stage::Baseline => "基线核查",
            Stage::Analysis => "研判还原",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StageStatus {
    Pending,
    Running,
    Done,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StageLog {
    pub stage: Stage,
    pub status: StageStatus,
    pub started: Option<Time>,
    pub elapsed_ms: u64,
    pub summary: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: String,
    pub started: Option<Time>,
    pub finished: Option<Time>,
    pub lookback_days: u32,
    pub host: HostInfo,
    pub processes: Vec<ProcessInfo>,
    pub connections: Vec<ConnInfo>,
    #[serde(default)]
    pub dns_cache: Vec<DnsCacheEntry>,
    #[serde(default)]
    pub neighbors: Vec<NeighborEntry>,
    pub persistence: Vec<PersistItem>,
    pub accounts: Vec<Account>,
    pub group_members: Vec<GroupMember>,
    pub sessions: Vec<SessionInfo>,
    pub events: Vec<EventRecord>,
    /// 审计/日志配置缺口：存在时事件类结论可能不完整
    pub log_gaps: Vec<String>,
    pub files: Vec<FileArtifact>,
    /// None 表示无法读取（通常是权限不足）
    #[serde(default)]
    pub shadow_copies: Option<Vec<ShadowCopy>>,
    pub baseline: Vec<BaselineCheck>,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub stages: Vec<StageLog>,
    pub errors: Vec<String>,
}

impl ScanReport {
    pub fn baseline_score(&self) -> Option<u32> {
        let judged: Vec<_> = self
            .baseline
            .iter()
            .filter(|c| c.status != CheckStatus::Unknown)
            .collect();
        if judged.is_empty() {
            return None;
        }
        let pass = judged.iter().filter(|c| c.status == CheckStatus::Pass).count();
        Some(((pass as f64 / judged.len() as f64) * 100.0).round() as u32)
    }

    pub fn count_findings(&self, min: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= min).count()
    }
}
