//! 处置动作：应急响应中对本机执行的少量写操作。
//!
//! 采集部分始终只读；本模块是唯一会修改系统状态的地方。每次动作无论成败都会立即
//! 追加到 `%APPDATA%\LovelyWinInspect\actions.log`，并随证据包一起导出，便于复盘
//! 处置过程。所有破坏性动作在界面上都需要二次确认。

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::collect::util::wide;
use crate::settings::config_dir;

pub fn log_path() -> PathBuf {
    config_dir().join("actions.log")
}

/// 记录一次处置动作。`ok` 为 false 时说明动作失败。
fn record(action: &str, target: &str, ok: bool, detail: &str) {
    let mut line = String::new();
    let _ = writeln!(
        line,
        "{}\t{}\t{}\t{}\t{}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        action,
        target,
        if ok { "成功" } else { "失败" },
        detail.replace(['\r', '\n', '\t'], " ")
    );
    let path = log_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
    if ok {
        log::info!("处置动作 {action} -> {target}: {detail}");
    } else {
        log::warn!("处置动作 {action} -> {target} 失败: {detail}");
    }
}

fn done(action: &str, target: &str, r: Result<String, String>) -> Result<String, String> {
    match &r {
        Ok(msg) => record(action, target, true, msg),
        Err(e) => record(action, target, false, e),
    }
    r
}

// ---------------------------------------------------------------- 进程

/// 结束指定进程。成功返回提示文案。
pub fn kill_process(pid: u32, name: &str) -> Result<String, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    let target = format!("{name} ({pid})");
    if pid <= 4 {
        return done("结束进程", &target, Err("系统进程不可结束".into()));
    }
    let r = unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => {
                let out = match TerminateProcess(h, 1) {
                    Ok(()) => Ok(format!("已结束进程 {target}")),
                    Err(e) => Err(format!("结束失败：{}", e.message())),
                };
                let _ = CloseHandle(h);
                out
            }
            Err(e) => Err(format!("无法打开进程（可能是受保护进程或权限不足）：{}", e.message())),
        }
    };
    done("结束进程", &target, r)
}

// ---------------------------------------------------------------- 文件

/// 去掉文件的隐藏 / 系统属性，使其在资源管理器中正常可见。
pub fn clear_hidden(path: &str) -> Result<String, String> {
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_FLAGS_AND_ATTRIBUTES,
        GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SetFileAttributesW,
    };
    use windows::core::PCWSTR;
    let w = wide(path);
    let r = unsafe {
        let attrs = GetFileAttributesW(PCWSTR(w.as_ptr()));
        if attrs == INVALID_FILE_ATTRIBUTES {
            Err("文件不存在或无法读取属性".to_string())
        } else {
            let hidden = attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0;
            let system = attrs & FILE_ATTRIBUTE_SYSTEM.0 != 0;
            if !hidden && !system {
                Ok("该文件本就没有隐藏/系统属性".to_string())
            } else {
                let cleared = attrs & !FILE_ATTRIBUTE_HIDDEN.0 & !FILE_ATTRIBUTE_SYSTEM.0;
                match SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(cleared)) {
                    Ok(()) => Ok(format!(
                        "已去掉{}属性",
                        match (hidden, system) {
                            (true, true) => "隐藏和系统",
                            (true, false) => "隐藏",
                            _ => "系统",
                        }
                    )),
                    Err(e) => Err(format!("修改属性失败：{}", e.message())),
                }
            }
        }
    };
    done("恢复隐藏文件", path, r)
}

/// 在资源管理器中定位文件（不修改系统，不记录日志）。
pub fn reveal_in_explorer(path: &str) {
    let p = Path::new(path);
    if p.is_file() {
        let _ = std::process::Command::new("explorer.exe").arg(format!("/select,{path}")).spawn();
    } else {
        let dir = if p.is_dir() { p.to_path_buf() } else { p.parent().map(Path::to_path_buf).unwrap_or_default() };
        if dir.as_os_str().is_empty() {
            return;
        }
        let _ = std::process::Command::new("explorer.exe").arg(dir).spawn();
    }
}

// ---------------------------------------------------------------- 注册表

/// 把我们记录的位置（HKLM\... / HKU\<SID>\...）转为注册表编辑器能识别的完整路径。
fn full_reg_path(location: &str) -> Option<String> {
    let loc = location.split(" | ").next()?.trim();
    let (short, rest) = loc.split_once('\\')?;
    let hive = match short.to_ascii_uppercase().as_str() {
        "HKLM" => "HKEY_LOCAL_MACHINE",
        "HKCU" => "HKEY_CURRENT_USER",
        "HKU" => "HKEY_USERS",
        "HKCR" => "HKEY_CLASSES_ROOT",
        _ => return None,
    };
    // 采集时为了显示美观会把中间层级缩写成 "..."，这类路径无法直接定位
    if rest.contains("...") {
        return Some(format!("{hive}"));
    }
    Some(format!("{hive}\\{rest}"))
}

/// 在注册表编辑器中打开指定位置。
pub fn open_regedit(location: &str) -> Result<String, String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    let Some(full) = full_reg_path(location) else {
        return done("定位注册表", location, Err("无法解析注册表路径".into()));
    };
    let applet = r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    // 沿用系统现有的本地化前缀（如“计算机”/"Computer"）
    let prefix = hkcu
        .open_subkey_with_flags(applet, KEY_READ)
        .ok()
        .and_then(|k| k.get_value::<String, _>("LastKey").ok())
        .and_then(|v| v.split('\\').next().map(str::to_string))
        .filter(|p| !p.contains(':') && !p.starts_with("HKEY_"))
        .unwrap_or_else(|| "计算机".to_string());
    let r = (|| -> Result<String, String> {
        let (key, _) = hkcu.create_subkey(applet).map_err(|e| e.to_string())?;
        key.set_value("LastKey", &format!("{prefix}\\{full}")).map_err(|e| e.to_string())?;
        std::process::Command::new("regedit.exe").spawn().map_err(|e| e.to_string())?;
        Ok(format!("已在注册表编辑器中打开 {full}"))
    })();
    done("定位注册表", &full, r)
}

// ---------------------------------------------------------------- 启动项

/// 可被本工具禁用的启动项类型。
pub fn can_disable(kind: crate::model::PersistKind) -> bool {
    use crate::model::PersistKind as K;
    matches!(kind, K::RunKey | K::ScheduledTask | K::Service)
}

/// 禁用启动项。Run 键使用与任务管理器相同的 StartupApproved 机制（可在任务管理器中恢复），
/// 计划任务与服务通过系统自带命令禁用，均不删除任何数据。
pub fn disable_startup(item: &crate::model::PersistItem) -> Result<String, String> {
    use crate::model::PersistKind as K;
    let target = format!("{} [{}]", item.name, item.kind.label());
    let r = match item.kind {
        K::RunKey => disable_run_key(item),
        K::ScheduledTask => {
            let name = item.name.clone();
            run_tool("schtasks.exe", &["/change", "/tn", &name, "/disable"])
                .map(|_| format!("已禁用计划任务 {name}（可用 schtasks /change /tn \"{name}\" /enable 恢复）"))
        }
        K::Service => {
            let name = item.name.clone();
            run_tool("sc.exe", &["config", &name, "start=", "disabled"])
                .map(|_| format!("服务 {name} 已设为禁用启动（当前实例仍在运行，重启后不再自启）"))
        }
        _ => Err("该类型暂不支持一键禁用，请手动处置".into()),
    };
    done("禁用启动项", &target, r)
}

fn run_tool(program: &str, args: &[&str]) -> Result<String, String> {
    run_tool_raw(program, args).map(|out| decode_console(&out).trim().to_string())
}

/// 执行系统命令并返回原始标准输出；失败时附带按控制台代码页解码的错误信息。
fn run_tool_raw(program: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("无法执行 {program}：{e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        let msg = decode_console(&out.stderr);
        let msg = if msg.trim().is_empty() { decode_console(&out.stdout) } else { msg };
        Err(format!("{program} 返回错误：{}", msg.split_whitespace().collect::<Vec<_>>().join(" ")))
    }
}

/// sc / schtasks / netsh 的输出使用控制台 OEM 代码页（中文系统为 GBK），按 UTF-8 解码会乱码。
fn decode_console(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    use windows::Win32::Globalization::{CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar};
    unsafe {
        let n = MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None);
        if n <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut buf = vec![0u16; n as usize];
        let n = MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, Some(&mut buf));
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }
}

// ---------------------------------------------------------------- 服务

/// 服务名只允许常见字符，避免拼进命令行时产生歧义。
fn valid_service_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 256 && !name.contains(['"', '/', '\\', '\r', '\n'])
}

/// 立即停止服务（不修改启动类型）。
pub fn stop_service(name: &str) -> Result<String, String> {
    let r = if !valid_service_name(name) {
        Err("服务名无效".to_string())
    } else {
        run_tool("sc.exe", &["stop", name]).map(|_| format!("已向服务 {name} 发送停止指令（停止可能需要几秒）"))
    };
    done("停止服务", name, r)
}

/// 把被禁用的服务恢复为手动启动（禁用的撤销操作）。
pub fn enable_service(name: &str) -> Result<String, String> {
    let r = if !valid_service_name(name) {
        Err("服务名无效".to_string())
    } else {
        run_tool("sc.exe", &["config", name, "start=", "demand"]).map(|_| format!("服务 {name} 已改为手动启动"))
    };
    done("启用服务", name, r)
}

// ---------------------------------------------------------------- 计划任务

fn valid_task_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 512 && !name.contains(['"', '\r', '\n'])
}

pub fn enable_task(name: &str) -> Result<String, String> {
    let r = if !valid_task_name(name) {
        Err("任务名无效".to_string())
    } else {
        run_tool("schtasks.exe", &["/change", "/tn", name, "/enable"]).map(|_| format!("已启用计划任务 {name}"))
    };
    done("启用计划任务", name, r)
}

/// 删除计划任务。删除前把任务 XML 备份到 %APPDATA%\LovelyWinInspect\backup\tasks，
/// 失败则不删除。返回信息中附带恢复命令。
pub fn delete_task(item: &crate::model::PersistItem) -> Result<String, String> {
    let name = item.name.clone();
    let r = (|| -> Result<String, String> {
        if !valid_task_name(&name) {
            return Err("任务名无效".into());
        }
        let dir = config_dir().join("backup").join("tasks");
        std::fs::create_dir_all(&dir).map_err(|e| format!("无法创建备份目录：{e}"))?;
        let safe: String = name.trim_matches('\\').chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect();
        let backup = dir.join(format!("{}_{}.xml", safe, chrono::Local::now().format("%Y%m%d%H%M%S")));
        // 优先复制 System32\Tasks 下的原始 XML（UTF-16，可直接用 schtasks /create /xml 导入）
        let src = Path::new(&item.location);
        if src.is_file() {
            std::fs::copy(src, &backup).map_err(|e| format!("备份任务 XML 失败：{e}"))?;
        } else {
            let xml = run_tool_raw("schtasks.exe", &["/query", "/tn", &name, "/xml", "ONE"])?;
            if xml.is_empty() {
                return Err("无法导出任务 XML，已取消删除".into());
            }
            std::fs::write(&backup, &xml).map_err(|e| format!("写入备份失败：{e}"))?;
        }
        run_tool("schtasks.exe", &["/delete", "/tn", &name, "/f"])?;
        Ok(format!(
            "已删除计划任务 {name}，XML 已备份到 {}（恢复：schtasks /create /tn \"{name}\" /xml \"{}\"）",
            backup.display(),
            backup.display()
        ))
    })();
    done("删除计划任务", &name, r)
}

// ---------------------------------------------------------------- 防火墙

fn blocked_file() -> PathBuf {
    config_dir().join("blocked_ips.json")
}

/// 本工具添加过封禁规则的 IP（用于在菜单中显示“解除封禁”）。
pub fn blocked_ips() -> std::collections::HashSet<String> {
    std::fs::read(blocked_file()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_blocked(set: &std::collections::HashSet<String>) {
    let mut v: Vec<_> = set.iter().cloned().collect();
    v.sort();
    let _ = std::fs::create_dir_all(config_dir());
    if let Ok(json) = serde_json::to_vec_pretty(&v) {
        let _ = std::fs::write(blocked_file(), json);
    }
}

/// 可封禁的远程地址：合法 IP，且不是回环、未指定或组播地址。
pub fn blockable_ip(ip: &str) -> Option<std::net::IpAddr> {
    let addr: std::net::IpAddr = ip.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()?;
    (!addr.is_loopback() && !addr.is_unspecified() && !addr.is_multicast()).then_some(addr)
}

fn rule_name(ip: &std::net::IpAddr) -> String {
    format!("LovelyWinInspect-Block-{ip}")
}

/// 用 Windows 防火墙双向封禁远程 IP。
pub fn block_ip(ip: &str) -> Result<String, String> {
    let r = (|| -> Result<String, String> {
        let addr = blockable_ip(ip).ok_or("不是可封禁的 IP 地址")?;
        let name = format!("name={}", rule_name(&addr));
        let remote = format!("remoteip={addr}");
        for dir in ["dir=in", "dir=out"] {
            run_tool("netsh.exe", &["advfirewall", "firewall", "add", "rule", &name, dir, "action=block", &remote, "enable=yes"])?;
        }
        let mut set = blocked_ips();
        set.insert(addr.to_string());
        save_blocked(&set);
        Ok(format!("已在 Windows 防火墙中双向封禁 {addr}（规则名 {}）", rule_name(&addr)))
    })();
    done("封禁 IP", ip, r)
}

pub fn unblock_ip(ip: &str) -> Result<String, String> {
    let r = (|| -> Result<String, String> {
        let addr = blockable_ip(ip).ok_or("不是有效的 IP 地址")?;
        let name = format!("name={}", rule_name(&addr));
        let res = run_tool("netsh.exe", &["advfirewall", "firewall", "delete", "rule", &name]);
        let mut set = blocked_ips();
        set.remove(&addr.to_string());
        save_blocked(&set);
        res.map(|_| format!("已删除对 {addr} 的封禁规则"))
    })();
    done("解除封禁 IP", ip, r)
}

// ---------------------------------------------------------------- 隔离区

/// 隔离区中的一个文件。
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original: String,
    pub sha256: String,
    pub size: u64,
    pub attributes: u32,
    pub time: crate::model::Time,
}

/// 隔离文件用 0xA5 逐字节异或保存，避免被误执行或被杀软当作样本清除。
const QKEY: u8 = 0xA5;

pub fn quarantine_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(|p| PathBuf::from(p).join("LovelyWinInspect").join("Quarantine"))
        .unwrap_or_else(|| config_dir().join("quarantine"))
}

fn index_path(dir: &Path) -> PathBuf {
    dir.join("index.json")
}

pub fn quarantine_list() -> Vec<QuarantineEntry> {
    list_in(&quarantine_dir())
}

fn list_in(dir: &Path) -> Vec<QuarantineEntry> {
    std::fs::read(index_path(dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_index(dir: &Path, list: &[QuarantineEntry]) -> Result<(), String> {
    let tmp = dir.join("index.json.tmp");
    let json = serde_json::to_vec_pretty(list).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, json).map_err(|e| format!("写入隔离区索引失败：{e}"))?;
    std::fs::rename(&tmp, index_path(dir)).map_err(|e| format!("写入隔离区索引失败：{e}"))
}

/// 流式异或复制。
fn xor_copy(src: &Path, dst: &Path) -> std::io::Result<u64> {
    use std::io::{Read, Write};
    let mut r = std::fs::File::open(src)?;
    let mut w = std::fs::File::create(dst)?;
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for b in &mut buf[..n] {
            *b ^= QKEY;
        }
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
    w.sync_all()?;
    Ok(total)
}

fn file_attributes(path: &str) -> u32 {
    use windows::Win32::Storage::FileSystem::GetFileAttributesW;
    use windows::core::PCWSTR;
    let w = wide(path);
    unsafe { GetFileAttributesW(PCWSTR(w.as_ptr())) }
}

fn set_attributes(path: &str, attrs: u32) {
    use windows::Win32::Storage::FileSystem::{FILE_FLAGS_AND_ATTRIBUTES, SetFileAttributesW};
    use windows::core::PCWSTR;
    let w = wide(path);
    unsafe {
        let _ = SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attrs));
    }
}

/// 把文件移入隔离区：编码保存、记录原路径与 SHA256，然后删除原文件。原文件删除失败时回滚。
pub fn quarantine_file(path: &str) -> Result<String, String> {
    let r = quarantine_into(&quarantine_dir(), path);
    done("隔离文件", path, r)
}

fn quarantine_into(dir: &Path, path: &str) -> Result<String, String> {
    use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM};
    let src = Path::new(path);
    if !src.is_file() {
        return Err("文件不存在".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("无法创建隔离区目录：{e}"))?;
    let sha = crate::collect::util::sha256_file(src, u64::MAX);
    if sha.is_empty() {
        return Err("无法读取文件（可能被占用或无权限）".into());
    }
    let attrs = file_attributes(path);
    let id = format!("{}_{}", chrono::Local::now().format("%Y%m%d%H%M%S%3f"), &sha[..12]);
    let stored = dir.join(format!("{id}.lwiq"));
    let size = xor_copy(src, &stored).map_err(|e| {
        let _ = std::fs::remove_file(&stored);
        format!("复制到隔离区失败：{e}")
    })?;
    // 去掉只读/隐藏/系统属性后才能删除
    if attrs != u32::MAX {
        set_attributes(path, attrs & !(FILE_ATTRIBUTE_READONLY.0 | FILE_ATTRIBUTE_HIDDEN.0 | FILE_ATTRIBUTE_SYSTEM.0));
    }
    if let Err(e) = std::fs::remove_file(src) {
        let _ = std::fs::remove_file(&stored);
        if attrs != u32::MAX {
            set_attributes(path, attrs);
        }
        return Err(format!("原文件无法删除（可能正被进程使用，请先结束相关进程）：{e}"));
    }
    let mut list = list_in(dir);
    list.push(QuarantineEntry { id: id.clone(), original: path.to_string(), sha256: sha.clone(), size, attributes: attrs, time: chrono::Local::now() });
    save_index(dir, &list)?;
    Ok(format!("已隔离 {path}（SHA256 {sha}），可在“文件管理 → 隔离区”中还原"))
}

/// 从隔离区还原到原位置。原位置已有同名文件时拒绝覆盖。
pub fn restore_quarantine(id: &str) -> Result<String, String> {
    let target = list_in(&quarantine_dir()).into_iter().find(|e| e.id == id).map(|e| e.original).unwrap_or_else(|| id.to_string());
    let r = restore_from(&quarantine_dir(), id);
    done("还原隔离文件", &target, r)
}

fn restore_from(dir: &Path, id: &str) -> Result<String, String> {
    let mut list = list_in(dir);
    let pos = list.iter().position(|e| e.id == id).ok_or("隔离区中没有这条记录")?;
    let entry = list[pos].clone();
    let stored = dir.join(format!("{id}.lwiq"));
    let dst = Path::new(&entry.original);
    if dst.exists() {
        return Err("原位置已存在同名文件，为避免覆盖已取消还原".into());
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("无法创建原目录：{e}"))?;
    }
    xor_copy(&stored, dst).map_err(|e| {
        let _ = std::fs::remove_file(dst);
        format!("还原失败：{e}")
    })?;
    let sha = crate::collect::util::sha256_file(dst, u64::MAX);
    if !sha.eq_ignore_ascii_case(&entry.sha256) {
        let _ = std::fs::remove_file(dst);
        return Err("还原后的文件校验不一致，已撤销还原".into());
    }
    if entry.attributes != u32::MAX {
        set_attributes(&entry.original, entry.attributes);
    }
    let _ = std::fs::remove_file(&stored);
    list.remove(pos);
    save_index(dir, &list)?;
    Ok(format!("已还原到 {}", entry.original))
}

/// 写入 StartupApproved：首字节 bit0 置 1 表示禁用，与任务管理器一致。
fn disable_run_key(item: &crate::model::PersistItem) -> Result<String, String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS};
    let loc = item.location.to_ascii_uppercase();
    let sub = if loc.contains("WOW6432NODE") { "Run32" } else { "Run" };
    const USER_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
    let (root, base) = if loc.starts_with("HKLM") {
        (
            HKEY_LOCAL_MACHINE,
            format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sub}"),
        )
    } else if loc.starts_with("HKU") {
        // 采集记录的是具体用户的 SID，必须写回同一个用户，不能用当前用户代替
        let sid = item
            .location
            .split('\\')
            .nth(1)
            .filter(|s| s.starts_with("S-1-"))
            .ok_or("无法从位置中解析用户 SID")?;
        (HKEY_USERS, format!(r"{sid}\{USER_PATH}\{sub}"))
    } else if loc.starts_with("HKCU") {
        (HKEY_CURRENT_USER, format!(r"{USER_PATH}\{sub}"))
    } else {
        return Err("无法判断该启动项所属配置单元".into());
    };
    let hive = RegKey::predef(root);
    let (key, _) = hive.create_subkey(&base).map_err(|e| format!("无法打开 StartupApproved：{e}"))?;
    // 12 字节：首字节 0x03 = 已禁用，其后 8 字节为禁用时间（留零即可）
    let data = winreg::RegValue { bytes: std::borrow::Cow::Owned(vec![3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), vtype: winreg::enums::REG_BINARY };
    key.set_raw_value(&item.name, &data).map_err(|e| format!("写入失败：{e}"))?;
    Ok(format!("已禁用自启动项 {}（可在任务管理器“启动”选项卡中恢复）", item.name))
}

// ---------------------------------------------------------------- 哈希

pub fn sha256(path: &str) -> Result<String, String> {
    let p = Path::new(path);
    if !p.is_file() {
        return Err("文件不存在".into());
    }
    let h = crate::collect::util::sha256_file(p, 2 << 30);
    if h.is_empty() { Err("计算失败（文件过大或无法读取）".into()) } else { Ok(h) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_path_maps_hives() {
        assert_eq!(full_reg_path(r"HKLM\SOFTWARE\Test").as_deref(), Some(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test"));
        assert_eq!(full_reg_path(r"HKCU\Software\X").as_deref(), Some(r"HKEY_CURRENT_USER\Software\X"));
        // 位置里带有展示用的省略号时只定位到根
        assert_eq!(full_reg_path(r"HKU\S-1-5-21-1\...\Run").as_deref(), Some("HKEY_USERS"));
        assert_eq!(full_reg_path("C:\notregistry"), None);
    }

    #[test]
    fn clear_hidden_removes_attributes() {
        use windows::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, GetFileAttributesW, SetFileAttributesW,
        };
        use windows::core::PCWSTR;

        let path = std::env::temp_dir().join(format!("lwi_hidden_test_{}.txt", std::process::id()));
        std::fs::write(&path, b"test").unwrap();
        let s = path.display().to_string();
        let w = wide(&s);
        unsafe {
            SetFileAttributesW(PCWSTR(w.as_ptr()), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM).unwrap();
            let before = GetFileAttributesW(PCWSTR(w.as_ptr()));
            assert_ne!(before & FILE_ATTRIBUTE_HIDDEN.0, 0, "前置条件：文件应为隐藏");

            assert!(clear_hidden(&s).is_ok());

            let after = GetFileAttributesW(PCWSTR(w.as_ptr()));
            assert_eq!(after & FILE_ATTRIBUTE_HIDDEN.0, 0, "隐藏属性应已去除");
            assert_eq!(after & FILE_ATTRIBUTE_SYSTEM.0, 0, "系统属性应已去除");
        }
        // 重复执行应提示本就没有隐藏属性，而不是报错
        assert!(clear_hidden(&s).unwrap().contains("本就"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kill_refuses_system_pids() {
        assert!(kill_process(4, "System").is_err());
    }

    #[test]
    fn quarantine_round_trip_restores_content_and_attributes() {
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;
        let base = std::env::temp_dir().join(format!("lwi_q_test_{}", std::process::id()));
        let qdir = base.join("q");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("sample.exe");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&file, &data).unwrap();
        let path = file.display().to_string();
        set_attributes(&path, file_attributes(&path) | FILE_ATTRIBUTE_HIDDEN.0);

        quarantine_into(&qdir, &path).unwrap();
        assert!(!file.exists(), "隔离后原文件应被删除");
        let list = list_in(&qdir);
        assert_eq!(list.len(), 1);
        let stored = std::fs::read(qdir.join(format!("{}.lwiq", list[0].id))).unwrap();
        assert_ne!(stored[..64], data[..64], "隔离区中的内容应已编码");

        restore_from(&qdir, &list[0].id).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), data);
        assert_ne!(file_attributes(&path) & FILE_ATTRIBUTE_HIDDEN.0, 0, "应恢复原有隐藏属性");
        assert!(list_in(&qdir).is_empty());

        // 原位置已有文件时拒绝覆盖
        quarantine_into(&qdir, &path).unwrap();
        std::fs::write(&file, b"new").unwrap();
        let id = list_in(&qdir)[0].id.clone();
        assert!(restore_from(&qdir, &id).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        set_attributes(&path, 0x80);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn blockable_ip_rejects_local_and_invalid() {
        assert!(blockable_ip("8.8.8.8").is_some());
        assert!(blockable_ip("[2001:db8::1]").is_some());
        assert!(blockable_ip("127.0.0.1").is_none());
        assert!(blockable_ip("0.0.0.0").is_none());
        assert!(blockable_ip("224.0.0.1").is_none());
        assert!(blockable_ip("1.2.3.4 dir=in").is_none());
        assert!(blockable_ip("").is_none());
    }

    #[test]
    fn service_and_task_names_are_validated() {
        assert!(valid_service_name("Spooler"));
        assert!(!valid_service_name("a\" & calc"));
        assert!(valid_task_name(r"\Microsoft\Windows\Defrag\ScheduledDefrag"));
        assert!(!valid_task_name("x\ny"));
    }

    #[test]
    fn console_output_decodes_utf8_passthrough() {
        assert_eq!(decode_console("成功".as_bytes()), "成功");
        assert_eq!(decode_console(b""), "");
    }
}
