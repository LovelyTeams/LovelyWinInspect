//! 轻量 PE 解析：文件头、节表（含熵值）与导入表，用于文件预览中的快速研判。
//!
//! 只做只读解析，所有偏移都经过边界检查，畸形文件返回 None 或部分结果而不会 panic。

use crate::model::Time;

#[derive(Clone, Debug, Default)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    /// 原始数据的香农熵（0–8），> 7.2 通常意味着加壳或加密
    pub entropy: f64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PeInfo {
    pub machine: &'static str,
    pub is_64: bool,
    pub is_dll: bool,
    pub is_driver: bool,
    pub dotnet: bool,
    pub subsystem: &'static str,
    pub timestamp: Option<Time>,
    pub entry_point: u32,
    pub image_base: u64,
    /// 是否带有 Authenticode 签名数据（不代表签名有效）
    pub has_signature_blob: bool,
    pub sections: Vec<PeSection>,
    /// (DLL, 函数名列表)
    pub imports: Vec<(String, Vec<String>)>,
    /// 导入表之后、位于文件末尾的附加数据大小
    pub overlay: u64,
}

impl PeInfo {
    /// 导入的高风险 API（进程注入、凭据窃取、下载执行等常见于恶意代码）。
    pub fn sensitive_imports(&self) -> Vec<String> {
        const SENSITIVE: &[&str] = &[
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "SetThreadContext",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "GetAsyncKeyState",
            "GetKeyState",
            "MiniDumpWriteDump",
            "LsaEnumerateLogonSessions",
            "SamIConnect",
            "CredEnumerateA",
            "CredEnumerateW",
            "CryptUnprotectData",
            "AdjustTokenPrivileges",
            "ImpersonateLoggedOnUser",
            "DuplicateTokenEx",
            "CreateProcessWithTokenW",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "WinHttpOpen",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "CryptEncrypt",
            "BCryptEncrypt",
        ];
        let mut out: Vec<String> = self
            .imports
            .iter()
            .flat_map(|(_, f)| f.iter())
            .filter(|f| SENSITIVE.contains(&f.as_str()))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn high_entropy_sections(&self) -> Vec<&PeSection> {
        self.sections.iter().filter(|s| s.raw_size >= 1024 && s.entropy > 7.2).collect()
    }
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}

fn cstr_at(d: &[u8], o: usize, max: usize) -> Option<String> {
    let tail = d.get(o..)?;
    let end = tail.iter().take(max).position(|&b| b == 0)?;
    let s = &tail[..end];
    s.iter().all(|&b| (0x20..0x7f).contains(&b)).then(|| String::from_utf8_lossy(s).into_owned())
}

pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "x86",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        0x01c4 => "ARMv7",
        0x0200 => "IA64",
        _ => "未知",
    }
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "原生 (驱动/系统)",
        2 => "图形界面",
        3 => "控制台",
        9 => "Windows CE",
        10..=13 => "EFI",
        16 => "启动应用",
        _ => "其他",
    }
}

/// 解析 PE 文件。`data` 应尽量包含完整文件（导入表可能位于文件后部）。
pub fn parse(data: &[u8]) -> Option<PeInfo> {
    if data.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(data, 0x3C)? as usize;
    if data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let machine = u16_at(data, coff)?;
    let nsec = u16_at(data, coff + 2)? as usize;
    let stamp = u32_at(data, coff + 4)?;
    let opt_size = u16_at(data, coff + 16)? as usize;
    let characteristics = u16_at(data, coff + 18)?;
    let opt = coff + 20;
    let magic = u16_at(data, opt)?;
    let is_64 = match magic {
        0x20b => true,
        0x10b => false,
        _ => return None,
    };
    let entry_point = u32_at(data, opt + 16)?;
    let image_base = if is_64 { u64_at(data, opt + 24)? } else { u32_at(data, opt + 28)? as u64 };
    let subsystem = u16_at(data, opt + 68)?;
    let (ndirs_off, dirs_off) = if is_64 { (opt + 108, opt + 112) } else { (opt + 92, opt + 96) };
    let ndirs = u32_at(data, ndirs_off).unwrap_or(0).min(16) as usize;
    let dir = |i: usize| -> (u32, u32) {
        if i >= ndirs {
            return (0, 0);
        }
        (u32_at(data, dirs_off + i * 8).unwrap_or(0), u32_at(data, dirs_off + i * 8 + 4).unwrap_or(0))
    };

    // 节表
    let sec_off = opt + opt_size;
    let mut sections = Vec::new();
    let mut raw: Vec<(u32, u32, u32, u32)> = Vec::new(); // (va, vsize, raw_ptr, raw_size)
    let mut end_of_sections = 0u64;
    for i in 0..nsec.min(96) {
        let o = sec_off + i * 40;
        let Some(name_bytes) = data.get(o..o + 8) else { break };
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();
        let vsize = u32_at(data, o + 8)?;
        let va = u32_at(data, o + 12)?;
        let raw_size = u32_at(data, o + 16)?;
        let raw_ptr = u32_at(data, o + 20)?;
        let ch = u32_at(data, o + 36)?;
        let start = raw_ptr as usize;
        let stop = start.saturating_add(raw_size as usize).min(data.len());
        let ent = if start < stop { entropy(&data[start..stop]) } else { 0.0 };
        end_of_sections = end_of_sections.max(raw_ptr as u64 + raw_size as u64);
        sections.push(PeSection {
            name,
            virtual_size: vsize,
            raw_size,
            entropy: ent,
            executable: ch & 0x2000_0000 != 0,
            writable: ch & 0x8000_0000 != 0,
        });
        raw.push((va, vsize, raw_ptr, raw_size));
    }
    let rva_to_off = |rva: u32| -> Option<usize> {
        raw.iter().find_map(|&(va, vsize, ptr, rsize)| {
            let span = vsize.max(rsize);
            (rva >= va && rva < va.saturating_add(span)).then(|| (rva - va) as usize + ptr as usize)
        })
    };

    // 导入表
    let mut imports = Vec::new();
    let (imp_rva, _) = dir(1);
    if imp_rva != 0
        && let Some(mut d) = rva_to_off(imp_rva)
    {
        for _ in 0..512 {
            let (Some(oft), Some(name_rva), Some(ft)) = (u32_at(data, d), u32_at(data, d + 12), u32_at(data, d + 16)) else { break };
            if oft == 0 && name_rva == 0 && ft == 0 {
                break;
            }
            let dll = rva_to_off(name_rva).and_then(|o| cstr_at(data, o, 256)).unwrap_or_else(|| "?".into());
            let mut funcs = Vec::new();
            let thunk_rva = if oft != 0 { oft } else { ft };
            if let Some(mut t) = rva_to_off(thunk_rva) {
                for _ in 0..4096 {
                    let (val, ordinal) = if is_64 {
                        let Some(v) = u64_at(data, t) else { break };
                        (v, v & (1 << 63) != 0)
                    } else {
                        let Some(v) = u32_at(data, t) else { break };
                        (v as u64, v & 0x8000_0000 != 0)
                    };
                    if val == 0 {
                        break;
                    }
                    if ordinal {
                        funcs.push(format!("#{}", val & 0xFFFF));
                    } else if let Some(name) = rva_to_off(val as u32).and_then(|o| cstr_at(data, o + 2, 256)) {
                        funcs.push(name);
                    }
                    t += if is_64 { 8 } else { 4 };
                }
            }
            imports.push((dll, funcs));
            d += 20;
        }
    }

    let (sec_dir_off, sec_dir_size) = dir(4);
    let (clr, _) = dir(14);
    // 签名数据位于节之后，计算 overlay 时应排除
    let sig_end = if sec_dir_off != 0 { sec_dir_off as u64 + sec_dir_size as u64 } else { 0 };
    let file_len = data.len() as u64;
    let overlay = if sig_end >= file_len && sec_dir_off as u64 >= end_of_sections {
        (sec_dir_off as u64).saturating_sub(end_of_sections)
    } else {
        file_len.saturating_sub(end_of_sections.max(sig_end))
    };

    Some(PeInfo {
        machine: machine_name(machine),
        is_64,
        is_dll: characteristics & 0x2000 != 0,
        is_driver: subsystem == 1,
        dotnet: clr != 0,
        subsystem: subsystem_name(subsystem),
        timestamp: (stamp != 0).then(|| crate::collect::util::unix_to_local(stamp as i64, 0)).flatten(),
        entry_point,
        image_base,
        has_signature_blob: sec_dir_off != 0 && sec_dir_size != 0,
        sections,
        imports,
        overlay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_own_test_binary() {
        let exe = std::env::current_exe().unwrap();
        let data = std::fs::read(exe).unwrap();
        let pe = parse(&data).expect("测试程序本身应能解析");
        assert_eq!(pe.machine, "x64");
        assert!(pe.is_64);
        assert!(!pe.is_dll);
        assert!(pe.sections.iter().any(|s| s.name == ".text" && s.executable));
        assert!(pe.imports.iter().any(|(dll, f)| dll.eq_ignore_ascii_case("kernel32.dll") && !f.is_empty()));
    }

    #[test]
    fn parses_system_dll_imports() {
        let path = format!("{}\\System32\\kernel32.dll", std::env::var("SystemRoot").unwrap_or("C:\\Windows".into()));
        let data = std::fs::read(path).unwrap();
        let pe = parse(&data).unwrap();
        assert!(pe.is_dll);
        assert!(!pe.imports.is_empty());
    }

    #[test]
    fn rejects_garbage_and_truncated_input() {
        assert!(parse(b"").is_none());
        assert!(parse(b"MZ").is_none());
        let mut fake = vec![0u8; 0x100];
        fake[0] = b'M';
        fake[1] = b'Z';
        fake[0x3C] = 0x80;
        fake[0x80..0x84].copy_from_slice(b"PE\0\0");
        // 可选头被截断：不应 panic
        assert!(parse(&fake).is_none());
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        for cut in [0x40, 0x200, 0x400, 0x1000] {
            let _ = parse(&exe[..cut.min(exe.len())]);
        }
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[0u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }
}
