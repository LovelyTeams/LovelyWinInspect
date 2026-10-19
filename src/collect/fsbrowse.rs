//! 文件管理：目录浏览、递归搜索、内容预览与进程模块枚举。全部只读。

use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::util::{filetime_ticks_to_local, is_suspicious_dir, is_system_dir};
use crate::model::{SignState, Time};

pub const ATTR_READONLY: u32 = 0x1;
pub const ATTR_HIDDEN: u32 = 0x2;
pub const ATTR_SYSTEM: u32 = 0x4;
pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_ARCHIVE: u32 = 0x20;
pub const ATTR_REPARSE: u32 = 0x400;

#[derive(Clone, Debug, Default)]
pub struct FsEntry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub created: Option<Time>,
    pub modified: Option<Time>,
    pub accessed: Option<Time>,
    pub attrs: u32,
    /// 盘符条目的说明（如“本地磁盘”）
    pub note: String,
}

impl FsEntry {
    fn from_meta(path: &Path, meta: &std::fs::Metadata) -> FsEntry {
        let attrs = meta.file_attributes();
        FsEntry {
            path: path.display().to_string(),
            name: path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string()),
            is_dir: attrs & ATTR_DIRECTORY != 0,
            size: if attrs & ATTR_DIRECTORY != 0 { 0 } else { meta.file_size() },
            created: filetime_ticks_to_local(meta.creation_time()),
            modified: filetime_ticks_to_local(meta.last_write_time()),
            accessed: filetime_ticks_to_local(meta.last_access_time()),
            attrs,
            note: String::new(),
        }
    }

    pub fn ext(&self) -> String {
        if self.is_dir {
            return String::new();
        }
        Path::new(&self.name).extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
    }

    pub fn hidden(&self) -> bool {
        self.attrs & (ATTR_HIDDEN | ATTR_SYSTEM) != 0
    }

    pub fn parent(&self) -> String {
        Path::new(&self.path).parent().map(|p| p.display().to_string()).unwrap_or_default()
    }

    /// “HSRA” 风格的属性串。
    pub fn attr_text(&self) -> String {
        attr_text(self.attrs)
    }

    /// 研判提示：可疑目录中的可执行文件、双扩展名、隐藏属性等。
    pub fn hints(&self, recent: Option<Time>) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.is_dir {
            if self.hidden() && !is_system_dir(&self.path) {
                v.push("隐藏目录");
            }
            return v;
        }
        let ext = self.ext();
        let exec = EXEC_EXTS.contains(&ext.as_str());
        let script = SCRIPT_EXTS.contains(&ext.as_str());
        if (exec || script) && is_suspicious_dir(&self.path) {
            v.push("可疑目录中的可执行文件/脚本");
        }
        if double_extension(&self.name) {
            v.push("双扩展名伪装");
        }
        if self.hidden() && !is_system_dir(&self.path) && (exec || script) {
            v.push("隐藏的可执行文件");
        }
        if WEB_EXTS.contains(&ext.as_str()) && self.path.to_ascii_lowercase().contains("wwwroot") && recent.is_some_and(|r| self.modified.is_some_and(|m| m >= r)) {
            v.push("Web 目录中近期修改的脚本");
        }
        if (exec || script) && recent.is_some_and(|r| self.created.is_some_and(|c| c >= r)) && !is_system_dir(&self.path) {
            v.push("近期新建的可执行文件");
        }
        v
    }
}

pub fn attr_text(attrs: u32) -> String {
    let mut s = String::new();
    for (bit, c) in [(ATTR_HIDDEN, 'H'), (ATTR_SYSTEM, 'S'), (ATTR_READONLY, 'R'), (ATTR_ARCHIVE, 'A'), (ATTR_REPARSE, 'L')] {
        if attrs & bit != 0 {
            s.push(c);
        }
    }
    s
}

pub fn attr_label(attrs: u32) -> String {
    let mut v = Vec::new();
    for (bit, l) in [(ATTR_HIDDEN, "隐藏"), (ATTR_SYSTEM, "系统"), (ATTR_READONLY, "只读"), (ATTR_ARCHIVE, "存档"), (ATTR_REPARSE, "重解析点/链接")] {
        if attrs & bit != 0 {
            v.push(l);
        }
    }
    if v.is_empty() { "-".into() } else { v.join("、") }
}

pub const EXEC_EXTS: &[&str] = &["exe", "dll", "sys", "scr", "com", "cpl", "ocx", "msi", "pif", "drv"];
pub const SCRIPT_EXTS: &[&str] = &["ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk"];
pub const WEB_EXTS: &[&str] = &["asp", "aspx", "ashx", "asmx", "php", "jsp", "jspx", "cer", "asa", "cshtml"];
pub const DOC_EXTS: &[&str] = &["doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pdf", "rtf", "txt", "csv"];
pub const ARCHIVE_EXTS: &[&str] = &["zip", "rar", "7z", "tar", "gz", "cab", "iso", "img"];

/// 形如 invoice.pdf.exe：倒数第二段是常见文档扩展名、最后一段是可执行扩展名。
pub fn double_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let parts: Vec<&str> = lower.rsplitn(3, '.').collect();
    parts.len() == 3
        && (EXEC_EXTS.contains(&parts[0]) || SCRIPT_EXTS.contains(&parts[0]))
        && (DOC_EXTS.contains(&parts[1]) || ["jpg", "png", "gif", "mp4", "html", "zip", "rar"].contains(&parts[1]))
}

/// 列出目录内容，目录在前，按名称排序。
pub fn list_dir(dir: &Path, show_hidden: bool) -> Result<Vec<FsEntry>, String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("无法读取目录：{e}"))?;
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let Ok(meta) = ent.metadata() else { continue };
        let e = FsEntry::from_meta(&ent.path(), &meta);
        if !show_hidden && e.hidden() {
            continue;
        }
        out.push(e);
    }
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(out)
}

/// 只列子目录（目录树用）。
pub fn sub_dirs(dir: &Path, show_hidden: bool) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            let a = m.file_attributes();
            (a & ATTR_DIRECTORY != 0 && a & ATTR_REPARSE == 0 && (show_hidden || a & (ATTR_HIDDEN | ATTR_SYSTEM) == 0)).then(|| e.path())
        })
        .take(5000)
        .collect();
    v.sort_by_key(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default());
    v
}

/// 本机盘符。
pub fn drives() -> Vec<FsEntry> {
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    use windows::core::PCWSTR;
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| {
            let root = format!("{}:\\", (b'A' + i) as char);
            let w = super::util::wide(&root);
            let kind = match unsafe { GetDriveTypeW(PCWSTR(w.as_ptr())) } {
                2 => "可移动磁盘",
                3 => "本地磁盘",
                4 => "网络驱动器",
                5 => "光驱",
                6 => "内存盘",
                _ => "驱动器",
            };
            FsEntry { path: root.clone(), name: root, is_dir: true, note: kind.into(), ..Default::default() }
        })
        .collect()
}

/// 应急排查常看的位置（只返回存在的目录）。
pub fn quick_locations() -> Vec<(&'static str, PathBuf)> {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let sys = PathBuf::from(super::util::system_root());
    let mut v: Vec<(&'static str, Option<PathBuf>)> = vec![
        ("桌面", env("USERPROFILE").map(|p| p.join("Desktop"))),
        ("下载", env("USERPROFILE").map(|p| p.join("Downloads"))),
        ("用户临时目录", env("TEMP")),
        ("系统临时目录", Some(sys.join("Temp"))),
        ("ProgramData", env("ProgramData")),
        ("公共用户", env("PUBLIC")),
        ("启动目录（当前用户）", env("APPDATA").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs\Startup"))),
        ("启动目录（所有用户）", env("ProgramData").map(|p| p.join(r"Microsoft\Windows\Start Menu\Programs\StartUp"))),
        ("计划任务 XML", Some(sys.join(r"System32\Tasks"))),
        ("hosts 所在目录", Some(sys.join(r"System32\drivers\etc"))),
    ];
    let www = PathBuf::from(format!("{}\\inetpub\\wwwroot", super::util::system_drive()));
    v.push(("IIS 网站目录", Some(www)));
    v.into_iter().filter_map(|(l, p)| p.filter(|p| p.is_dir()).map(|p| (l, p))).collect()
}

/// 搜索条件。
#[derive(Clone, Debug, Default)]
pub struct SearchCriteria {
    /// 文件名关键字（小写），支持 * 与 ? 通配；为空表示不限
    pub name: String,
    /// 扩展名白名单（小写，不含点）；为空表示不限
    pub exts: Vec<&'static str>,
    /// 修改或创建时间晚于此时间
    pub since: Option<Time>,
    /// 最小文件大小
    pub min_size: Option<u64>,
    pub include_dirs: bool,
}

impl SearchCriteria {
    pub fn matches(&self, e: &FsEntry) -> bool {
        if e.is_dir && !self.include_dirs {
            return false;
        }
        if !self.name.is_empty() && !name_matches(&e.name.to_lowercase(), &self.name) {
            return false;
        }
        if !self.exts.is_empty() && (e.is_dir || !self.exts.contains(&e.ext().as_str())) {
            return false;
        }
        if let Some(since) = self.since {
            let newest = e.modified.max(e.created);
            if newest.is_none_or(|t| t < since) {
                return false;
            }
        }
        if let Some(min) = self.min_size
            && (e.is_dir || e.size < min)
        {
            return false;
        }
        true
    }
}

/// 名称匹配：含通配符时整体匹配，否则按子串匹配。
pub fn name_matches(name: &str, pattern: &str) -> bool {
    if pattern.contains(['*', '?']) { wildcard(name.as_bytes(), pattern.as_bytes()) } else { name.contains(pattern) }
}

fn wildcard(s: &[u8], p: &[u8]) -> bool {
    let (mut si, mut pi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// 搜索进度，供界面轮询。
#[derive(Default)]
pub struct SearchProgress {
    pub scanned: AtomicUsize,
    pub cancel: AtomicBool,
    pub results: std::sync::Mutex<Vec<FsEntry>>,
}

pub const MAX_RESULTS: usize = 5000;

/// 递归搜索（不跟随重解析点，避免目录联接造成死循环）。结果超过 MAX_RESULTS 时停止。
pub fn search(root: &Path, c: &SearchCriteria, progress: &Arc<SearchProgress>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if progress.cancel.load(Ordering::Relaxed) {
            return;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut found = Vec::new();
        for ent in rd.flatten() {
            let Ok(meta) = ent.metadata() else { continue };
            let e = FsEntry::from_meta(&ent.path(), &meta);
            progress.scanned.fetch_add(1, Ordering::Relaxed);
            if e.is_dir && e.attrs & ATTR_REPARSE == 0 {
                stack.push(ent.path());
            }
            if c.matches(&e) {
                found.push(e);
            }
        }
        if !found.is_empty()
            && let Ok(mut r) = progress.results.lock()
        {
            r.extend(found);
            if r.len() >= MAX_RESULTS {
                r.truncate(MAX_RESULTS);
                progress.cancel.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------- 预览

#[derive(Clone, Debug, Default)]
pub struct Preview {
    pub size: u64,
    pub sha256: String,
    pub sign: SignState,
    /// 文本内容（判定为文本时）
    pub text: Option<String>,
    /// 文件开头若干字节（十六进制视图）
    pub head: Vec<u8>,
    pub pe: Option<super::pe::PeInfo>,
    pub streams: Vec<String>,
    pub error: Option<String>,
}

const TEXT_LIMIT: usize = 64 * 1024;
const HEX_LIMIT: usize = 4096;
const PE_LIMIT: u64 = 64 << 20;

/// 判断是否像文本：UTF-16 BOM，或前 4KB 中几乎没有控制字符。
fn looks_text(b: &[u8]) -> bool {
    if b.starts_with(&[0xFF, 0xFE]) || b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return true;
    }
    let sample = &b[..b.len().min(4096)];
    if sample.is_empty() {
        return true;
    }
    let bad = sample.iter().filter(|&&c| c < 0x09 || ((0x0E..0x20).contains(&c) && c != 0x1B)).count();
    bad * 100 / sample.len() < 2
}

pub fn load_preview(path: &str) -> Preview {
    use std::io::Read;
    let p = Path::new(path);
    let mut out = Preview::default();
    let meta = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) => {
            out.error = Some(format!("无法读取文件：{e}"));
            return out;
        }
    };
    out.size = meta.len();
    out.streams = super::files::alt_streams(p).into_iter().filter(|(n, _)| !n.is_empty()).map(|(n, s)| format!("{n} ({} 字节)", s)).collect();
    let mut f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) => {
            out.error = Some(format!("无法打开文件：{e}"));
            return out;
        }
    };
    let read_len = if out.size <= PE_LIMIT { out.size as usize } else { TEXT_LIMIT };
    let mut buf = Vec::with_capacity(read_len);
    if let Err(e) = (&mut f).take(read_len as u64).read_to_end(&mut buf) {
        out.error = Some(format!("读取失败：{e}"));
        return out;
    }
    out.head = buf[..buf.len().min(HEX_LIMIT)].to_vec();
    if buf.starts_with(b"MZ") {
        out.pe = super::pe::parse(&buf);
        out.sign = super::signature::check(path);
    } else if looks_text(&buf) {
        let mut t = super::util::decode_text(&buf[..buf.len().min(TEXT_LIMIT)]);
        if out.size as usize > TEXT_LIMIT {
            t.push_str("\n…（仅显示前 64 KB）");
        }
        out.text = Some(t);
    }
    out.sha256 = super::util::sha256_file(p, 4 << 30);
    out
}

/// 十六进制视图的一行：偏移、16 个字节、可见字符。
pub fn hex_line(offset: usize, chunk: &[u8]) -> String {
    let mut s = format!("{offset:08X}  ");
    for i in 0..16 {
        match chunk.get(i) {
            Some(b) => s.push_str(&format!("{b:02X} ")),
            None => s.push_str("   "),
        }
        if i == 7 {
            s.push(' ');
        }
    }
    s.push(' ');
    s.extend(chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
    s
}

// ---------------------------------------------------------------- 进程模块

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub path: String,
    pub base: u64,
    pub size: u32,
    pub sign: SignState,
}

/// 枚举进程加载的模块并校验签名。受保护进程或权限不足时返回错误。
pub fn process_modules(pid: u32) -> Result<Vec<ModuleInfo>, String> {
    use windows::Win32::Foundation::{CloseHandle, ERROR_BAD_LENGTH};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };
    if pid <= 4 {
        return Err("系统进程没有用户态模块".into());
    }
    let mut paths = Vec::new();
    unsafe {
        // 进程正在加载模块时可能返回 ERROR_BAD_LENGTH，按文档重试
        let mut snap = None;
        for _ in 0..5 {
            match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
                Ok(h) => {
                    snap = Some(h);
                    break;
                }
                Err(e) if e.code() == ERROR_BAD_LENGTH.to_hresult() => continue,
                Err(e) => return Err(format!("无法读取模块列表（可能是受保护进程或权限不足）：{}", e.message())),
            }
        }
        let snap = snap.ok_or("模块列表读取失败，请重试")?;
        let mut me = MODULEENTRY32W { dwSize: size_of::<MODULEENTRY32W>() as u32, ..Default::default() };
        if Module32FirstW(snap, &mut me).is_ok() {
            loop {
                let path = super::util::from_wide(&me.szExePath);
                paths.push((path, me.modBaseAddr as u64, me.modBaseSize));
                if Module32NextW(snap, &mut me).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    let mut out: Vec<ModuleInfo> =
        paths.into_iter().map(|(path, base, size)| ModuleInfo { sign: super::signature::check(&path), path, base, size }).collect();
    // 未签名的排前面，其次是非系统目录
    out.sort_by_key(|m| (m.sign == SignState::Signed, is_system_dir(&m.path), m.path.to_lowercase()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_and_substring_matching() {
        assert!(name_matches("invoice.pdf.exe", "*.exe"));
        assert!(name_matches("a1.tmp", "a?.tmp"));
        assert!(!name_matches("a12.tmp", "a?.tmp"));
        assert!(name_matches("mimikatz.exe", "katz"));
        assert!(!name_matches("notepad.exe", "*.dll"));
        assert!(name_matches("x", "*"));
    }

    #[test]
    fn detects_double_extension() {
        assert!(double_extension("发票.pdf.exe"));
        assert!(double_extension("photo.JPG.scr"));
        assert!(!double_extension("setup.exe"));
        assert!(!double_extension("archive.tar.gz"));
    }

    #[test]
    fn criteria_filters_by_ext_size_and_time() {
        let now = chrono::Local::now();
        let e = FsEntry { name: "a.exe".into(), size: 2048, modified: Some(now), ..Default::default() };
        let mut c = SearchCriteria { exts: vec!["exe"], ..Default::default() };
        assert!(c.matches(&e));
        c.min_size = Some(4096);
        assert!(!c.matches(&e));
        c.min_size = None;
        c.since = Some(now + chrono::Duration::days(1));
        assert!(!c.matches(&e));
        let dir = FsEntry { name: "d".into(), is_dir: true, ..Default::default() };
        assert!(!SearchCriteria::default().matches(&dir));
    }

    #[test]
    fn search_finds_files_and_honours_cancel() {
        let base = std::env::temp_dir().join(format!("lwi_search_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub/deeper")).unwrap();
        std::fs::write(base.join("sub/deeper/evil.ps1"), b"x").unwrap();
        std::fs::write(base.join("readme.txt"), b"x").unwrap();
        let progress = Arc::new(SearchProgress::default());
        search(&base, &SearchCriteria { exts: vec!["ps1"], ..Default::default() }, &progress);
        let r = progress.results.lock().unwrap().clone();
        assert_eq!(r.len(), 1);
        assert!(r[0].path.ends_with("evil.ps1"));
        assert!(progress.scanned.load(Ordering::Relaxed) >= 4);

        let cancelled = Arc::new(SearchProgress::default());
        cancelled.cancel.store(true, Ordering::Relaxed);
        search(&base, &SearchCriteria::default(), &cancelled);
        assert_eq!(cancelled.scanned.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn list_dir_puts_directories_first() {
        let base = std::env::temp_dir().join(format!("lwi_list_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("zdir")).unwrap();
        std::fs::write(base.join("afile.txt"), b"hello").unwrap();
        let v = list_dir(&base, true).unwrap();
        assert_eq!(v[0].name, "zdir");
        assert!(v[0].is_dir);
        assert_eq!(v[1].size, 5);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn preview_detects_text_and_pe() {
        let base = std::env::temp_dir().join(format!("lwi_prev_{}.txt", std::process::id()));
        std::fs::write(&base, "第一行\r\nline2").unwrap();
        let p = load_preview(&base.display().to_string());
        assert!(p.text.as_deref().unwrap().contains("line2"));
        assert_eq!(p.sha256.len(), 64);
        let _ = std::fs::remove_file(&base);
        let exe = load_preview(&std::env::current_exe().unwrap().display().to_string());
        assert!(exe.pe.is_some());
        assert!(exe.text.is_none());
    }

    #[test]
    fn hex_line_format() {
        let l = hex_line(16, b"MZ\x90\x00");
        assert!(l.starts_with("00000010  4D 5A 90 00"));
        assert!(l.ends_with("MZ.."));
    }

    #[test]
    fn modules_of_current_process() {
        let m = process_modules(std::process::id()).unwrap();
        assert!(m.iter().any(|x| x.path.to_ascii_lowercase().ends_with("ntdll.dll")));
    }
}
