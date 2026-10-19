//! 极简 .lnk 快捷方式解析（MS-SHLLINK），只取目标路径与参数。

#[derive(Default, Debug, Clone)]
pub struct LnkInfo {
    pub target: String,
    pub arguments: String,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(o)?, *b.get(o + 1)?, *b.get(o + 2)?, *b.get(o + 3)?]))
}

fn cstr_at(b: &[u8], o: usize) -> String {
    let end = b[o.min(b.len())..].iter().position(|&c| c == 0).map(|p| o + p).unwrap_or(b.len());
    String::from_utf8_lossy(&b[o.min(b.len())..end]).into_owned()
}

fn wstr_at(b: &[u8], o: usize) -> String {
    let mut words = Vec::new();
    let mut i = o;
    while let Some(w) = u16_at(b, i) {
        if w == 0 {
            break;
        }
        words.push(w);
        i += 2;
    }
    String::from_utf16_lossy(&words)
}

pub fn parse(bytes: &[u8]) -> Option<LnkInfo> {
    if bytes.len() < 0x4C || u32_at(bytes, 0)? != 0x4C {
        return None;
    }
    let flags = u32_at(bytes, 0x14)?;
    let unicode = flags & 0x80 != 0;
    let mut off = 0x4C;
    let mut info = LnkInfo::default();

    if flags & 0x01 != 0 {
        off += 2 + u16_at(bytes, off)? as usize;
    }
    if flags & 0x02 != 0 {
        let li = off;
        let size = u32_at(bytes, li)? as usize;
        let header = u32_at(bytes, li + 4)? as usize;
        let base_off = u32_at(bytes, li + 16)? as usize;
        if header >= 0x24 {
            if let Some(uoff) = u32_at(bytes, li + 28) {
                if uoff > 0 {
                    info.target = wstr_at(bytes, li + uoff as usize);
                }
            }
        }
        if info.target.is_empty() && base_off > 0 {
            info.target = cstr_at(bytes, li + base_off);
        }
        off += size;
    }

    // StringData: NAME, RELATIVE_PATH, WORKING_DIR, ARGUMENTS, ICON_LOCATION
    let read_string = |off: &mut usize| -> Option<String> {
        let count = u16_at(bytes, *off)? as usize;
        *off += 2;
        let s = if unicode {
            let end = (*off + count * 2).min(bytes.len());
            let words: Vec<u16> = bytes[*off..end]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            *off += count * 2;
            String::from_utf16_lossy(&words)
        } else {
            let end = (*off + count).min(bytes.len());
            let s = String::from_utf8_lossy(&bytes[*off..end]).into_owned();
            *off += count;
            s
        };
        Some(s)
    };
    let mut relative = String::new();
    if flags & 0x04 != 0 {
        read_string(&mut off)?;
    }
    if flags & 0x08 != 0 {
        relative = read_string(&mut off)?;
    }
    if flags & 0x10 != 0 {
        read_string(&mut off)?;
    }
    if flags & 0x20 != 0 {
        info.arguments = read_string(&mut off)?;
    }
    if info.target.is_empty() {
        info.target = relative;
    }
    Some(info)
}

pub fn parse_file(path: &std::path::Path) -> Option<LnkInfo> {
    let bytes = std::fs::read(path).ok()?;
    parse(&bytes)
}
