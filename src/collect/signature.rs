//! Authenticode 签名校验：先校验内嵌签名，失败后再查系统编录(catalog)签名。

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::WinTrust::*;
use windows::core::{GUID, PCWSTR, w};

use super::util::wide;
use crate::model::SignState;

const DRIVER_ACTION_VERIFY: GUID = GUID::from_u128(0xf750e6c3_38ee_11d1_85e5_00c04fc295ee);

fn cache() -> &'static Mutex<HashMap<String, SignState>> {
    static CACHE: OnceLock<Mutex<HashMap<String, SignState>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn check(path: &str) -> SignState {
    if path.is_empty() {
        return SignState::NotChecked;
    }
    let key = path.to_ascii_lowercase();
    if key.contains("\\program files\\windowsapps\\") && Path::new(path).is_file() {
        // 应用商店包目录仅 TrustedInstaller 可写，签名由包清单保证
        return SignState::Signed;
    }
    if let Some(s) = cache().lock().ok().and_then(|c| c.get(&key).copied()) {
        return s;
    }
    let state = if !Path::new(path).is_file() {
        SignState::Missing
    } else if verify_embedded(path) || verify_catalog(path) {
        SignState::Signed
    } else {
        SignState::Unsigned
    };
    if let Ok(mut c) = cache().lock() {
        c.insert(key, state);
    }
    state
}

fn base_trust_data() -> WINTRUST_DATA {
    WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    }
}

unsafe fn run_trust(data: &mut WINTRUST_DATA) -> bool {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    unsafe {
        let r = WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND::default(), &mut action, data as *mut _ as *mut c_void);
        r == 0
    }
}

fn verify_embedded(path: &str) -> bool {
    let wpath = wide(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = base_trust_data();
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file_info;
    unsafe { run_trust(&mut data) }
}

fn verify_catalog(path: &str) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let handle = HANDLE(file.as_raw_handle() as *mut c_void);
    for algo in [w!("SHA256"), PCWSTR::null()] {
        if let Some(ok) = unsafe { verify_catalog_with(path, handle, algo) } {
            return ok;
        }
    }
    false
}

/// 返回 None 表示该哈希算法下没有找到编录，可换算法重试。
unsafe fn verify_catalog_with(path: &str, handle: HANDLE, algo: PCWSTR) -> Option<bool> {
    unsafe {
        let mut admin: isize = 0;
        CryptCATAdminAcquireContext2(&mut admin, Some(&DRIVER_ACTION_VERIFY), algo, None, None)
            .ok()?;
        let mut hash_len: u32 = 0;
        let _ = CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut hash_len, None, None);
        if hash_len == 0 || hash_len > 256 {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            return None;
        }
        let mut hash = vec![0u8; hash_len as usize];
        if CryptCATAdminCalcHashFromFileHandle2(
            admin,
            handle,
            &mut hash_len,
            Some(hash.as_mut_ptr()),
            None,
        )
        .is_err()
        {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            return None;
        }
        let cat = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
        if cat == 0 {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            return None;
        }
        let mut info = CATALOG_INFO {
            cbStruct: size_of::<CATALOG_INFO>() as u32,
            ..Default::default()
        };
        let mut ok = false;
        if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
            let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
            let wtag = wide(&tag);
            let wpath = wide(path);
            let mut cat_info = WINTRUST_CATALOG_INFO {
                cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(wtag.as_ptr()),
                pcwszMemberFilePath: PCWSTR(wpath.as_ptr()),
                hMemberFile: handle,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash.len() as u32,
                hCatAdmin: admin,
                ..Default::default()
            };
            let mut data = base_trust_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous.pCatalog = &mut cat_info;
            ok = run_trust(&mut data);
        }
        let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        let _ = CryptCATAdminReleaseContext(admin, 0);
        Some(ok)
    }
}
