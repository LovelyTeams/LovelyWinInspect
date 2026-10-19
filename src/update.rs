//! 版本更新：查询 GitHub Releases 获取最新版本信息，由用户前往发布页下载。

use serde::{Deserialize, Serialize};

use crate::collect::util::run_powershell;

/// 更新仓库：优先读取环境变量 LWI_UPDATE_REPO，其次使用 Cargo.toml 中的 repository 字段。
pub fn repo() -> Option<String> {
    if let Ok(r) = std::env::var("LWI_UPDATE_REPO") {
        if r.contains('/') {
            return Some(r.trim().trim_matches('/').to_string());
        }
    }
    let url = env!("CARGO_PKG_REPOSITORY");
    let rest = url.trim_end_matches(".git").trim_end_matches('/').split("github.com/").nth(1)?;
    let mut parts = rest.split('/');
    let (owner, name) = (parts.next()?, parts.next()?);
    (!owner.is_empty() && !name.is_empty()).then(|| format!("{owner}/{name}"))
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag: String,
    pub name: String,
    pub notes: String,
    pub url: String,
    pub published: String,
    pub prerelease: bool,
    pub assets: Vec<(String, u64)>,
}

impl ReleaseInfo {
    pub fn version(&self) -> String {
        self.tag.trim_start_matches(['v', 'V']).to_string()
    }
}

/// 版本号比较：按数字段逐段比较，忽略 "-beta" 等后缀中的非数字部分。
pub fn is_newer(remote: &str, local: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches(['v', 'V'])
            .split(['.', '-', '+'])
            .map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>())
            .take(3)
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    let (r, l) = (parse(remote), parse(local));
    for i in 0..3 {
        let (a, b) = (r.get(i).copied().unwrap_or(0), l.get(i).copied().unwrap_or(0));
        if a != b {
            return a > b;
        }
    }
    false
}

/// 查询最新发布版本（直连 api.github.com）。
pub fn fetch_latest(repo: &str, include_prerelease: bool) -> Result<ReleaseInfo, String> {
    if !repo.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)) {
        return Err("仓库名称格式不正确".into());
    }
    let endpoint = if include_prerelease {
        format!("https://api.github.com/repos/{repo}/releases?per_page=10")
    } else {
        format!("https://api.github.com/repos/{repo}/releases/latest")
    };
    let script = format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
         try {{ $r = Invoke-RestMethod -Uri '{endpoint}' -TimeoutSec 15 -Headers @{{ 'User-Agent' = 'LovelyWinInspect'; 'Accept' = 'application/vnd.github+json' }}; \
         $r | ConvertTo-Json -Depth 5 -Compress }} \
         catch {{ $code = 0; if ($_.Exception.Response) {{ $code = [int]$_.Exception.Response.StatusCode }}; \
         @{{ error = $_.Exception.Message; status = $code }} | ConvertTo-Json -Compress }}"
    );
    let out = run_powershell(&script).ok_or("无法执行网络请求")?;
    let v: serde_json::Value = serde_json::from_str(out.trim()).map_err(|_| "GitHub 返回内容无法解析".to_string())?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        let status = v.get("status").and_then(|s| s.as_i64()).unwrap_or(0);
        return Err(match status {
            404 => "仓库不存在或尚未发布任何 Release".into(),
            403 => "GitHub API 访问频率受限，请稍后再试".into(),
            _ => format!("连接 GitHub 失败：{err}"),
        });
    }
    let release = match &v {
        serde_json::Value::Array(list) => list
            .iter()
            .find(|r| !r.get("draft").and_then(|d| d.as_bool()).unwrap_or(false))
            .cloned()
            .ok_or("仓库尚未发布任何 Release")?,
        other => other.clone(),
    };
    let s = |k: &str| release.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let assets = release
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .map(|x| {
                    (
                        x.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        x.get("size").and_then(|n| n.as_u64()).unwrap_or(0),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let info = ReleaseInfo {
        tag: s("tag_name"),
        name: s("name"),
        notes: s("body"),
        url: s("html_url"),
        published: chrono::DateTime::parse_from_rfc3339(&s("published_at"))
            .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|_| s("published_at")),
        prerelease: release.get("prerelease").and_then(|p| p.as_bool()).unwrap_or(false),
        assets,
    };
    if info.tag.is_empty() {
        return Err("未获取到版本号".into());
    }
    Ok(info)
}

pub fn releases_page(repo: &str) -> String {
    format!("https://github.com/{repo}/releases")
}
