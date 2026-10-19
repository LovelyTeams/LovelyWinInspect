<#
.SYNOPSIS
    生成 GitHub Release 发布说明：CHANGELOG.md 中该版本的更新日志 + 下载说明与 SHA256（.github/release-footer.md）。

.DESCRIPTION
    同时做发布前检查：标签版本必须与 Cargo.toml 一致，且 CHANGELOG.md 中必须有该版本的非空条目，
    否则报错退出，CI 不会发布。

.EXAMPLE
    # 只检查（CI 在构建前执行，尽早失败）
    ./tools/release_notes.ps1 -Tag v0.1.1 -CheckOnly

.EXAMPLE
    # 生成发布说明
    ./tools/release_notes.ps1 -Tag v0.1.1 -Exe target/release/LovelyWinInspect.exe -Out notes.md
#>
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    # 用于计算 SHA256 的 exe；也可直接用 -Sha256 传入
    [string]$Exe,
    [string]$Sha256,
    [string]$Out,
    [string]$Repo = $env:GITHUB_REPOSITORY,
    [switch]$CheckOnly
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$ver = $Tag -replace '^v', ''
if (-not $Repo) { $Repo = "LovelyTeams/LovelyWinInspect" }

# 标签与 Cargo.toml 版本一致
$cargoLine = @(Get-Content (Join-Path $root "Cargo.toml") -Encoding UTF8) | Where-Object { $_ -match '^version\s*=' } | Select-Object -First 1
$cargoVer = [regex]::Match($cargoLine, '"([^"]+)"').Groups[1].Value
if ($cargoVer -ne $ver) { throw "标签 $Tag 与 Cargo.toml 中的版本 $cargoVer 不一致" }

# 取出 CHANGELOG.md 中该版本的段落：从 “## [版本]” 到下一个二级标题
$lines = @(Get-Content (Join-Path $root "CHANGELOG.md") -Encoding UTF8)
$heading = '^##\s+\[?v?' + [regex]::Escape($ver) + '\]?(\s|$)'
$start = -1
$end = $lines.Count
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($start -lt 0) {
        if ($lines[$i] -match $heading) { $start = $i + 1 }
    } elseif ($lines[$i] -match '^##\s') {
        $end = $i
        break
    }
}
if ($start -lt 0) { throw "CHANGELOG.md 中没有 $ver 的更新日志，请先补充再打标签" }
$section = if ($end -gt $start) { ($lines[$start..($end - 1)] -join "`n").Trim() } else { "" }
if (-not $section) { throw "CHANGELOG.md 中 $ver 的更新日志为空" }

if ($CheckOnly) {
    "CHANGELOG.md 已包含 $ver 的更新日志（$(($section -split "`n").Count) 行），版本号与 Cargo.toml 一致"
    return
}

if (-not $Sha256) {
    if (-not $Exe) { throw "需要 -Exe 或 -Sha256" }
    $Sha256 = (Get-FileHash $Exe -Algorithm SHA256).Hash
}
$Sha256 = $Sha256.ToLower() -replace '^sha256:', ''

# 与上一个版本的对比链接（需要完整的 git 历史与标签）
$compare = ""
# Windows PowerShell 5.1 在 Stop 模式下会把原生命令的 stderr 当作异常，这里临时放宽
$ErrorActionPreference = "Continue"
$prev = git -C $root describe --tags --abbrev=0 --match "v*" "$Tag^" 2>$null
$ok = $LASTEXITCODE -eq 0
$ErrorActionPreference = "Stop"
if ($ok -and $prev) {
    $compare = "**完整变更**：https://github.com/$Repo/compare/$prev...$Tag`n`n"
}
$global:LASTEXITCODE = 0

# CHANGELOG 中的相对链接（如 docs/xxx.md）在 Release 页面无法解析，改为指向该标签的绝对地址
$section = [regex]::Replace($section, '\]\((?!https?://|#|mailto:)([^)\s]+)\)', "](https://github.com/$Repo/blob/$Tag/`$1)")

$footer = Get-Content (Join-Path $root ".github/release-footer.md") -Encoding UTF8 -Raw
$footer = $footer.Replace("{{SHA256}}", $Sha256).Replace("{{COMPARE}}", $compare).Replace("{{REPO}}", $Repo)
$notes = "$section`n`n$($footer.Trim())`n"

if ($Out) {
    # 不带 BOM，否则 BOM 会出现在发布说明开头
    [System.IO.File]::WriteAllText($Out, $notes, (New-Object System.Text.UTF8Encoding $false))
    "发布说明已写入 $Out"
} else {
    $notes
}
