//! 图形界面无法启动时的兜底，以及无界面采集的公共流程。
//!
//! GPUI 依赖 Direct3D 11。没有显卡驱动时系统自带的软件渲染器（Microsoft Basic Render Driver）
//! 也能满足要求；只有连它都不可用（显示子系统损坏、精简系统等）时，GPUI 才会弹出英文错误并退出。
//! 因此启动前先按 GPUI 的条件探测一次，失败时提示用户改为无界面采集，并在浏览器中打开 HTML 报告。

use std::time::Instant;

use chrono::Local;

use crate::collect;
use crate::model::{ScanReport, Stage, StageLog, StageStatus};
use crate::report;

/// 一个 DXGI 适配器的探测结果。
pub struct AdapterProbe {
    pub name: String,
    pub vendor: u32,
    pub software: bool,
    /// 能否创建满足 GPUI 要求的 Direct3D 11 设备；不能时为原因
    pub usable: Result<(), String>,
}

/// 按 GPUI 的要求逐个检查适配器：能创建支持 BGRA 的 D3D11 设备（特性级别 10.1 及以上），
/// 并支持结构化缓冲区。
pub fn probe_adapters() -> Result<Vec<AdapterProbe>, String> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1};
    use windows::Win32::Graphics::Direct3D11::{
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_FEATURE_D3D10_X_HARDWARE_OPTIONS, D3D11_FEATURE_DATA_D3D10_X_HARDWARE_OPTIONS,
        D3D11_SDK_VERSION, D3D11CreateDevice, ID3D11Device,
    };
    use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory2, DXGI_ADAPTER_FLAG_SOFTWARE, DXGI_CREATE_FACTORY_FLAGS, IDXGIFactory1};

    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory2(DXGI_CREATE_FACTORY_FLAGS(0)) }.map_err(|e| format!("无法创建 DXGI 工厂：{}", e.message()))?;
    let mut out = Vec::new();
    for i in 0..32 {
        let Ok(adapter) = (unsafe { factory.EnumAdapters1(i) }) else { break };
        let Ok(desc) = (unsafe { adapter.GetDesc1() }) else { continue };
        let name = String::from_utf16_lossy(&desc.Description).trim_matches('\0').to_string();
        let usable = (|| -> Result<(), String> {
            let mut device: Option<ID3D11Device> = None;
            unsafe {
                D3D11CreateDevice(
                    &adapter,
                    D3D_DRIVER_TYPE_UNKNOWN,
                    HMODULE::default(),
                    D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                    Some(&[D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1]),
                    D3D11_SDK_VERSION,
                    Some(&mut device),
                    None,
                    None,
                )
            }
            .map_err(|e| format!("创建设备失败：{}", e.message()))?;
            let device = device.ok_or("创建设备失败")?;
            let mut data = D3D11_FEATURE_DATA_D3D10_X_HARDWARE_OPTIONS::default();
            unsafe {
                device.CheckFeatureSupport(
                    D3D11_FEATURE_D3D10_X_HARDWARE_OPTIONS,
                    &mut data as *mut _ as _,
                    size_of::<D3D11_FEATURE_DATA_D3D10_X_HARDWARE_OPTIONS>() as u32,
                )
            }
            .map_err(|e| format!("查询特性失败：{}", e.message()))?;
            if data.ComputeShaders_Plus_RawAndStructuredBuffers_Via_Shader_4_x.as_bool() {
                Ok(())
            } else {
                Err("不支持结构化缓冲区".into())
            }
        })();
        out.push(AdapterProbe {
            name,
            vendor: desc.VendorId,
            software: desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0 || desc.VendorId == 0x1414,
            usable,
        });
    }
    Ok(out)
}

/// 图形界面能否启动。环境变量 LWI_SIMULATE_NO_D3D=1 模拟不可用，便于测试兜底流程。
pub fn probe_d3d11() -> Result<(), String> {
    if std::env::var_os("LWI_SIMULATE_NO_D3D").is_some() {
        return Err("Direct3D 11 不可用（LWI_SIMULATE_NO_D3D 模拟）".into());
    }
    verdict(&probe_adapters()?)
}

fn verdict(adapters: &[AdapterProbe]) -> Result<(), String> {
    if adapters.iter().any(|a| a.usable.is_ok()) {
        Ok(())
    } else if adapters.is_empty() {
        Err("系统中没有任何图形适配器（包括软件渲染器）".into())
    } else {
        Err("没有可用的 Direct3D 11 图形设备（包括系统自带的软件渲染器）".into())
    }
}

/// `--gpu-info`：列出图形适配器与可用性，便于排查“界面打不开”的问题。
pub fn print_gpu_info() {
    match probe_adapters() {
        Ok(list) if list.is_empty() => println!("没有枚举到任何图形适配器"),
        Ok(list) => {
            for a in &list {
                println!(
                    "{}  [厂商 0x{:04X}{}]  {}",
                    a.name,
                    a.vendor,
                    if a.software { "，软件渲染" } else { "" },
                    match &a.usable {
                        Ok(()) => "可用".to_string(),
                        Err(e) => format!("不可用：{e}"),
                    }
                );
            }
            match list.iter().find(|a| a.usable.is_ok()) {
                Some(a) if a.software => println!("结论：图形界面可以启动，将使用软件渲染（界面动画会自动关闭）"),
                Some(a) => println!("结论：图形界面可以启动，将使用 {}", a.name),
                None => println!("结论：图形界面无法启动，请使用 --report 或 --json 无界面采集"),
            }
        }
        Err(e) => println!("探测失败：{e}"),
    }
}

/// 无界面采集全部阶段。每个阶段完成后回调 (阶段, 摘要, 耗时毫秒)。
pub fn collect_all(days: u32, mut on_stage: impl FnMut(Stage, &str, u64)) -> ScanReport {
    let mut report = ScanReport {
        tool: format!("LovelyWinInspect {}", env!("CARGO_PKG_VERSION")),
        lookback_days: days,
        started: Some(Local::now()),
        ..Default::default()
    };
    for stage in Stage::ALL {
        let started = Local::now();
        let t = Instant::now();
        let summary = collect::run_stage(stage, &mut report);
        let elapsed_ms = t.elapsed().as_millis() as u64;
        on_stage(stage, &summary, elapsed_ms);
        report.stages.push(StageLog { stage, status: StageStatus::Done, started: Some(started), elapsed_ms, summary });
    }
    report.finished = Some(Local::now());
    report
}

fn message_box(text: &str, flags: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT {
    use windows::Win32::UI::WindowsAndMessaging::{MB_SETFOREGROUND, MessageBoxW};
    use windows::core::HSTRING;
    unsafe { MessageBoxW(None, &HSTRING::from(text), &HSTRING::from("LovelyWinInspect"), flags | MB_SETFOREGROUND) }
}

/// 没有控制台时（双击启动）新建一个，用来显示采集进度。
fn ensure_console() {
    use windows::Win32::System::Console::{AllocConsole, GetConsoleWindow, SetConsoleTitleW};
    use windows::core::w;
    unsafe {
        if GetConsoleWindow().0.is_null() && AllocConsole().is_ok() {
            let _ = SetConsoleTitleW(w!("LovelyWinInspect - 无界面采集"));
        }
    }
}

fn open_in_browser(path: &std::path::Path) -> bool {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, PCWSTR, w};
    let r = unsafe { ShellExecuteW(None, w!("open"), &HSTRING::from(path.as_os_str()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
    r.0 as isize > 32
}

/// 无界面采集 → 导出报告 → 在浏览器中打开 HTML 报告。
///
/// `reason` 有值表示图形界面启动失败后的兜底：先用对话框说明原因并征求同意，结束时再用对话框
/// 告知结果（双击启动时控制台会随进程退出而关闭）。返回是否成功生成报告。
pub fn run_report(reason: Option<&str>, days: u32) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_YESNO};
    let interactive = reason.is_some();
    if let Some(reason) = reason {
        log::warn!("图形界面无法启动：{reason}");
        let text = format!(
            "无法启动图形界面：{reason}\n\n\
             可以改为无界面采集：在控制台窗口中显示进度，完成后自动导出报告，并在浏览器中打开 HTML 报告（通常需要 1 分钟左右）。\n\n\
             是否开始采集？"
        );
        if message_box(&text, MB_YESNO | MB_ICONWARNING) != IDYES {
            return false;
        }
    }
    ensure_console();
    println!("LovelyWinInspect {} 无界面采集（回溯 {days} 天）", env!("CARGO_PKG_VERSION"));
    let report = collect_all(days, |stage, summary, ms| println!("[{}] {} ({} ms)", stage.label(), summary, ms));

    let settings = crate::settings::Settings::load();
    let mut opts = settings.export;
    opts.html = true;
    match report::export(&report, opts, settings.export_root().as_deref()) {
        Ok(res) => {
            let html = res.dir.join("report.html");
            println!("报告已导出到 {}（{} 个文件）", res.dir.display(), res.files.len());
            let opened = open_in_browser(&html);
            if opened {
                println!("已在浏览器中打开 {}", html.display());
            } else {
                println!("无法自动打开浏览器，请手动打开 {}", html.display());
            }
            if interactive {
                message_box(
                    &format!(
                        "采集完成，报告已导出到：\n{}\n\n{}",
                        res.dir.display(),
                        if opened { "HTML 报告已在浏览器中打开。" } else { "无法自动打开浏览器，请手动打开其中的 report.html。" }
                    ),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            true
        }
        Err(e) => {
            eprintln!("导出失败：{e}");
            if interactive {
                message_box(&format!("采集完成，但导出报告失败：{e}"), MB_OK | MB_ICONERROR);
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_lists_adapters_without_panicking() {
        // CI 机器没有显卡，但应至少枚举到软件渲染器；这里只要求探测本身不出错
        let list = probe_adapters().expect("DXGI 工厂应可创建");
        for a in &list {
            println!("{} vendor=0x{:04X} software={} usable={:?}", a.name, a.vendor, a.software, a.usable);
        }
    }

    fn adapter(software: bool, ok: bool) -> AdapterProbe {
        AdapterProbe { name: "x".into(), vendor: 0, software, usable: if ok { Ok(()) } else { Err("no".into()) } }
    }

    #[test]
    fn verdict_accepts_any_usable_adapter_including_software() {
        assert!(verdict(&[adapter(false, false), adapter(true, true)]).is_ok());
        assert!(verdict(&[adapter(false, false)]).is_err());
        assert!(verdict(&[]).unwrap_err().contains("没有任何"));
    }
}
