use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/app.ico");
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/logo_256.png");
    println!("cargo:rerun-if-changed=assets/logo_64.png");
    println!("cargo::rustc-check-cfg=cfg(has_logo)");

    // 有 logo 资源时启用界面内 logo（由 tools/make_icons.py 生成）
    if Path::new("assets/logo_256.png").exists() && Path::new("assets/logo_64.png").exists() {
        println!("cargo:rustc-cfg=has_logo");
    }

    // exe 图标：GPUI 在 Windows 上以资源 ID 1 作为窗口/任务栏图标
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") && Path::new("assets/app.ico").exists() {
        embed_resource::compile("assets/app.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("编译图标资源失败");
    }
}
