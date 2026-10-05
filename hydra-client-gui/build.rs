//! 构建脚本：为 Windows exe 嵌入应用图标资源（assets/app.ico）。
//! 仅 Windows 宿主编译时生效；其他平台此脚本为空操作。
//! 图标来源：仓库根目录 favicon.ico 的副本（资源管理器/桌面快捷方式/任务栏显示）。

/// Windows 宿主：用 winresource 把 assets/app.ico 嵌入 exe 资源段。
#[cfg(windows)]
fn embed_icon() {
    // 非 Windows 目标（交叉编译到其他平台）：无需嵌入资源
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    // 嵌入失败仅告警不阻断编译（图标缺失不影响功能）
    if let Err(e) = res.set_icon("assets/app.ico").compile() {
        println!("cargo:warning=嵌入应用图标失败: {}", e);
    }
}

/// 非 Windows 宿主：空操作。
#[cfg(not(windows))]
fn embed_icon() {}

fn main() {
    embed_icon();
}
