//! 应用图标模块：从嵌入的 `assets/app.ico`（构建期 include_bytes! 零运行时文件依赖）
//! 解码出各处所需的 RGBA 像素：
//! - 窗口图标（标题栏/任务栏缩略图）：优先选 ≥48px 的最大帧；
//! - 系统托盘图标：解码后统一缩放到 32×32（托盘标准尺寸）。
//!
//! 解码在任何一步失败都不 panic：调用方拿到 `None` 后 fallback（无窗口图标 /
//! 代码生成的默认托盘图标），仅记 warn 日志。

use eframe::egui;
use image::ImageReader;
use std::io::Cursor;

/// 嵌入的应用图标（ICO，可含多尺寸帧）。源文件为仓库根目录 favicon.ico 的副本。
pub const APP_ICO_BYTES: &[u8] = include_bytes!("../assets/app.ico");

/// 从 ICO 嵌入字节解码：选最大帧，转 RGBA8。
/// image crate 的 ICO 解码器会自动选择目录中尺寸最大的帧，无需手动解析目录。
fn decode_largest_rgba() -> Result<image::RgbaImage, String> {
    let img = ImageReader::new(Cursor::new(APP_ICO_BYTES))
        .with_guessed_format()
        .map_err(|e| format!("ICO 格式探测失败: {}", e))?
        .decode()
        .map_err(|e| format!("ICO 解码失败: {}", e))?;
    Ok(img.to_rgba8())
}

/// 窗口图标（eframe ViewportBuilder::with_icon）：≥48px 的最大帧原样转 RGBA8。
/// 任何失败返回 None（调用方不设置窗口图标）并记 warn。
pub fn load_window_icon() -> Option<egui::IconData> {
    match decode_largest_rgba() {
        Ok(rgba) => {
            let (w, h) = rgba.dimensions();
            // ICO 里可能有极小帧，窗口图标太小观感差：小于 48px 不采用
            if w < 48 || h < 48 {
                tracing::warn!("应用图标最大帧 {}x{} 小于 48px，跳过窗口图标", w, h);
                return None;
            }
            Some(egui::IconData {
                width: w,
                height: h,
                rgba: rgba.into_raw(),
            })
        }
        Err(e) => {
            tracing::warn!("窗口图标加载失败（无自定义图标）: {}", e);
            None
        }
    }
}

/// 托盘图标 RGBA（32×32）：解码最大帧后缩放到 32×32 RGBA。
/// 任何失败返回 None（调用方 fallback 到代码生成的默认图标）并记 warn。
pub fn load_tray_icon_rgba() -> Option<Vec<u8>> {
    match decode_largest_rgba() {
        Ok(rgba) => {
            let resized = image::imageops::resize(&rgba, 32, 32, image::imageops::FilterType::Lanczos3);
            Some(resized.into_raw())
        }
        Err(e) => {
            tracing::warn!("托盘图标解码失败（使用默认图标）: {}", e);
            None
        }
    }
}
