//! 二维码生成与识别（Team-Q 分享体系 v2）。
//!
//! - 生成：`fast_qr` 产出 QR 矩阵 → 白底黑块 + 4 模块静区 → egui `ColorImage`（UI 直接显示）
//! - 识别：`rqrr` + `image` 从图片文件字节解码出二维码文本（用户「从图片导入二维码」）
//!
//! 二维码内容即 hydra 分享链接 v2 文本（见 hydra-client::share_link 模块文档）。
//! **安全提示**：完整分享（含密钥）的二维码等同持有节点，仅限当面/可信渠道出示。

use eframe::egui;

/// 静区宽度（模块数，QR 规范最小 4）
pub const QUIET_ZONE: u32 = 4;

/// 生成二维码布尔矩阵（行优先，`cells[y * size + x]`；None = 内容过长等编码失败）
pub fn qr_matrix(text: &str) -> Option<(Vec<bool>, usize)> {
    let qr = fast_qr::qr::QRBuilder::new(text.as_bytes()).build().ok()?;
    let size = qr.size;
    let mut cells = Vec::with_capacity(size * size);
    for y in 0..size {
        for x in 0..size {
            cells.push(qr[y][x].value());
        }
    }
    Some((cells, size))
}

/// 生成二维码的 egui 颜色图像（白底黑块 + 4 模块静区，每模块 1 像素；
/// UI 侧按需缩放显示）
pub fn qr_color_image(text: &str) -> Option<egui::ColorImage> {
    let (cells, size) = qr_matrix(text)?;
    let size = size as u32;
    let total = size + QUIET_ZONE * 2;
    let mut pixels = vec![egui::Color32::WHITE; (total * total) as usize];
    for y in 0..size {
        for x in 0..size {
            if cells[(y * size + x) as usize] {
                let px = (y + QUIET_ZONE) * total + (x + QUIET_ZONE);
                pixels[px as usize] = egui::Color32::BLACK;
            }
        }
    }
    Some(egui::ColorImage {
        size: [total as usize, total as usize],
        pixels,
    })
}

/// 解码前缩图上限（长边像素，审查 R-15）：手机相册常见 4000px 级照片直接喂
/// rqrr 会做全图多次扫描（像素工作量 ~12 倍于 1000px），且在 UI 调用栈同步
/// 执行时冻结界面。二维码在 ≤1000px 下信息密度绰绰有余。
const DECODE_MAX_EDGE: u32 = 1000;

/// 从图片文件字节（png/jpg）解码二维码文本；图片中无二维码或解码失败 → Err（中文根因）。
/// 解码前先缩图至长边 ≤1000px（`image::imageops::resize` 三次插值），降低像素工作量。
pub fn decode_qr_from_bytes(bytes: &[u8]) -> Result<String, String> {
    let img = image::load_from_memory(bytes).map_err(|e| format!("图片解码失败: {}", e))?;
    // 缩图：长边超过上限时等比缩小（小图不动，避免放大失真）
    let (w, h) = (img.width(), img.height());
    let long_edge = w.max(h);
    let img = if long_edge > DECODE_MAX_EDGE {
        let scale = DECODE_MAX_EDGE as f64 / long_edge as f64;
        let (nw, nh) = (
            (w as f64 * scale).round() as u32,
            (h as f64 * scale).round() as u32,
        );
        img.resize(nw.max(1), nh.max(1), image::imageops::FilterType::Triangle)
    } else {
        img
    };
    let gray = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("图片中未找到二维码".to_string());
    }
    let mut last_err = String::new();
    for grid in &grids {
        match grid.decode() {
            Ok((_, text)) => return Ok(text),
            Err(e) => last_err = format!("二维码内容读取失败: {:?}", e),
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tq_qr_matrix_nonempty_and_valid_size() {
        let url = "hydra://127.0.0.1:8080?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online&v=3&k=MTIzNDU2Nzg5MGFiY2RlZg";
        let (cells, size) = qr_matrix(url).expect("合法 URL 应编码成功");
        assert!(size >= 21, "QR version 1 最小 21 模块，实际 {}", size);
        assert_eq!(cells.len(), size * size);
        // 矩阵非全黑/全白（含定位图案必有黑白变化）
        assert!(cells.iter().any(|c| *c) && cells.iter().any(|c| !*c));

        // ColorImage 尺寸 = size + 两侧静区
        let img = qr_color_image(url).unwrap();
        let total = size + QUIET_ZONE as usize * 2;
        assert_eq!(img.size[0], total);
        assert_eq!(img.size[1], total);
        assert_eq!(img.pixels.len(), total * total);
        // 四角静区全白
        assert_eq!(img.pixels[0], egui::Color32::WHITE);
        // 中心区域应存在黑模块
        assert!(img.pixels.contains(&egui::Color32::BLACK));
    }

    #[test]
    fn tq_qr_generate_then_decode_roundtrip() {
        // v2 链接 → 二维码矩阵 → 渲染为灰度图（6 倍放大）→ rqrr 解码 → 文本一致
        let url = "hydra://192.168.1.100:4433?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online&v=3&k=MTIzNDU2Nzg5MGFiY2RlZg&mode=obfs&ok=cGFzc3dvcmQ";
        let (cells, size) = qr_matrix(url).unwrap();

        let scale: u32 = 6;
        let total = size as u32 + QUIET_ZONE * 2;
        let mut gray = image::GrayImage::new(total * scale, total * scale);
        for y in 0..total {
            for x in 0..total {
                let v = if x >= QUIET_ZONE
                    && y >= QUIET_ZONE
                    && x < total - QUIET_ZONE
                    && y < total - QUIET_ZONE
                    && cells[((y - QUIET_ZONE) * size as u32 + (x - QUIET_ZONE)) as usize]
                {
                    0u8
                } else {
                    255u8
                };
                for dy in 0..scale {
                    for dx in 0..scale {
                        gray.put_pixel(x * scale + dx, y * scale + dy, image::Luma([v]));
                    }
                }
            }
        }

        let mut png_buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageLuma8(gray)
            .write_to(&mut png_buf, image::ImageFormat::Png)
            .expect("PNG 编码应成功");
        let decoded = decode_qr_from_bytes(png_buf.get_ref()).expect("应从 PNG 解码出二维码");
        assert_eq!(decoded, url);
    }

    #[test]
    fn tq_decode_downscales_oversized_image() {
        // R-15：长边 >1000px 的大图先缩图再解码，仍能正确识别（超清相册图路径）
        let url = "hydra://192.168.1.100:4433?bandwidth=100&latency=10&loss_rate=0.01&load=0.5&status=online&v=3&k=MTIzNDU2Nzg5MGFiY2RlZg";
        let (cells, size) = qr_matrix(url).unwrap();
        let scale: u32 = 40; // total≈(size+8)*40 → 长边 >1000px，触发缩图分支
        let total = size as u32 + QUIET_ZONE * 2;
        let mut gray = image::GrayImage::new(total * scale, total * scale);
        for y in 0..total {
            for x in 0..total {
                let v = if x >= QUIET_ZONE
                    && y >= QUIET_ZONE
                    && x < total - QUIET_ZONE
                    && y < total - QUIET_ZONE
                    && cells[((y - QUIET_ZONE) * size as u32 + (x - QUIET_ZONE)) as usize]
                {
                    0u8
                } else {
                    255u8
                };
                for dy in 0..scale {
                    for dx in 0..scale {
                        gray.put_pixel(x * scale + dx, y * scale + dy, image::Luma([v]));
                    }
                }
            }
        }
        assert!(
            gray.width() > 1000 && gray.height() > 1000,
            "测试图必须超限"
        );
        let mut png_buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageLuma8(gray)
            .write_to(&mut png_buf, image::ImageFormat::Png)
            .unwrap();
        let decoded = decode_qr_from_bytes(png_buf.get_ref()).expect("缩图后仍应解码成功");
        assert_eq!(decoded, url);
    }

    #[test]
    fn tq_decode_rejects_non_qr_image() {
        // 纯白 PNG：合法图片但无二维码 → Err 中文报错
        let white = image::DynamicImage::ImageLuma8(image::GrayImage::from_pixel(
            64,
            64,
            image::Luma([255]),
        ));
        let mut png_buf = std::io::Cursor::new(Vec::new());
        white
            .write_to(&mut png_buf, image::ImageFormat::Png)
            .unwrap();
        let err = decode_qr_from_bytes(png_buf.get_ref()).unwrap_err();
        assert!(err.contains("二维码"), "报错应为中文根因: {}", err);

        // 非图片字节 → Err
        assert!(decode_qr_from_bytes(b"not an image").is_err());
    }
}
