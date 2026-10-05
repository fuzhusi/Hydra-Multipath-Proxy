//! T2（Team-G）：系统托盘模块。
//!
//! - 图标：代码生成 32×32 RGBA（蓝底白色 H 字母），无外部资源文件；
//! - 菜单：显示主窗 / 启动代理 / 停止代理 / 退出；
//! - 左键单击托盘图标 = 显示/隐藏主窗切换（Windows）；
//! - 事件桥：tray-icon（Windows）经全局 mpsc 通道投递事件，两个后台转发线程
//!   把菜单/点击事件转入本模块自己的通道，并调用 `egui::Context::request_repaint`
//!   唤醒 GUI 线程（窗口隐藏时也能即时响应）；GUI 线程在 update 中 try_recv 轮询，
//!   与既有的订阅/健康检查 mpsc 轮询模式一致。

use eframe::egui;
use std::sync::mpsc::{channel, Receiver};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// 托盘事件 → GUI 命令（在 egui update 线程上执行）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    /// 左键单击托盘图标：显示/隐藏主窗切换
    ToggleWindow,
    /// 菜单「显示主窗」
    ShowWindow,
    /// 菜单「启动代理」（与 UI 按钮同一 start_proxy 路径）
    StartProxy,
    /// 菜单「停止代理」（与 UI 按钮同一 stop_proxy 路径，含系统代理清理）
    StopProxy,
    /// 菜单「退出」：真正退出（先停代理 + 清理系统代理 + 落盘）
    Quit,
}

/// 托盘句柄 + 命令接收端
pub struct HydraTray {
    pub tray: TrayIcon,
    pub command_rx: Receiver<TrayCommand>,
}

impl HydraTray {
    /// 更新托盘 tooltip（代理运行状态）
    pub fn set_tooltip(&self, tooltip: &str) {
        if let Err(e) = self.tray.set_tooltip(Some(tooltip)) {
            eprintln!("[Tray] set_tooltip 失败: {}", e);
        }
    }
}

/// 创建托盘并启动事件转发线程。失败返回 Err（GUI 仍可正常使用，仅无托盘）。
pub fn create_tray(ctx: egui::Context) -> Result<HydraTray, String> {
    let icon = tray_icon::Icon::from_rgba(generate_icon_rgba(), 32, 32)
        .map_err(|e| format!("托盘图标生成失败: {}", e))?;

    let (tx, rx) = channel::<TrayCommand>();
    let tx_menu = tx.clone();
    let tx_click = tx.clone();

    let menu = Menu::new();
    let item_show = MenuItem::new("显示主窗", true, None);
    let item_start = MenuItem::new("启动代理", true, None);
    let item_stop = MenuItem::new("停止代理", true, None);
    let item_quit = MenuItem::new("退出", true, None);
    let id_show = item_show.id().clone();
    let id_start = item_start.id().clone();
    let id_stop = item_stop.id().clone();
    let id_quit = item_quit.id().clone();
    menu.append(&item_show)
        .map_err(|e| format!("托盘菜单构建失败: {}", e))?;
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| format!("托盘菜单构建失败: {}", e))?;
    menu.append(&item_start)
        .map_err(|e| format!("托盘菜单构建失败: {}", e))?;
    menu.append(&item_stop)
        .map_err(|e| format!("托盘菜单构建失败: {}", e))?;
    menu.append(&PredefinedMenuItem::separator())
        .map_err(|e| format!("托盘菜单构建失败: {}", e))?;
    menu.append(&item_quit)
        .map_err(|e| format!("托盘菜单构建失败: {}", e))?;

    let tray = TrayIconBuilder::new()
        .with_tooltip("Hydra 代理已停止")
        .with_icon(icon)
        .with_menu(Box::new(menu))
        // 左键不弹菜单（左键留给显示/隐藏切换；右键弹菜单）
        .with_menu_on_left_click(false)
        .build()
        .map_err(|e| format!("托盘初始化失败: {}", e))?;

    // ── 转发线程 1：菜单事件 ──
    let ctx_menu = ctx.clone();
    std::thread::spawn(move || {
        let rx_menu = MenuEvent::receiver();
        // while let 形式（clippy）：recv Err = 发送端弃用（进程退出），线程结束
        while let Ok(ev) = rx_menu.recv() {
            let cmd = if ev.id == id_show {
                Some(TrayCommand::ShowWindow)
            } else if ev.id == id_start {
                Some(TrayCommand::StartProxy)
            } else if ev.id == id_stop {
                Some(TrayCommand::StopProxy)
            } else if ev.id == id_quit {
                Some(TrayCommand::Quit)
            } else {
                None
            };
            if let Some(cmd) = cmd {
                let _ = tx_menu.send(cmd);
                // 窗口隐藏/空闲时唤醒 egui 立即处理
                ctx_menu.request_repaint();
            }
        }
    });

    // ── 转发线程 2：托盘图标左键单击 = 显示/隐藏切换 ──
    let ctx_click = ctx.clone();
    std::thread::spawn(move || {
        let rx_tray = TrayIconEvent::receiver();
        loop {
            match rx_tray.recv() {
                Ok(TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }) => {
                    let _ = tx_click.send(TrayCommand::ToggleWindow);
                    ctx_click.request_repaint();
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    Ok(HydraTray {
        tray,
        command_rx: rx,
    })
}

/// 代码生成托盘图标：32×32，蓝色圆角方块背景 + 白色「H」字母，逐像素绘制。
fn generate_icon_rgba() -> Vec<u8> {
    const SIZE: usize = 32;
    // 主题强调色（与 UI 一致）
    const BG: [u8; 3] = [0x2B, 0x4C, 0x9E];
    const ACCENT: [u8; 3] = [0x4C, 0x8B, 0xFF];
    const FG: [u8; 3] = [0xFF, 0xFF, 0xFF];

    let mut rgba = vec![0u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (r, g, b, a) = if in_rounded_rect(x, y, SIZE, 7.0) {
                // H 字母笔画：左右竖笔 + 中间横笔（宽 3px）
                let in_h = ((8..=10).contains(&x) || (21..=23).contains(&x))
                    && (8..=23).contains(&y)
                    || (8..=23).contains(&x) && (14..=17).contains(&y);
                if in_h {
                    (FG[0], FG[1], FG[2], 255)
                } else {
                    // 背景做一点垂直渐变，视觉更现代
                    let t = y as f32 / (SIZE - 1) as f32;
                    let mix = |c0: u8, c1: u8| -> u8 {
                        (c0 as f32 * (1.0 - t) + c1 as f32 * t).round() as u8
                    };
                    (
                        mix(BG[0], ACCENT[0]),
                        mix(BG[1], ACCENT[1]),
                        mix(BG[2], ACCENT[2]),
                        255,
                    )
                }
            } else {
                (0, 0, 0, 0) // 圆角外透明
            };
            let idx = (y * SIZE + x) * 4;
            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = a;
        }
    }
    rgba
}

/// 点 (x, y) 是否在圆角矩形内（半径 corner）
fn in_rounded_rect(x: usize, y: usize, size: usize, corner: f32) -> bool {
    let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
    let (w, h) = (size as f32, size as f32);
    // 距矩形边缘
    let dx = (corner - fx).max(fx - (w - corner)).max(0.0);
    let dy = (corner - fy).max(fy - (h - corner)).max(0.0);
    dx * dx + dy * dy <= corner * corner
}
