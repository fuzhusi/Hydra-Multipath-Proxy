// ═══════════════ A1：Windows 系统代理真实实现 ═══════════════
//
// 写 HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings：
//   ProxyEnable(DWORD)=1、ProxyServer="127.0.0.1:port"（裸 host:port）、
//   ProxyOverride（Windows 不支持 CIDR，用通配符）、删除 AutoConfigURL（PAC 会覆盖手动代理）。
// 停止时恢复旧值而非清除（enable 前先读旧值）；刷新用 windows-sys InternetSetOptionW(39/37)。
// 恢复所需旧值存放在全局槽位：panic hook / Drop / stop_proxy 三条清理路径都是静态函数。

use std::sync::Mutex;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
use winreg::RegKey;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
/// Windows 不支持 CIDR，使用通配符；<local> 覆盖裸主机名
const PROXY_OVERRIDE: &str = "localhost;127.*;192.168.*;172.*;10.*;<local>";

/// enable 之前的注册表旧值（disable 时恢复）
#[derive(Debug, Default, Clone)]
pub struct SavedProxyState {
    pub proxy_enable: Option<u32>,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
    pub autoconfig_url: Option<String>,
}

/// 全局旧值槽位：清理路径（panic hook 等）无法访问 GUI 状态，经此恢复。
/// Mutex 中毒时直接取回内部数据——panic 清理路径本身必须可用。
static SAVED_STATE: Mutex<Option<SavedProxyState>> = Mutex::new(None);

fn lock_saved() -> std::sync::MutexGuard<'static, Option<SavedProxyState>> {
    SAVED_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn open_settings_key() -> std::io::Result<RegKey> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_SET_VALUE)
}

/// 开启系统代理。返回 Err 时 GUI 侧显式报错，不静默。
pub fn enable(proxy_addr: &str) -> std::io::Result<()> {
    let key = open_settings_key()?;
    let mut saved = SavedProxyState {
        proxy_enable: key.get_value("ProxyEnable").ok(),
        proxy_server: key.get_value("ProxyServer").ok(),
        proxy_override: key.get_value("ProxyOverride").ok(),
        autoconfig_url: key.get_value("AutoConfigURL").ok(),
    };
    // 修复式保存：旧值本身是死代理残留（上次异常退出所留）→ 槽位改存"无代理"，
    // 停机恢复为直接连接，不再把坏状态原样还回（断根"每次关闭都断网"循环）
    if snapshot_is_dead(saved.proxy_enable, saved.proxy_server.as_deref(), port_has_listener) {
        tracing::warn!("enable 前的旧系统代理指向无监听的本机端口（异常退出残留）——停机将恢复为直接连接");
        saved = SavedProxyState::default();
    }
    *lock_saved() = Some(saved);

    key.set_value("ProxyEnable", &1u32)?;
    // 裸 host:port（不带协议前缀；WinINet 对 SOCKS 可用 "socks=host:port" 形式，
    // 裸 host:port 表示所有协议的 HTTP 代理，浏览器按需升级 CONNECT）
    key.set_value("ProxyServer", &proxy_addr.to_string())?;
    key.set_value("ProxyOverride", &PROXY_OVERRIDE)?;
    // PAC 会覆盖手动代理，必须删除
    let _ = key.delete_value("AutoConfigURL");
    refresh();
    Ok(())
}

/// 恢复 enable 之前的注册表状态（旧值恢复而非一律清除；原先不存在的键值则删除）。
/// 从未 enable 过时不做任何事。
pub fn disable() {
    let saved = match lock_saved().take() {
        Some(s) => s,
        None => return,
    };
    if let Ok(key) = open_settings_key() {
        match saved.proxy_enable {
            Some(v) => {
                let _ = key.set_value("ProxyEnable", &v);
            }
            None => {
                let _ = key.delete_value("ProxyEnable");
            }
        }
        match saved.proxy_server {
            Some(v) => {
                let _ = key.set_value("ProxyServer", &v);
            }
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        match saved.proxy_override {
            Some(v) => {
                let _ = key.set_value("ProxyOverride", &v);
            }
            None => {
                let _ = key.delete_value("ProxyOverride");
            }
        }
        match saved.autoconfig_url {
            Some(v) => {
                let _ = key.set_value("AutoConfigURL", &v);
            }
            None => {
                let _ = key.delete_value("AutoConfigURL");
            }
        }
    }
    refresh();
}

/// 通知 WinINet 设置已更改并立即刷新：
/// InternetSetOptionW(NULL, 39=INTERNET_OPTION_SETTINGS_CHANGED) +
/// InternetSetOptionW(NULL, 37=INTERNET_OPTION_REFRESH)
fn refresh() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    unsafe {
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

// ═════════════ 异常退出残留治理（启动自愈 + 修复式保存）═════════════
//
// 背景（用户实测）：GUI 非正常死亡（强杀/断电——Windows 不给任何回调）后注册表
// 残留 ProxyEnable=1 → 127.0.0.1:port 死端口，浏览器断网；更糟的是 enable 会把
// 该坏状态当"用户原值"存槽位，disable 忠实还原 → 每次"启动→关闭"都把坏状态还
// 回来，断网反复出现。治理两层：
// 1) 修复式保存（enable 内）：旧值是死代理 → 槽位存"无代理"，停机恢复为直连；
// 2) 启动自愈（cleanup_stale_system_proxy）：启动时检出残留直接清除。
// 判据安全边际：仅"指向本机回环 + 端口无监听"才判死——其他软件的活代理（端口
// 有监听）与非回环代理一律不动；AutoConfigURL（PAC）属他方配置永不碰。

/// 启动自愈结果标志：main 在实例守卫后调用 cleanup 并置位，窗口创建后读出补日志
pub static STALE_PROXY_CLEANED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 从 ProxyServer 字符串提取"指向本机回环"的端口列表（纯函数，供判定与单测）。
/// 兼容裸 host:port（本工具写入格式）与 "socks=127.0.0.1:1080;http=…" 复合格式；
/// 非回环地址（局域网/公网代理）不算。
fn loopback_ports(server: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for seg in server.split(';') {
        let seg = seg.trim();
        let Some((host, port_str)) = seg.rsplit_once(':') else {
            continue;
        };
        let h = host.to_ascii_lowercase();
        if !(h.contains("127.0.0.1") || h.contains("localhost") || h.contains("::1")) {
            continue;
        }
        if let Ok(p) = port_str.trim().parse::<u16>() {
            if p != 0 && !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// 端口探测：bind 成功 = 无监听（死）；AddrInUse = 有监听（活）。
/// 用 bind 而非 connect——不向未知代理发起真实连接（探测零副作用）。
/// TIME_WAIT 等边缘导致 bind 失败时按"活"处理（保守：宁漏清不误清）。
fn port_has_listener(port: u16) -> bool {
    match std::net::TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => {
            drop(l);
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => true,
        Err(_) => false,
    }
}

/// 死代理判定（纯逻辑）：启用中 + ProxyServer 指向回环 + 全部端口都无监听。
/// ProxyServer 缺失/非回环/无端口 → 不判死（不是本工具制造的形态，不动）。
fn snapshot_is_dead(
    proxy_enable: Option<u32>,
    proxy_server: Option<&str>,
    is_live: impl Fn(u16) -> bool,
) -> bool {
    if proxy_enable != Some(1) {
        return false;
    }
    let Some(s) = proxy_server else { return false };
    if s.is_empty() {
        return false;
    }
    let ports = loopback_ports(s);
    !ports.is_empty() && ports.iter().all(|p| !is_live(*p))
}

/// 启动自愈：清除"启用中且指向无监听本机端口"的残留系统代理。
/// 返回是否执行了清除（调用方读 [`STALE_PROXY_CLEANED`] 补 UI 日志）。
/// 注：若残留前用户有 PAC（enable 删过 AutoConfigURL）则无法凭空恢复——
/// 清除手动代理后回到直连，PAC 需用户侧重配（代码注释存档，不弹窗打扰）。
pub fn cleanup_stale_system_proxy() {
    let Ok(key) = open_settings_key() else { return };
    let enable_v: Option<u32> = key.get_value("ProxyEnable").ok();
    let server: Option<String> = key.get_value("ProxyServer").ok();
    if !snapshot_is_dead(enable_v, server.as_deref(), port_has_listener) {
        return;
    }
    let _ = key.delete_value("ProxyEnable");
    let _ = key.delete_value("ProxyServer");
    let _ = key.delete_value("ProxyOverride");
    refresh();
    STALE_PROXY_CLEANED.store(true, std::sync::atomic::Ordering::SeqCst);
    tracing::warn!("启动自愈：清除上次异常退出残留的系统代理（指向无监听的本机端口）");
}

// ═════════════ WM_ENDSESSION 钩子（系统关机/注销时恢复）═════════════
//
// eframe/winit 不转发 WM_ENDSESSION——用 comctl32 子类化挂到本进程可见顶层
// 窗口。关机/注销时 ENDSESSION(wParam=TRUE) 到达 → 同步 disable()（注册表
// 毫秒级 + WinINet 刷新）后走默认处理，不拖慢关机。强杀/断电仍无法覆盖
// （Windows 无回调），由启动自愈兜底——两层合起来才是完整语义。

static ENDSESSION_INSTALLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 幂等安装（update 首帧起每帧调用，原子闸保证只装一次；窗口此时已创建）。
pub fn install_endsession_restore_hook() {
    use std::sync::atomic::Ordering;
    if ENDSESSION_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
    };
    const WM_ENDSESSION: u32 = 0x0016;

    unsafe extern "system" fn subclass_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        _id: usize,
        _data: usize,
    ) -> isize {
        if msg == WM_ENDSESSION && wparam != 0 {
            // disable 幂等（槽位 take），与其他清理路径先到先处理
            disable();
        }
        unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> i32 {
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if pid == std::process::id() && unsafe { IsWindowVisible(hwnd) } != 0 {
            unsafe { *(lparam as *mut HWND) = hwnd };
            return 0; // 找到即停
        }
        1
    }

    unsafe {
        // windows-sys 0.52 的 HWND 是 isize 裸句柄，0 = 空
        let mut found: HWND = 0;
        EnumWindows(Some(enum_proc), &mut found as *mut HWND as LPARAM);
        if found == 0 {
            // 窗口未就绪（理论上首帧已存在）：下次启动再装，不影响其他路径
            ENDSESSION_INSTALLED.store(false, Ordering::SeqCst);
            return;
        }
        SetWindowSubclass(found, Some(subclass_proc), 1, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ports_各格式() {
        assert_eq!(loopback_ports("127.0.0.1:1080"), vec![1080]);
        assert_eq!(loopback_ports("localhost:8080"), vec![8080]);
        assert_eq!(loopback_ports("[::1]:1080"), vec![1080]);
        assert_eq!(
            loopback_ports("socks=127.0.0.1:1080;http=127.0.0.1:8081"),
            vec![1080, 8081]
        );
        assert_eq!(loopback_ports("127.0.0.1:1;127.0.0.1:1"), vec![1], "去重");
        // 非回环 / 无端口 / 空串
        assert!(loopback_ports("10.0.0.5:8080").is_empty());
        assert!(loopback_ports("proxy.corp.example:8080").is_empty());
        assert!(loopback_ports("127.0.0.1").is_empty());
        assert!(loopback_ports("").is_empty());
    }

    #[test]
    fn port_has_listener_活死判定() {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(port_has_listener(port), "有监听应判活");
        drop(l);
        assert!(!port_has_listener(port), "关闭后应判死");
    }

    #[test]
    fn snapshot_is_dead_判定() {
        let dead = |_p: u16| false; // 全部无监听
        let live = |_p: u16| true; // 全部有监听
        // 启用 + 回环 + 无监听 = 死（本工具制造的残留形态）
        assert!(snapshot_is_dead(Some(1), Some("127.0.0.1:1080"), dead));
        // 有监听（其他软件活代理或我们自己在跑）= 不动
        assert!(!snapshot_is_dead(Some(1), Some("127.0.0.1:1080"), live));
        // 非回环 / 未启用 / 缺值 = 不动
        assert!(!snapshot_is_dead(Some(1), Some("10.0.0.5:8080"), dead));
        assert!(!snapshot_is_dead(Some(0), Some("127.0.0.1:1080"), dead));
        assert!(!snapshot_is_dead(None, Some("127.0.0.1:1080"), dead));
        assert!(!snapshot_is_dead(Some(1), None, dead));
        assert!(!snapshot_is_dead(Some(1), Some(""), dead));
        assert!(!snapshot_is_dead(Some(1), Some("127.0.0.1"), dead));
    }
}
