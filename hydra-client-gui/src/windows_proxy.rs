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
    let saved = SavedProxyState {
        proxy_enable: key.get_value("ProxyEnable").ok(),
        proxy_server: key.get_value("ProxyServer").ok(),
        proxy_override: key.get_value("ProxyOverride").ok(),
        autoconfig_url: key.get_value("AutoConfigURL").ok(),
    };
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
