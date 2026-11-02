//! Linux 系统代理（J 修复，仅 target_os = "linux" 编译）：GNOME gsettings +
//! KDE kioslaverc 的**快照-恢复**语义，对齐 windows_proxy——
//! enable 前快照用户原有配置，disable 原样写回；启动自愈只清「回环 + 死端口」
//! 的本工具残留（不误伤用户/其他软件的代理配置）。
//!
//! 已知限制（本轮不解决）：全部同步 `Command::output()` 在 UI 线程执行
//! （enable 约 20 次 spawn ≈ 100-300ms）；后续可按 node_test_receiver 范式移后台。
//!
//! 快照采用 `gsettings get` 的**原始 GVariant 文本**原样 `set` 回——该文本是
//! 合法的 set 入参，规避引号/转义/空数组（`@as []`）重建问题；未定制键快照到
//! 默认值，写回默认值等效 reset。

const PROTOS: [&str; 4] = ["http", "https", "ftp", "socks"];

/// enable 前的用户原有代理配置快照（逐键 `gsettings get` 原始输出）。
#[derive(Default, Clone)]
pub(crate) struct SavedProxyState {
    mode: Option<String>,
    host_port: Vec<(Option<String>, Option<String>)>,
    ignore_hosts: Option<String>,
    kde_proxy_type: Option<String>,
    kde_socks: Option<String>,
}

static SAVED_STATE: std::sync::Mutex<Option<SavedProxyState>> = std::sync::Mutex::new(None);

fn lock_saved() -> std::sync::MutexGuard<'static, Option<SavedProxyState>> {
    SAVED_STATE.lock().unwrap_or_else(|p| p.into_inner())
}

/// gsettings 读取；失败（命令缺失 / schema 不存在）返回 None = 跳过 GNOME 后端
fn gsettings(args: &[&str]) -> Option<String> {
    std::process::Command::new("gsettings")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn gsettings_set(schema: &str, key: &str, value: &str) {
    let _ = std::process::Command::new("gsettings")
        .args(["set", schema, key, value])
        .output();
}

fn kreadconfig(key: &str) -> Option<String> {
    for tool in ["kreadconfig6", "kreadconfig5"] {
        if let Some(out) = std::process::Command::new(tool)
            .args([
                "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key,
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
        {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn kwriteconfig(key: &str, value: &str) {
    let tool = if std::env::var("KDE_SESSION_VERSION").unwrap_or_default() == "6" {
        "kwriteconfig6"
    } else {
        "kwriteconfig5"
    };
    let _ = std::process::Command::new(tool)
        .args(["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, value])
        .output();
}

fn kde_notify_reload() {
    let _ = std::process::Command::new("dbus-send")
        .args([
            "--type=signal",
            "/KIO/Scheduler",
            "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
            "string:",
        ])
        .output();
}

fn snapshot() -> Option<SavedProxyState> {
    let mode = gsettings(&["get", "org.gnome.system.proxy", "mode"])?;
    let mut host_port = Vec::with_capacity(PROTOS.len());
    for proto in PROTOS {
        let host = gsettings(&["get", &format!("org.gnome.system.proxy.{proto}"), "host"]);
        let port = gsettings(&["get", &format!("org.gnome.system.proxy.{proto}"), "port"]);
        host_port.push((host, port));
    }
    let ignore_hosts = gsettings(&["get", "org.gnome.system.proxy", "ignore-hosts"]);
    // KDE 两键可选：读不到（非 KDE / 工具缺失）→ None → 不写不还原 KDE
    let kde_proxy_type = kreadconfig("ProxyType");
    let kde_socks = kreadconfig("socksProxy");
    Some(SavedProxyState {
        mode: Some(mode),
        host_port,
        ignore_hosts,
        kde_proxy_type,
        kde_socks,
    })
}

/// GVariant 文本解码出的 mode 是否为 manual（`"'manual'"` 带引号形态）
fn mode_is_manual(mode: &str) -> bool {
    mode.trim().trim_matches('\'') == "manual"
}

/// GVariant 文本解码 host（`"'127.0.0.1'"` → `127.0.0.1`；`"@as []"`/`"''"` → None）
fn decode_host(v: &Option<String>) -> Option<String> {
    let v = v.as_deref()?.trim();
    if v.is_empty() || v.starts_with("@as") || v == "''" {
        return None;
    }
    let unq = v.trim_matches('\'');
    if unq.is_empty() {
        None
    } else {
        Some(unq.to_string())
    }
}

/// GVariant 文本解码端口（`"'1080'"` / `"1080"` → 1080）
fn decode_port(v: &Option<String>) -> Option<u16> {
    let v = v.as_deref()?.trim().trim_matches('\'');
    v.parse().ok()
}

/// 回环判定（死代理判据之一；与 windows_proxy 的回环白名单同语义）
fn is_loopback_host(h: &str) -> bool {
    h == "localhost" || h == "::1" || h.starts_with("127.")
}

/// 端口是否有监听（bind 成功 = 无监听；与 windows_proxy 同款探测）
fn port_has_listener(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
}

/// 死代理判定（纯函数，注入 is_live 便于单测）：mode=manual 且全部非空 host
/// 均回环 且对应端口全部无监听 → 本工具崩溃残留形态
fn snapshot_is_dead(s: &SavedProxyState, is_live: impl Fn(u16) -> bool) -> bool {
    let Some(mode) = s.mode.as_deref() else {
        return false;
    };
    if !mode_is_manual(mode) {
        return false;
    }
    let mut saw_entry = false;
    for (h, p) in &s.host_port {
        let Some(host) = decode_host(h) else { continue };
        saw_entry = true;
        if !is_loopback_host(&host) {
            return false; // 非回环 host：可能是用户自有代理，绝不动
        }
        if let Some(port) = decode_port(p) {
            if is_live(port) {
                return false; // 端口有监听：可能是用户自有的本地代理
            }
        }
    }
    saw_entry
}

fn write_manual(proxy_host: &str, proxy_port: &str) {
    gsettings_set("org.gnome.system.proxy", "mode", "manual");
    for proto in PROTOS {
        gsettings_set(
            &format!("org.gnome.system.proxy.{proto}"),
            "host",
            proxy_host,
        );
        gsettings_set(
            &format!("org.gnome.system.proxy.{proto}"),
            "port",
            proxy_port,
        );
    }
    gsettings_set(
        "org.gnome.system.proxy",
        "ignore-hosts",
        "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']",
    );
}

fn write_kde(proxy_host: &str, proxy_port: &str) {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if !(desktop.contains("KDE") || desktop.contains("plasma")) {
        return;
    }
    kwriteconfig("ProxyType", "1");
    kwriteconfig("socksProxy", &format!("socks://{proxy_host}:{proxy_port}"));
    kde_notify_reload();
}

fn restore_kde(s: &SavedProxyState) {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    if !(desktop.contains("KDE") || desktop.contains("plasma")) {
        return;
    }
    if let Some(t) = &s.kde_proxy_type {
        kwriteconfig("ProxyType", t);
    }
    if let Some(v) = &s.kde_socks {
        kwriteconfig("socksProxy", v);
    }
    kde_notify_reload();
}

fn restore(s: &SavedProxyState) {
    if let Some(mode) = &s.mode {
        gsettings_set("org.gnome.system.proxy", "mode", mode);
    }
    for (proto, (h, p)) in PROTOS.iter().zip(&s.host_port) {
        if let Some(h) = h {
            gsettings_set(&format!("org.gnome.system.proxy.{proto}"), "host", h);
        }
        if let Some(p) = p {
            gsettings_set(&format!("org.gnome.system.proxy.{proto}"), "port", p);
        }
    }
    if let Some(ig) = &s.ignore_hosts {
        gsettings_set("org.gnome.system.proxy", "ignore-hosts", ig);
    }
    restore_kde(s);
}

/// 开启系统代理：快照（修复式保存——旧值本身是死代理残留时改存默认态）后写入
pub(crate) fn enable(proxy_host: &str, proxy_port: &str) {
    let Some(mut saved) = snapshot() else {
        return; // 非 GNOME 环境：跳过，不产生半写状态
    };
    if snapshot_is_dead(&saved, port_has_listener) {
        eprintln!(
            "[LinuxProxy] 启用前发现旧系统代理指向无监听的本机端口——停机将恢复为直接连接"
        );
        saved.mode = Some("'none'".to_string());
    }
    *lock_saved() = Some(saved);
    write_manual(proxy_host, proxy_port);
    write_kde(proxy_host, proxy_port);
}

/// 停止系统代理：恢复 enable 前的快照。从未 enable（无快照）= **绝不动用户配置**
/// （崩溃残留由下次启动的 cleanup_stale_system_proxy 兜底）
pub(crate) fn disable() {
    let Some(s) = lock_saved().take() else {
        return;
    };
    restore(&s);
}

pub static STALE_PROXY_CLEANED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 启动自愈（main 早期调用一次）：mode=manual + 全回环 + 全死端口 → 恢复直连
/// （mode 置 none + 四协议 host/port `gsettings reset`；KDE ProxyType 置 0）。
/// 判据安全边际与 windows_proxy 一致：非回环 / 端口有监听一律不动。
pub fn cleanup_stale_system_proxy() {
    let Some(s) = snapshot() else {
        return;
    };
    if !snapshot_is_dead(&s, port_has_listener) {
        return;
    }
    gsettings_set("org.gnome.system.proxy", "mode", "none");
    for proto in PROTOS {
        let _ = std::process::Command::new("gsettings")
            .args(["reset", &format!("org.gnome.system.proxy.{proto}"), "host"])
            .output();
        let _ = std::process::Command::new("gsettings")
            .args(["reset", &format!("org.gnome.system.proxy.{proto}"), "port"])
            .output();
    }
    if s.kde_proxy_type.is_some() {
        kwriteconfig("ProxyType", "0");
        kde_notify_reload();
    }
    STALE_PROXY_CLEANED.store(true, std::sync::atomic::Ordering::Relaxed);
    eprintln!("[LinuxProxy] 启动自愈：清除崩溃残留的系统代理指向（本机回环死端口）");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead_state() -> SavedProxyState {
        SavedProxyState {
            mode: Some("'manual'".to_string()),
            host_port: PROTOS
                .iter()
                .map(|_| (Some("'127.0.0.1'".to_string()), Some("'1080'".to_string())))
                .collect(),
            ignore_hosts: Some("@as []".to_string()),
            kde_proxy_type: None,
            kde_socks: None,
        }
    }

    #[test]
    fn mode_decode() {
        assert!(mode_is_manual("'manual'"));
        assert!(mode_is_manual("manual"));
        assert!(!mode_is_manual("'none'"));
        assert!(!mode_is_manual("@as []"));
    }

    #[test]
    fn host_port_decode() {
        assert_eq!(
            decode_host(&Some("'127.0.0.1'".to_string())).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(decode_host(&Some("@as []".to_string())), None);
        assert_eq!(decode_host(&Some("''".to_string())), None);
        assert_eq!(decode_port(&Some("'1080'".to_string())), Some(1080));
        assert_eq!(decode_port(&Some("1080".to_string())), Some(1080));
        assert_eq!(decode_port(&Some("@as []".to_string())), None);
    }

    #[test]
    fn stale_dead_state_detected() {
        assert!(snapshot_is_dead(&dead_state(), |_| false), "全回环+全死端口");
    }

    #[test]
    fn live_port_or_remote_host_blocks_cleanup() {
        let mut s = dead_state();
        assert!(!snapshot_is_dead(&s, |_| true), "端口有监听 → 不清");
        s.host_port[0] = (Some("'192.168.1.1'".to_string()), Some("'8080'".to_string()));
        assert!(
            !snapshot_is_dead(&s, |_| false),
            "非回环 host = 用户自有代理 → 不清"
        );
    }

    #[test]
    fn non_manual_mode_never_cleaned() {
        let mut s = dead_state();
        s.mode = Some("'none'".to_string());
        assert!(!snapshot_is_dead(&s, |_| false));
        s.mode = None;
        assert!(!snapshot_is_dead(&s, |_| false));
    }

    #[test]
    fn empty_hosts_not_cleaned() {
        // 全空 host（非本工具形态）→ 不清（安全边际）
        let mut s = dead_state();
        s.host_port = s.host_port.into_iter().map(|_| (None, None)).collect();
        assert!(!snapshot_is_dead(&s, |_| false));
    }
}
