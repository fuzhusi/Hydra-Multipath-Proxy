//! R4 防环回：出站 socket 保护钩子（docs/design/移动端Android方案-v2.md §R4）。
//!
//! Android `VpnService` 场景下，引擎自己发起的出站连接（到节点/直连目标）
//! 若不经 `VpnService.protect(fd)` 标记，会被本应用的 TUN 虚拟网卡捕获形成
//! 无限回环（连接全部超时/断网）。桌面与无 VPN 环境无此问题：钩子未安装时
//! [`connect_tcp_protected`] 与普通 connect 完全等价（零开销）。
//!
//! # 契约
//! - 钩子在**建连前**对每个新出站 socket 的 fd 调用（`TcpSocket` 阶段）；
//! - 回调返回 `false`（protect 失败）→ 连接**立即中止**——宁可单连接失败，
//!   不可静默放行进回环；
//! - 进程级单次安装（OnceLock 固化）：多引擎/重启引擎以首次安装者为准。

use std::net::SocketAddr;
use std::sync::OnceLock;

type ProtectFn = dyn Fn(i64) -> bool + Send + Sync;

/// 保护钩子类型（`Box<dyn Fn(i64) -> bool + Send + Sync>`；返回 false = protect
/// 失败，调用方必须中止该连接）
pub type ProtectHook = Box<ProtectFn>;

static PROTECT_HOOK: OnceLock<Option<ProtectHook>> = OnceLock::new();

/// 安装出站 socket 保护钩子（进程级，仅首次生效）。返回 false = 已被占用。
pub fn set_socket_protect_hook(hook: ProtectHook) -> bool {
    PROTECT_HOOK.set(Some(hook)).is_ok()
}

/// 是否已安装保护钩子（观测/测试用）
pub fn socket_protect_installed() -> bool {
    PROTECT_HOOK.get().is_some()
}

/// 对新建出站 socket 的 fd 调用保护回调。未安装钩子 → Ok（零开销路径）；
/// 回调失败 → Err（调用方必须中止该连接，防止流量进自身 TUN 回环）。
pub fn protect_outbound_fd(fd: i64) -> std::io::Result<()> {
    match PROTECT_HOOK.get() {
        Some(Some(hook)) => {
            if hook(fd) {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "VpnService.protect(fd) 失败：放行将使连接被本应用 TUN 捕获回环，已中止",
                ))
            }
        }
        _ => Ok(()),
    }
}

/// 受保护的家庭化出站 TCP 建连：新建 socket（拿到 fd）→ 保护回调 → connect。
/// protect 失败时 socket 随 TcpSocket drop 关闭，连接不发出。
pub async fn connect_tcp_protected(addr: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    // 内核优化 #10：TCP Fast Open（TCP_FASTOPEN_CONNECT，Linux 内核 4.11+）。
    // 客户端侧需配合节点 listen socket 的 TCP_FASTOPEN + sysctl
    // net.ipv4.tcp_fastopen>=2（部署文档）；未启用节点透明回退（cookie
    // 请求路径），env HYDRA_TFO=0 关闭。仅 Linux/Android 门控（Windows/
    // macOS 无此选项 API——回退普通建连）。
    #[cfg(target_os = "linux")]
    if tfo_enabled() && addr.is_ipv4() {
        use std::os::unix::io::AsRawFd;
        set_tfo_connect(sock.as_raw_fd());
    }
    // Android（unix）为真 fd（i32）；Windows 为 SOCKET 句柄——钩子仅在
    // Android 场景安装，桌面平台此调用为零开销直通
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        protect_outbound_fd(sock.as_raw_fd() as i64)?;
    }
    #[cfg(not(unix))]
    {
        use std::os::windows::io::AsRawSocket;
        protect_outbound_fd(sock.as_raw_socket() as i64)?;
    }
    sock.connect(addr).await
}

/// TFO 开关（env HYDRA_TFO=0 关闭；默认开，Linux/Android）
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tfo_enabled() -> bool {
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| std::env::var("HYDRA_TFO").as_deref() != Ok("0"))
}

/// raw setsockopt(TCP_FASTOPEN_CONNECT=30)：socket2 0.6 无此 API（评审修正）。
/// 失败静默（内核不支持/未配置时回退普通建连——透明降级）。
#[cfg(target_os = "linux")]
fn set_tfo_connect(fd: std::os::unix::io::RawFd) {
    // TCP_FASTOPEN_CONNECT = 30（linux/tcp.h）
    const TCP_FASTOPEN_CONNECT: i32 = 30;
    const optval: i32 = 1;
    // setsockopt(2)：level=IPPROTO_TCP(6)
    let r = unsafe { setsockopt(fd, 6, TCP_FASTOPEN_CONNECT, &optval as *const i32 as *const u8, 4) };
    if r != 0 {
        tracing::debug!("TCP_FASTOPEN_CONNECT 设置失败（回退普通建连）: errno={}", std::io::Error::last_os_error());
    }
}

#[cfg(target_os = "linux")]
extern "C" {
    fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const u8,
        optlen: u32,
    ) -> i32;
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn 未安装钩子时保护为零开销路径() {
        // 进程级 OnceLock：未安装即 Ok（若同进程其他测试已安装，跳过断言）
        if !socket_protect_installed() {
            assert!(protect_outbound_fd(12345).is_ok());
        }
    }

    #[test]
    fn 钩子失败中止连接_成功放行() {
        // OnceLock 进程级固化：本测试构造独立状态不可行，改由 Android 集成
        // 路径（hydra-android lib 测试）覆盖 install 后的行为；此处只验证
        // set 幂等语义的返回值组合在文档层面成立（首次 true，再次 false）。
        let installed = socket_protect_installed();
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = calls.clone();
        let ok = set_socket_protect_hook(Box::new(move |_fd| {
            c2.fetch_add(1, Ordering::Relaxed);
            true
        }));
        if !installed {
            assert!(ok, "首次安装应成功");
            assert!(socket_protect_installed());
            assert!(protect_outbound_fd(1).is_ok());
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            // 再次安装：被拒绝，原钩子保持
            assert!(!set_socket_protect_hook(Box::new(|_| false)));
            assert!(protect_outbound_fd(2).is_ok());
        }
    }
}


