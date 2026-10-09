//! DNS AAAA 查询本地过滤：v4-only 节点的上游降噪。
//!
//! # 问题背景（线上实测：单节点单日 1.5 万条错误日志）
//! TUN/VPN 模式下客户端系统 DNS 经 UDP 中继穿透查询，应答中的 AAAA 记录
//! 原样回流客户端；应用拿 v6 地址建连 → TUN 以**字面 v6 目标**交节点 →
//! 节点无 IPv6 出口路由 → `ENETUNREACH (os error 101)` 秒败。功能上客户端
//! 会回落 v4，但每连接一条 error 日志，噪音掩盖真问题。
//!
//! # 方案：AAAA 查询 → 本地合成 NODATA 应答
//! 节点对目标端口 53 的上行 DNS 查询，若 `QR=0`、单问题且 `qtype=AAAA`，
//! 直接回**空答案的 NOERROR（NODATA）**：不建 UDP 会话、不产生任何上游
//! 流量。客户端 OS 解析器收到「域名无 AAAA」后回落 A 记录——v6 目标从
//! 源头消失。这是标准解析器行为（RFC 2308 NODATA，无 SOA 时负缓存 TTL=0）。
//!
//! # 判定与开关
//! - 默认自动：节点无 IPv6 出口路由（UDP connect 探测，进程级缓存一次）
//!   时开启；有 v6 路由的节点不过滤，保持双栈能力；
//! - `HYDRA_DNS_FILTER_AAAA=1` 强制开启 / `=0` 强制关闭（显式覆盖自动判定；
//!   其他值视为无效配置，告警并回落自动判定）。
//!
//! # 已知局限（有逃生门即不阻塞）
//! - 探测只验证「有 v6 默认路由」：黑洞路由（路由在但出口不通）的节点
//!   误判为有出口、过滤不生效（此时仍有原 ENETUNREACH 日志，可用
//!   `HYDRA_DNS_FILTER_AAAA=1` 强制开启）；
//! - 探测结果进程级缓存：运行中获得 v6 的节点需重启才解除过滤；
//! - 客户端侧若挂严格 DNSSEC 验证转发器（如 unbound DNSSEC=yes），无
//!   SOA/NSEC 证明的合成 NODATA 会被判 bogus → SERVFAIL（TUN 场景 stub
//!   解析器自身不验证，影响面小；`HYDRA_DNS_FILTER_AAAA=0` 逃生）。
//!
//! 解析失败/非标准查询一律放行（fail-open），不干扰正常 DNS 转发。

use std::net::SocketAddr;
use std::sync::OnceLock;

/// AAAA 记录类型号（RFC 3596）
const QTYPE_AAAA: u16 = 28;
/// IN class
const QCLASS_IN: u16 = 1;
/// DNS 首部固定长度
const DNS_HEADER_LEN: usize = 12;

/// 节点是否具备 IPv6 出口路由（进程级探测一次）。
///
/// UDP socket `connect()` 只做路由查找、不发任何包：无 v6 栈/无 v6 默认路由
/// 时立即 `EADDRNOTAVAIL`/`ENETUNREACH`——恰好对应线上 ENETUNREACH os error 101
/// 的失败模式。探测目标地址本身无关紧要（不产生流量）。
pub fn has_v6_route() -> bool {
    static V6_ROUTE: OnceLock<bool> = OnceLock::new();
    *V6_ROUTE.get_or_init(|| {
        // 必须探全球单播地址（默认路由 ::/0 匹配）；::1 回环任何 v6 栈都有，
        // 探它会把「有栈无出口」的 v4-only VPS 误判为有路由。
        if let Ok(probe) = "2001:4860:4860::8888:53".parse::<SocketAddr>() {
            std::net::UdpSocket::bind("[::]:0")
                .and_then(|s| s.connect(probe))
                .is_ok()
        } else {
            false
        }
    })
}

/// AAAA 过滤是否启用：`HYDRA_DNS_FILTER_AAAA` 显式覆盖（仅认 `0`/`1`，
/// 其他值告警回落自动判定），否则自动（无 v6 出口路由 → 开启）。
/// 进程级缓存一次。
pub fn aaaa_filter_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| match std::env::var("HYDRA_DNS_FILTER_AAAA") {
        Ok(v) => match v.trim() {
            "0" => false,
            "1" => true,
            _ => {
                tracing::warn!("HYDRA_DNS_FILTER_AAAA={v:?} 无效（仅认 0/1），回落自动判定");
                !has_v6_route()
            }
        },
        Err(_) => !has_v6_route(),
    })
}

/// 目标串（`host:port`，host 可为域名/v4/v6 方括号）的端口。
/// 仅用于「是否 DNS 端口」的启发式判定，取**最后一个**冒号后的段。
pub(crate) fn target_port(target: &str) -> Option<u16> {
    target.rsplit_once(':')?.1.parse().ok()
}

/// DNS 查询检测：`msg` 是否为「opcode=QUERY(0)、单问题、qtype=AAAA、
/// qclass=IN」的查询报文（`QR=0`）。命中返回问题节结束偏移（合成应答的
/// 截断点）；其余一律 `None` 放行——NOTIFY/UPDATE/多问题/畸形/响应报文
/// 不做任何改写。
pub(crate) fn aaaa_query_question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < DNS_HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 != 0 {
        return None; // 响应报文（转发路径原样处理）
    }
    if flags & 0x7800 != 0 {
        return None; // opcode 非 QUERY（NOTIFY/UPDATE 等服务器间流量，不掺和）
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount != 1 {
        return None; // 零/多问题：不在本过滤职责内
    }
    let mut off = DNS_HEADER_LEN;
    // 跳过 QNAME：标签序列，`0x00` 结束或压缩指针（`11xxxxxx`，指针即名字
    // 结束，RFC 1035 4.1.4）。逐字节边界检查，指针天然有界（名字终结）。
    loop {
        // `?` 即放行语义：问题节被截断的畸形报文不处理（None）
        let len = *msg.get(off)?;
        if len & 0xC0 == 0xC0 {
            off += 2;
            break;
        }
        if len == 0 {
            off += 1;
            break;
        }
        off += 1 + len as usize;
    }
    let qtail = msg.get(off..off + 4)?;
    let qtype = u16::from_be_bytes([qtail[0], qtail[1]]);
    let qclass = u16::from_be_bytes([qtail[2], qtail[3]]);
    if qtype != QTYPE_AAAA || qclass != QCLASS_IN {
        return None;
    }
    Some(off + 4)
}

/// 由查询报文的「首部 + 问题节」（`[..q_end]`）合成 NODATA 应答：
/// ID/opcode/RD 原样保留，置 `QR=1`、`RA=1`，`RCODE=0`、AN/NS/AR=0。
/// 无 SOA → 客户端负缓存 TTL=0（RFC 2308），后续查询仍会到达本节点
/// （本地应答零上游成本，可接受）。
pub(crate) fn synthesize_nodata(query: &[u8], q_end: usize) -> Vec<u8> {
    let mut out = query[..q_end.min(query.len())].to_vec();
    if out.len() >= DNS_HEADER_LEN {
        // 字节 2：QR(0x80)=1，保留 opcode(0x78)与 RD(0x01)，清 AA/TC
        out[2] = (out[2] & 0x79) | 0x80;
        // 字节 3：RA(0x80)=1，RCODE=0，清 Z/AD/CD
        out[3] = 0x80;
        // ANCOUNT/NSCOUNT/ARCOUNT 归零（QDCOUNT 保留）
        out[6..DNS_HEADER_LEN].fill(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 DNS 查询：头部 + 问题节（不压缩）
    fn query(qtype: u16, name: &[&str]) -> Vec<u8> {
        let mut m = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    #[test]
    fn aaaa_query_detected_with_question_end() {
        let q = query(28, &["www", "example", "com"]);
        let end = aaaa_query_question_end(&q).expect("AAAA 查询应命中");
        assert_eq!(end, q.len());
        // 截断点即问题节末尾
        assert_eq!(&q[..end], &q[..]);
    }

    #[test]
    fn a_records_and_responses_pass_through() {
        assert!(aaaa_query_question_end(&query(1, &["a", "b"])).is_none()); // A 查询
        let mut resp = query(28, &["a"]);
        resp[2] = 0x81; // QR=1
        assert!(aaaa_query_question_end(&resp).is_none()); // 响应放行
        let multi = {
            let mut m = query(28, &["a"]);
            m[5] = 2; // QDCOUNT=2
            m
        };
        assert!(aaaa_query_question_end(&multi).is_none());
    }

    #[test]
    fn non_query_opcodes_pass_through() {
        // opcode=UPDATE(5)（DDNS）：问题节 qtype 恰为 AAAA 也不得伪造应答
        let mut upd = query(28, &["example", "com"]);
        upd[2] = (upd[2] & 0x87) | 0x28; // opcode=5，保持 QR=0
        assert!(aaaa_query_question_end(&upd).is_none());
        // opcode=NOTIFY(4) 同理
        let mut notify = query(28, &["zone"]);
        notify[2] = (notify[2] & 0x87) | 0x20;
        assert!(aaaa_query_question_end(&notify).is_none());
    }

    #[test]
    fn malformed_inputs_return_none() {
        assert!(aaaa_query_question_end(&[]).is_none());
        assert!(aaaa_query_question_end(&[0u8; 11]).is_none()); // 短于首部
        let trunc = {
            // 问题节被截断
            let mut q = query(28, &["abc"]);
            q.truncate(q.len() - 3);
            q
        };
        assert!(aaaa_query_question_end(&trunc).is_none());
    }

    #[test]
    fn compressed_qname_handled() {
        // QNAME 以压缩指针（0xC00C）开头：合法（虽少见），名字 2 字节终结
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C];
        m.extend_from_slice(&28u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(aaaa_query_question_end(&m), Some(m.len()));
    }

    #[test]
    fn nodata_reply_preserves_id_and_question() {
        let q = query(28, &["x", "y"]);
        let end = aaaa_query_question_end(&q).unwrap();
        let r = synthesize_nodata(&q, end);
        assert_eq!(r.len(), end); // 仅头部+问题节
        assert_eq!(&r[..2], &[0xAB, 0xCD]); // ID 原样
        assert_eq!(r[2] & 0x80, 0x80); // QR=1
        assert_eq!(r[2] & 0x01, 0x01); // RD 保留
        assert_eq!(r[3], 0x80); // RA=1，RCODE=0
        assert_eq!(&r[4..6], &[0, 1]); // QDCOUNT=1
        assert_eq!(&r[6..12], &[0; 6]); // AN/NS/AR=0
                                        // 问题节逐字节一致
        assert_eq!(&r[12..], &q[12..end]);
    }

    #[test]
    fn nodata_reply_oversized_q_end_is_safe() {
        let q = query(28, &["x"]);
        let r = synthesize_nodata(&q, q.len() + 100); // 越界截断不 panic
        assert_eq!(r.len(), q.len());
    }

    #[test]
    fn target_port_parses_all_target_shapes() {
        assert_eq!(target_port("8.8.8.8:53"), Some(53));
        assert_eq!(target_port("dns.google:53"), Some(53));
        assert_eq!(target_port("[2001:db8::1]:53"), Some(53));
        assert_eq!(target_port("[::1]:853"), Some(853));
        assert_eq!(target_port("8.8.8.8:443"), Some(443)); // 非 DNS 端口由调用方判断
        assert_eq!(target_port("no-port"), None);
        assert_eq!(target_port("host:port"), None);
    }

    #[test]
    fn probe_functions_callable() {
        // 环境相关（有无 v6 栈），只验证可调用且互斥语义成立
        let _ = has_v6_route();
        let _ = aaaa_filter_enabled();
    }
}
