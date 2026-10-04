//! STUN 客户端离线单测：手工构造合法/畸形响应字节，验证解析与拒绝逻辑
//! （不需要联网）。联网冒烟用例标 `#[ignore]`，CI 只跑离线。

use hydra_node::stun::{
    build_binding_request, discover_public_addr, parse_binding_response, StunError, TransactionId,
    MAGIC_COOKIE,
};

/// 编码 XOR-MAPPED-ADDRESS 属性值（IPv4）：[保留 1B][family 1B][xport 2B][xaddr 4B]
fn xor_mapped_v4_value(ip: [u8; 4], port: u16) -> Vec<u8> {
    let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
    let xip = u32::from_be_bytes(ip) ^ MAGIC_COOKIE;
    let mut v = vec![0u8, 0x01];
    v.extend_from_slice(&xport.to_be_bytes());
    v.extend_from_slice(&xip.to_be_bytes());
    v
}

/// 编码 XOR-MAPPED-ADDRESS 属性值（IPv6）：掩码 = MAGIC_COOKIE || txn_id
fn xor_mapped_v6_value(ip16: [u8; 16], port: u16, txn: &TransactionId) -> Vec<u8> {
    let xport = port ^ (MAGIC_COOKIE >> 16) as u16;
    let mut v = vec![0u8, 0x02];
    v.extend_from_slice(&xport.to_be_bytes());
    for i in 0..16 {
        v.push(ip16[i]);
    }
    // 就地异或：前 4 字节对 cookie，后 12 字节对事务 ID
    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
    for i in 0..4 {
        v[4 + i] ^= cookie_bytes[i];
    }
    for i in 0..12 {
        v[8 + i] ^= txn.0[i];
    }
    v
}

/// 通用属性编码（值自动 4 字节对齐填充）
fn attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&attr_type.to_be_bytes());
    a.extend_from_slice(&(value.len() as u16).to_be_bytes());
    a.extend_from_slice(value);
    while a.len() % 4 != 0 {
        a.push(0);
    }
    a
}

/// 构造 Binding Success Response 消息头 + 属性区
fn craft_response(txn: &TransactionId, attrs: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&0x0101u16.to_be_bytes());
    m.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    m.extend_from_slice(&txn.0);
    m.extend_from_slice(attrs);
    m
}

const ATTR_XOR_MAPPED: u16 = 0x0020;

#[test]
fn binding_request_wire_format() {
    let txn = TransactionId([7u8; 12]);
    let req = build_binding_request(&txn);
    assert_eq!(req.len(), 20);
    assert_eq!(&req[0..2], &0x0001u16.to_be_bytes()); // Binding Request
    assert_eq!(&req[2..4], &0u16.to_be_bytes()); // 无属性
    assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
    assert_eq!(&req[8..20], &txn.0[..]);
}

#[test]
fn transaction_ids_are_random() {
    let a = TransactionId::random();
    let b = TransactionId::random();
    assert_ne!(a, b, "两次随机事务 ID 不应相同");
    assert_eq!(a.0.len(), 12);
}

#[test]
fn valid_response_v4_parses() {
    let txn = TransactionId::random();
    let attrs = attr(
        ATTR_XOR_MAPPED,
        &xor_mapped_v4_value([203, 0, 113, 7], 45000),
    );
    let resp = craft_response(&txn, &attrs);
    let addr = parse_binding_response(&resp, &txn).unwrap();
    assert_eq!(addr.to_string(), "203.0.113.7:45000");
}

#[test]
fn valid_response_v6_parses() {
    let txn = TransactionId::random();
    let mut ip = [0x20u8; 16];
    ip[15] = 0x09;
    let attrs = attr(ATTR_XOR_MAPPED, &xor_mapped_v6_value(ip, 3478, &txn));
    let resp = craft_response(&txn, &attrs);
    let addr = parse_binding_response(&resp, &txn).unwrap();
    let v6 = match addr {
        std::net::SocketAddr::V6(v6) => v6,
        other => panic!("期望 IPv6，得到 {}", other),
    };
    assert_eq!(v6.port(), 3478);
    assert_eq!(v6.ip().octets(), ip);
}

#[test]
fn transaction_mismatch_rejected() {
    let txn = TransactionId([1u8; 12]);
    let other = TransactionId([2u8; 12]);
    let attrs = attr(ATTR_XOR_MAPPED, &xor_mapped_v4_value([1, 2, 3, 4], 80));
    let resp = craft_response(&txn, &attrs);
    // 响应属于 txn，用 other 去校验 = 拒绝（网络上应丢弃）
    assert_eq!(
        parse_binding_response(&resp, &other),
        Err(StunError::TransactionMismatch)
    );
}

#[test]
fn malformed_packets_rejected() {
    let txn = TransactionId::random();
    let attrs = attr(ATTR_XOR_MAPPED, &xor_mapped_v4_value([9, 9, 9, 9], 1));
    let resp = craft_response(&txn, &attrs);

    // 短于消息头
    assert!(matches!(
        parse_binding_response(&resp[..10], &txn),
        Err(StunError::Malformed("短于 20 字节消息头"))
    ));
    // 空包
    assert!(parse_binding_response(&[], &txn).is_err());
    // MAGIC_COOKIE 错误
    let mut bad_cookie = resp.clone();
    bad_cookie[4] = 0x00;
    assert!(matches!(
        parse_binding_response(&bad_cookie, &txn),
        Err(StunError::Malformed(_))
    ));
    // 非成功响应（0x0111 = Binding Error Response）
    let mut err_type = resp.clone();
    err_type[0] = 0x01;
    err_type[1] = 0x11;
    assert_eq!(
        parse_binding_response(&err_type, &txn),
        Err(StunError::NotSuccessResponse(0x0111))
    );
    // msg_len 声明超出实际数据报
    let mut bad_len = resp.clone();
    bad_len[3] = 0xFF;
    assert!(matches!(
        parse_binding_response(&bad_len, &txn),
        Err(StunError::Malformed("msg_len 超出数据报实际长度"))
    ));
    // 属性头不完整（属性区只剩 3 字节）
    let truncated_header = craft_response(&txn, &[0x00, 0x20, 0x00]);
    assert!(matches!(
        parse_binding_response(&truncated_header, &txn),
        Err(StunError::Malformed("属性头不完整"))
    ));
    // 属性值声明 8 字节但实际只带 4 字节
    let truncated_value = craft_response(&txn, &[0x00, 0x20, 0x00, 0x08, 1, 2, 3, 4]);
    assert!(matches!(
        parse_binding_response(&truncated_value, &txn),
        Err(StunError::Malformed("属性值超出消息边界"))
    ));
}

#[test]
fn unknown_attributes_are_skipped() {
    let txn = TransactionId::random();
    // SOFTWARE (0x8022) 在前，XOR-MAPPED-ADDRESS 在后
    let software = attr(0x8022, b"hydra-node");
    let xor = attr(
        ATTR_XOR_MAPPED,
        &xor_mapped_v4_value([198, 51, 100, 7], 1234),
    );
    let resp = craft_response(&txn, &[software, xor].concat());
    let addr = parse_binding_response(&resp, &txn).unwrap();
    assert_eq!(addr.to_string(), "198.51.100.7:1234");
}

#[test]
fn fingerprint_attribute_is_not_required() {
    // FINGERPRINT (0x8028) 可选：本实现跳过不校验 CRC32（RFC5389 §6 仅为可选机制）
    let txn = TransactionId::random();
    let xor = attr(ATTR_XOR_MAPPED, &xor_mapped_v4_value([192, 0, 2, 33], 5));
    let fp = attr(0x8028, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let resp = craft_response(&txn, &[xor, fp].concat());
    assert_eq!(
        parse_binding_response(&resp, &txn).unwrap().to_string(),
        "192.0.2.33:5"
    );
}

#[test]
fn response_without_xor_mapped_rejected() {
    let txn = TransactionId::random();
    let software = attr(0x8022, b"other-stun");
    let resp = craft_response(&txn, &software);
    assert_eq!(
        parse_binding_response(&resp, &txn),
        Err(StunError::NoMappedAddress)
    );
}

#[test]
fn trailing_bytes_beyond_msg_len_ignored() {
    // 数据报尾部有额外字节（某些链路填充）时只读 msg_len 范围
    let txn = TransactionId::random();
    let xor = attr(
        ATTR_XOR_MAPPED,
        &xor_mapped_v4_value([100, 64, 0, 1], 65535),
    );
    let mut resp = craft_response(&txn, &xor);
    resp.extend_from_slice(&[0xFF; 16]);
    let addr = parse_binding_response(&resp, &txn).unwrap();
    assert_eq!(addr.to_string(), "100.64.0.1:65535");
}

#[test]
fn bad_address_family_rejected() {
    let txn = TransactionId::random();
    let mut value = vec![0u8, 0x99]; // 未知地址族
    value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let attrs = attr(ATTR_XOR_MAPPED, &value);
    let resp = craft_response(&txn, &attrs);
    assert!(matches!(
        parse_binding_response(&resp, &txn),
        Err(StunError::Malformed("未知地址族"))
    ));
}

/// 联网冒烟（默认忽略）：Google 公共 STUN，验证端到端公网地址发现。
/// 运行: cargo test -p hydra-node --test test_stun -- --ignored
#[tokio::test]
#[ignore = "联网冒烟：需要外网可达 stun.l.google.com:19302"]
async fn online_smoke_google_stun() {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = ("stun.l.google.com", 19302)
        .to_socket_addrs()
        .expect("DNS 解析失败")
        .collect();
    let server = addrs.into_iter().next().expect("无可用地址");
    let public = discover_public_addr(server)
        .await
        .expect("公网地址发现失败");
    assert!(!public.ip().is_unspecified());
    assert!(!public.ip().is_loopback());
    println!("STUN 冒烟: 公网映射地址 = {}", public);
}
