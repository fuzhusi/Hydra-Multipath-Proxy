//! 批次 B0：UDP 中继链路 criterion 基线基准。
//!
//! 三个基准面（后续批次 B1/B2/B3 优化以此表为前后对比基线，数字随代码
//! 变化同步更新 benches/README.md）：
//! ① udp_relay 会话帧构造/解析往返（hydra_protocol::udp_frame，payload 1200B
//!    ≈ 典型 MTU 数据报；往返经 block_on——附 block_on 空转对照组供校准）；
//! ② RFC 1071 checksum16（实现位于 hydra-client/src/tun.rs，B2 单遍化基线）；
//! ③ 路由 decide（RuleEngine::builtin_cn，GeoIP-CN 命中 114.114.114.114 与
//!    未命中 8.8.8.8 两样例；每连接建连一次的热路径）。
//!
//! 分配计数：`cargo bench --features bench-alloc` 时启用计数分配器
//! （#[global_allocator] 仅本 feature 门控，不影响生产分配器），每组基准
//! 附加测量 allocs/op 与 bytes/op（criterion 计时之外的独立循环测量，
//! 结果以 `alloc/op` 行打印，随基准输出一同出现）。

#[cfg(feature = "bench-alloc")]
mod counting_alloc {
    //! 计数分配器（仅 bench-alloc feature 启用）：包裹 System 统计
    //! 分配次数与字节；基准组用 take()/snapshot() 差分得到 per-op 数据。
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub static ALLOCS: AtomicUsize = AtomicUsize::new(0);
    pub static BYTES: AtomicUsize = AtomicUsize::new(0);

    pub struct CountingAlloc;

    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            System.alloc(layout)
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout)
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(new_size.saturating_sub(layout.size()), Ordering::Relaxed);
            System.realloc(ptr, layout, new_size)
        }
    }

    /// 差分快照
    pub fn snapshot() -> (usize, usize) {
        (
            ALLOCS.load(Ordering::Relaxed),
            BYTES.load(Ordering::Relaxed),
        )
    }
}

#[cfg(feature = "bench-alloc")]
#[global_allocator]
static GLOBAL: counting_alloc::CountingAlloc = counting_alloc::CountingAlloc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hydra_core::routing_rules::RuleEngine;
use hydra_protocol::udp_frame::{encode_udp_data, read_udp_frame, UdpFrame};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// 典型 MTU 级 UDP 载荷（1200B）
const PAYLOAD_1200: &[u8] = &[0xABu8; 1200];
/// 小报文（DNS 查询量级）
const PAYLOAD_64: &[u8] = &[0xCDu8; 64];

/// 分配计数测量（bench-alloc 关闭时打印提示行，保持输出结构一致）
fn report_allocs(name: &str, iters: usize, mut op: impl FnMut()) {
    #[cfg(feature = "bench-alloc")]
    {
        // 预热（初始化惰性状态，不计入差分）
        op();
        let (a0, b0) = counting_alloc::snapshot();
        for _ in 0..iters {
            op();
        }
        let (a1, b1) = counting_alloc::snapshot();
        println!(
            "alloc-op  {:<42} allocs/op = {:<6.2} bytes/op = {}",
            name,
            (a1 - a0) as f64 / iters as f64,
            (b1 - b0) / iters
        );
    }
    #[cfg(not(feature = "bench-alloc"))]
    {
        let _ = (name, iters, &mut op);
        println!(
            "alloc-op  {:<42} （未启用 bench-alloc feature：cargo bench --features bench-alloc）",
            name
        );
    }
}

fn bench_udp_frame(c: &mut Criterion) {
    // ①-a 帧构造（上行发送热路径：encode + write）
    c.bench_function("udp_frame/encode_1200B", |b| {
        b.iter(|| {
            black_box(
                encode_udp_data(black_box(7), black_box("1.2.3.4:5300"), black_box(PAYLOAD_1200))
                    .unwrap(),
            )
        })
    });
    c.bench_function("udp_frame/encode_64B", |b| {
        b.iter(|| {
            black_box(
                encode_udp_data(black_box(7), black_box("1.2.3.4:5300"), black_box(PAYLOAD_64))
                    .unwrap(),
            )
        })
    });

    // ①-b 构造→解析往返（下行接收热路径：read → 解复用）。read_udp_frame 为
    // async：经 current_thread runtime block_on 驱动；附 ①-c 空转对照组校准
    // block_on 常数开销。
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime");
    c.bench_function("udp_frame/roundtrip_1200B_blockon", |b| {
        b.iter(|| {
            let frame =
                encode_udp_data(9, "1.2.3.4:5300", PAYLOAD_1200).expect("encode");
            rt.block_on(async {
                match read_udp_frame(&mut Cursor::new(&frame)).await.expect("parse") {
                    UdpFrame::Data { datagram, .. } => black_box(datagram),
                    _ => panic!("期望数据帧"),
                }
            })
        })
    });
    c.bench_function("udp_frame/blockon_overhead_control", |b| {
        b.iter(|| rt.block_on(async { black_box(1u8) }))
    });
    report_allocs("udp_frame/encode_1200B", 10_000, || {
        let _ = encode_udp_data(7, "1.2.3.4:5300", PAYLOAD_1200).unwrap();
    });
}

fn bench_checksum16(c: &mut Criterion) {
    // ② checksum16（IPv4 伪首部+段 = 576B，B2 单遍化基线；输入按偶数长度取整）
    let buf = vec![0x11u8; 576];
    c.bench_function("checksum16/576B", |b| {
        b.iter(|| black_box(hydra_client::checksum16(black_box(&buf))))
    });
    report_allocs("checksum16/576B", 10_000, || {
        black_box(hydra_client::checksum16(&buf));
    });
}

fn bench_routing_decide(c: &mut Criterion) {
    // ③ 路由 decide：内置 GeoIP-CN 命中/未命中（每连接建连一次的热路径）
    let engine = RuleEngine::builtin_cn();
    let cn = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)), 53);
    let non_cn = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    c.bench_function("routing_decide/geoip_cn_hit", |b| {
        b.iter(|| black_box(engine.decide(black_box(cn))))
    });
    c.bench_function("routing_decide/geoip_cn_miss", |b| {
        b.iter(|| black_box(engine.decide(black_box(non_cn))))
    });
    report_allocs("routing_decide/geoip_cn_miss", 10_000, || {
        black_box(engine.decide(non_cn));
    });
}

criterion_group!(
    benches,
    bench_udp_frame,
    bench_checksum16,
    bench_routing_decide
);
criterion_main!(benches);
