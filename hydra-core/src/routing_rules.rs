//! 智能分流规则引擎（docs/design/智能分流设计方案-v1.md v1.1 §三 + 评审 R1-R10）。
//!
//! 职责（纯逻辑，零平台依赖、零 tokio）：
//! 1. 规则文件解析（容错：UTF-8 BOM / CRLF / 行尾空白 / `#` 内联注释 /
//!    GBK 非法 UTF-8 行告警跳过——评审 R8）；
//! 2. 规则类型：IP-CIDR（v4+v6）/ GEOIP CN / DST-PORT（v1 范围）；
//! 3. 匹配 [`RuleEngine::decide`]（顺序，评审 §三.2）：
//!    内置「私网/回环/链路本地 → DIRECT」（R5，最高优先）→ 自定义规则
//!    （端口线性 + CIDR 匹配）→ GeoIP-CN 二分 → 默认 Proxy；
//! 4. GeoIP-CN 表：构建期由 `scripts/gen-geoip.ps1` 生成的
//!    `assets/geoip_cn.dat`（v4 + v6 段，评审 R6），`include_bytes!` 嵌入 +
//!    懒解析 OnceLock，查询为排序段二分 O(log n)；
//! 5. 自定义 CIDR 规则 ≥50 条时构建「排序合并段 + 二分」（R10 性能注记），
//!    合并保持先出现规则优先语义（跨动作重叠裁剪后段）。
//!
//! 与既有 SOCKS 路径 Exec2 域名分流（`routing::is_direct_target`）的关系
//! （评审 §2.1）：两套 v1 允许并存——SOCKS 按域名表、TUN 按目的 IP GeoIP，
//! 口径不一属已知现状，v1.1 候选统一。

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::OnceLock;

/// 单条连接的分流判定结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 直连（源 IP 绑定出物理网卡，绕过 TUN）
    Direct,
    /// 经节点代理（既有通道）
    Proxy,
}

// ── GeoIP-CN 嵌入式段表 ──────────────────────────────────────────────────────

/// 构建期生成的 CN 段表（scripts/gen-geoip.ps1 产物，随仓库提交——CI 不联网
/// 也能构建；数据时效见脚本输出，重新生成即更新）
static GEOIP_CN_DAT: &[u8] = include_bytes!("../assets/geoip_cn.dat");

/// dat 魔数（"HGI1"：Hydra GeoIP v1）
const GEOIP_MAGIC: [u8; 4] = *b"HGI1";

/// 解析后的 GeoIP 段表：排序、合并不重叠的闭区间数组，二分查询
#[derive(Debug, Clone, Default)]
pub struct GeoTables {
    /// CN IPv4 段（start, end 闭区间，升序不重叠）
    v4: Vec<(u32, u32)>,
    /// CN IPv6 段（同上，u128；评审 R6：v6 段同样生成）
    v6: Vec<(u128, u128)>,
}

impl GeoTables {
    /// 解析 dat 字节流（格式见 scripts/gen-geoip.ps1 头注释）。 defensively
    /// 排序（生成端已排序，此处兜底），段不裁剪重叠（生成端已合并）。
    pub fn from_bytes(dat: &[u8]) -> Result<GeoTables, String> {
        if dat.len() < 8 || dat[..4] != GEOIP_MAGIC {
            return Err(format!(
                "GeoIP dat 魔数不符（期望 {GEOIP_MAGIC:?}，实际 {:?}）",
                dat.get(..4).unwrap_or(&[])
            ));
        }
        let be32 = |off: usize| -> Result<u32, String> {
            dat.get(off..off + 4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                .ok_or_else(|| "GeoIP dat 截断（段数区）".to_string())
        };
        let n4 = be32(4)? as usize;
        let v4_end = 8 + n4 * 8;
        if dat.len() < v4_end + 4 {
            return Err("GeoIP dat 截断（v4 段区）".to_string());
        }
        let mut v4 = Vec::with_capacity(n4);
        for i in 0..n4 {
            let o = 8 + i * 8;
            let s = u32::from_be_bytes(dat[o..o + 4].try_into().unwrap());
            let e = u32::from_be_bytes(dat[o + 4..o + 8].try_into().unwrap());
            if e < s {
                return Err(format!("GeoIP dat v4 段非法（end<start）: {s:#x}-{e:#x}"));
            }
            v4.push((s, e));
        }
        let n6 = be32(v4_end)? as usize;
        let need = v4_end + 4 + n6 * 32;
        if dat.len() < need {
            return Err("GeoIP dat 截断（v6 段区）".to_string());
        }
        let mut v6 = Vec::with_capacity(n6);
        for i in 0..n6 {
            let o = v4_end + 4 + i * 32;
            let s = u128::from_be_bytes(dat[o..o + 16].try_into().unwrap());
            let e = u128::from_be_bytes(dat[o + 16..o + 32].try_into().unwrap());
            if e < s {
                return Err("GeoIP dat v6 段非法（end<start）".to_string());
            }
            v6.push((s, e));
        }
        // 生成端已排序合并，此处防御性排序（幂等，成本仅启动一次）
        v4.sort_unstable();
        v6.sort_unstable();
        Ok(GeoTables { v4, v6 })
    }

    /// 目的 IP 是否命中 CN 段（排序段二分）
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.contains_v4(u32::from(v4)),
            IpAddr::V6(v6) => self.contains_v6(u128::from(v6)),
        }
    }

    /// IPv4 二分：找最后一个 start ≤ ip 的段，验证 end ≥ ip
    pub fn contains_v4(&self, ip: u32) -> bool {
        let idx = self.v4.partition_point(|&(s, _)| s <= ip);
        idx > 0 && self.v4[idx - 1].1 >= ip
    }

    /// IPv6 二分（同上，u128）
    pub fn contains_v6(&self, ip: u128) -> bool {
        let idx = self.v6.partition_point(|&(s, _)| s <= ip);
        idx > 0 && self.v6[idx - 1].1 >= ip
    }

    /// 段数（观测/测试）
    pub fn len(&self) -> (usize, usize) {
        (self.v4.len(), self.v6.len())
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// 嵌入式 CN 表（懒解析 OnceLock：进程内仅解析一次，启动 ~1ms 量级）
pub fn geoip_cn_tables() -> &'static GeoTables {
    static TABLES: OnceLock<GeoTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        match GeoTables::from_bytes(GEOIP_CN_DAT) {
            Ok(t) => t,
            // 生成产物随仓库提交且解析有单测覆盖，损坏即构建期问题——
            // 运行时降级为空表（全部走节点），不 panic 影响代理主路径
            Err(e) => {
                tracing::warn!("内置 GeoIP-CN 表解析失败（降级为空表，全部走节点）: {e}");
                GeoTables::default()
            }
        }
    })
}

// ── 自定义规则 ───────────────────────────────────────────────────────────────

/// 规则动作（文件语法）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Direct,
    Proxy,
}

impl Action {
    fn parse(s: &str) -> Option<Action> {
        match s.trim().to_ascii_uppercase().as_str() {
            "DIRECT" => Some(Action::Direct),
            "PROXY" => Some(Action::Proxy),
            _ => None,
        }
    }
    fn decision(self) -> Decision {
        match self {
            Action::Direct => Decision::Direct,
            Action::Proxy => Decision::Proxy,
        }
    }
}

/// 自定义 CIDR 段二分优化的阈值（评审 R10：≥50 条时构建排序合并段二分，
/// 避免「数百条 CIDR 线性扫描」成为热路径）
const CIDR_BINARY_SEARCH_THRESHOLD: usize = 50;

/// 规则引擎：自定义规则（规则文件）+ 内置 GeoIP-CN 表 + 内置私网直连
pub struct RuleEngine {
    /// DST-PORT 规则（线性，数量小；评审 §2.3：仅作 DIRECT 例外等次要手段）
    port_rules: Vec<(u16, Action)>,
    /// 自定义 CIDR v4（文件顺序；≤阈值时线性首中即返回）
    cidr4: Vec<(u32, u32, Action)>,
    /// 自定义 CIDR v6（同上）
    cidr6: Vec<(u128, u128, Action)>,
    /// ≥阈值时对 CIDR 构建的排序合并段（先出现规则优先，跨动作重叠裁剪后段）
    cidr4_sorted: Option<Vec<(u32, u32, Action)>>,
    cidr6_sorted: Option<Vec<(u128, u128, Action)>>,
    /// 是否启用内置 GeoIP-CN 表（`GEOIP,CN,DIRECT` 规则出现，或 builtin 构造）
    geoip_enabled: bool,
    /// 解析统计：跳过的非法/不可解析行数（观测用）
    pub skipped_lines: usize,
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 段表千条量级，Debug 不展开内容，仅计数
        f.debug_struct("RuleEngine")
            .field("port_rules", &self.port_rules.len())
            .field("cidr4", &self.cidr4.len())
            .field("cidr6", &self.cidr6.len())
            .field("cidr4_sorted", &self.cidr4_sorted.is_some())
            .field("cidr6_sorted", &self.cidr6_sorted.is_some())
            .field("geoip_enabled", &self.geoip_enabled)
            .field("skipped_lines", &self.skipped_lines)
            .finish()
    }
}

impl RuleEngine {
    /// 从规则文件加载（UTF-8，容错解析见 [`RuleEngine::from_bytes`]）。
    /// 读取失败返回 Err（调用方决定降级策略——GUI 默认回退 builtin）。
    pub fn from_rule_file(path: impl AsRef<Path>) -> Result<RuleEngine, String> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|e| format!("读取规则文件 {} 失败: {e}", path.display()))?;
        Ok(RuleEngine::from_bytes(&bytes))
    }

    /// 从字节流解析（R8 容错）：
    /// - 跳过 UTF-8 BOM；
    /// - CRLF / LF / 行尾空白均容忍；
    /// - `#` 起整行注释与行内 `# …` 尾注均剥离；
    /// - 单行非法 UTF-8（旧记事本 GBK 保存）→ 告警计数并跳过该行，
    ///   **不静默整表失效**；
    /// - 语法非法行同样跳过计数。
    pub fn from_bytes(bytes: &[u8]) -> RuleEngine {
        let mut eng = RuleEngine {
            port_rules: Vec::new(),
            cidr4: Vec::new(),
            cidr6: Vec::new(),
            cidr4_sorted: None,
            cidr6_sorted: None,
            geoip_enabled: false,
            skipped_lines: 0,
        };
        let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(bytes);
        for raw in body.split(|&b| b == b'\n') {
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            let line = match std::str::from_utf8(raw) {
                Ok(s) => s,
                Err(_) => {
                    // GBK 等非 UTF-8 行（R8）：告警跳过，不整表失效
                    tracing::warn!("规则文件存在非 UTF-8 行（GBK 保存？），已跳过该行");
                    eng.skipped_lines += 1;
                    continue;
                }
            };
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if !eng.parse_line(line) {
                eng.skipped_lines += 1;
            }
        }
        eng.build_indexes();
        eng
    }

    /// 仅内置 GeoIP-CN 表（无自定义规则）——规则文件缺失/不可读时的降级形态，
    /// 也是「内置 CN 直连」的最小引擎
    pub fn builtin_cn() -> RuleEngine {
        RuleEngine {
            port_rules: Vec::new(),
            cidr4: Vec::new(),
            cidr6: Vec::new(),
            cidr4_sorted: None,
            cidr6_sorted: None,
            geoip_enabled: true,
            skipped_lines: 0,
        }
    }

    /// 单行语法：`TYPE,参数…,ACTION`（类型/动作大小写不敏感）
    fn parse_line(&mut self, line: &str) -> bool {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            return false;
        }
        let kind = parts[0].to_ascii_uppercase();
        let action = match Action::parse(parts[parts.len() - 1]) {
            Some(a) => a,
            None => {
                tracing::warn!("规则文件行动作非法（期望 DIRECT/PROXY），跳过: {line}");
                return false;
            }
        };
        match kind.as_str() {
            "IP-CIDR" => {
                if parts.len() != 3 {
                    return false;
                }
                match parse_cidr(parts[1]) {
                    Ok(Cidr::V4(s, e)) => self.cidr4.push((s, e, action)),
                    Ok(Cidr::V6(s, e)) => self.cidr6.push((s, e, action)),
                    Err(e) => {
                        tracing::warn!("规则文件 CIDR 非法（{e}），跳过: {line}");
                        return false;
                    }
                }
                true
            }
            // v1 仅内置 CN 表：其他国家代码不支持（如实跳过）
            "GEOIP" => {
                if parts.len() != 3 || !parts[1].eq_ignore_ascii_case("CN") {
                    tracing::warn!("规则文件 GEOIP 仅支持 CN（v1），跳过: {line}");
                    return false;
                }
                if action != Action::Direct {
                    tracing::warn!("规则文件 GEOIP,CN 仅支持 DIRECT（v1），跳过: {line}");
                    return false;
                }
                self.geoip_enabled = true;
                true
            }
            "DST-PORT" => {
                if parts.len() != 3 {
                    return false;
                }
                match parts[1].parse::<u16>() {
                    Ok(p) => {
                        self.port_rules.push((p, action));
                        true
                    }
                    Err(_) => {
                        tracing::warn!("规则文件端口非法，跳过: {line}");
                        false
                    }
                }
            }
            _ => {
                tracing::warn!("规则文件类型未支持（{kind}），跳过: {line}");
                false
            }
        }
    }

    /// 构建查询索引：CIDR ≥阈值时排序 + 合并（同类相邻合并 / 跨动作重叠按
    /// 先出现规则优先裁剪后段），查询走二分（R10）
    fn build_indexes(&mut self) {
        if self.cidr4.len() >= CIDR_BINARY_SEARCH_THRESHOLD {
            self.cidr4_sorted = Some(merge_cidr4(&mut self.cidr4));
        }
        if self.cidr6.len() >= CIDR_BINARY_SEARCH_THRESHOLD {
            self.cidr6_sorted = Some(merge_cidr6(&mut self.cidr6));
        }
    }

    /// 匹配判定（每连接建连时一次，热路径零新增分配——输入为原始 SocketAddr）
    pub fn decide(&self, dst: SocketAddr) -> Decision {
        // 1. 内置最高优先级：私网/回环/链路本地 → DIRECT（R5——豁免路由缺失
        //    时私网包会进栈，直连 opener bind 物理 IP 后可访问 NAS/路由器，
        //    优于丢弃/走节点）
        if is_builtin_direct(dst.ip()) {
            return Decision::Direct;
        }
        // 2. 自定义规则：端口线性（数量小）→ CIDR（阈值内线性 / 以上二分）
        for (p, a) in &self.port_rules {
            if *p == dst.port() {
                return a.decision();
            }
        }
        let hit4 = |ip: u32| match &self.cidr4_sorted {
            Some(segs) => lookup_sorted(segs, ip),
            None => self.cidr4.iter().find(|(s, e, _)| ip >= *s && ip <= *e).map(|r| r.2),
        };
        let hit6 = |ip: u128| match &self.cidr6_sorted {
            Some(segs) => lookup_sorted(segs, ip),
            None => self.cidr6.iter().find(|(s, e, _)| ip >= *s && ip <= *e).map(|r| r.2),
        };
        let custom = match dst.ip() {
            IpAddr::V4(ip) => hit4(u32::from(ip)),
            IpAddr::V6(ip) => hit6(u128::from(ip)),
        };
        if let Some(a) = custom {
            return a.decision();
        }
        // 3. GeoIP-CN 表二分
        if self.geoip_enabled && geoip_cn_tables().contains(dst.ip()) {
            return Decision::Direct;
        }
        // 4. 默认策略 → PROXY
        Decision::Proxy
    }

    /// 是否启用 GeoIP-CN（观测用）
    pub fn geoip_enabled(&self) -> bool {
        self.geoip_enabled
    }

    /// 自定义端口规则数（日志/观测）
    pub fn port_rule_count(&self) -> usize {
        self.port_rules.len()
    }

    /// 自定义 IPv4 CIDR 规则数（日志/观测）
    pub fn cidr4_count(&self) -> usize {
        self.cidr4.len()
    }

    /// 自定义 IPv6 CIDR 规则数（日志/观测）
    pub fn cidr6_count(&self) -> usize {
        self.cidr6.len()
    }
}

/// CIDR 解析："1.2.3.0/24" / "2001:db8::/32" → 闭区间 (start, end)（掩码对齐）
fn parse_cidr(s: &str) -> Result<Cidr, String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("缺少前缀长度: {s}"))?;
    let prefix: u32 = prefix
        .trim()
        .parse()
        .map_err(|_| format!("前缀长度非法: {s}"))?;
    let addr: IpAddr = addr
        .trim()
        .parse()
        .map_err(|e| format!("地址非法: {s} ({e})"))?;
    match addr {
        IpAddr::V4(ip) => {
            if prefix > 32 {
                return Err(format!("IPv4 前缀 >32: {s}"));
            }
            let v = u32::from(ip);
            let mask = host_mask(prefix);
            let start = v & !mask;
            Ok(Cidr::V4(start, start | mask))
        }
        IpAddr::V6(ip) => {
            if prefix > 128 {
                return Err(format!("IPv6 前缀 >128: {s}"));
            }
            let v = u128::from(ip);
            let mask = if prefix >= 128 {
                u128::MAX
            } else {
                (1u128 << (128 - prefix)) - 1
            };
            let start = v & !mask;
            Ok(Cidr::V6(start, start | mask))
        }
    }
}

enum Cidr {
    V4(u32, u32),
    V6(u128, u128),
}

/// IPv4 主机位掩码（prefix=0 → 全主机位）
fn host_mask(prefix: u32) -> u32 {
    if prefix >= 32 {
        0
    } else {
        u32::MAX >> prefix
    }
}

/// 排序合并（先出现规则优先语义保持）——IPv4 版：
/// - 同动作重叠段合并；
/// - 跨动作重叠：先出现的规则胜出，后段从 `last.end+1` 起裁剪
///   （首中即返回语义，交界的单个 IP 归先出现规则）。
///
/// 输出按 start 升序不重叠，可安全二分。
fn merge_cidr4(segs: &mut [(u32, u32, Action)]) -> Vec<(u32, u32, Action)> {
    segs.sort_unstable_by_key(|&(s, e, _)| (s, e));
    let mut out: Vec<(u32, u32, Action)> = Vec::with_capacity(segs.len());
    for &(s, e, a) in segs.iter() {
        // 先以不可变借用取前段信息，避免 push 与 last_mut 的借用冲突
        let prev = out.last().filter(|last| s <= last.1).map(|last| (last.2 == a, last.1));
        match prev {
            Some((same_action, last_end)) => {
                if same_action {
                    if e > last_end {
                        out.last_mut().unwrap().1 = e; // 重叠同动作：扩张前段
                    }
                } else if e > last_end {
                    // 跨动作重叠：裁掉与先出现规则的交集（含交界 IP）
                    out.push((last_end.saturating_add(1), e, a));
                }
                // e <= last_end：后段完全被先出现的规则覆盖，丢弃
            }
            None => out.push((s, e, a)),
        }
    }
    out
}

/// 排序合并——IPv6 版（u128，语义同 [`merge_cidr4`]）
fn merge_cidr6(segs: &mut [(u128, u128, Action)]) -> Vec<(u128, u128, Action)> {
    segs.sort_unstable_by_key(|&(s, e, _)| (s, e));
    let mut out: Vec<(u128, u128, Action)> = Vec::with_capacity(segs.len());
    for &(s, e, a) in segs.iter() {
        let prev = out.last().filter(|last| s <= last.1).map(|last| (last.2 == a, last.1));
        match prev {
            Some((same_action, last_end)) => {
                if same_action {
                    if e > last_end {
                        out.last_mut().unwrap().1 = e;
                    }
                } else if e > last_end {
                    out.push((last_end.saturating_add(1), e, a));
                }
            }
            None => out.push((s, e, a)),
        }
    }
    out
}

/// 排序段二分（输出不重叠的前提下精确）：最后一个 start ≤ ip 的段，end ≥ ip 即命中
fn lookup_sorted<T: Copy + PartialOrd>(segs: &[(T, T, Action)], ip: T) -> Option<Action> {
    let idx = segs.partition_point(|&(s, _, _)| s <= ip);
    if idx > 0 {
        let (s, e, a) = segs[idx - 1];
        if e >= ip && s <= ip {
            return Some(a);
        }
    }
    None
}

/// 内置最高优先级直连（R5）：私网 / 回环 / 链路本地 / 未指定 / 0.0.0.0::/8 与
/// 运营商级 NAT 100.64/10 / 组播 / 广播 / ULA。与 tun.rs 的私网过滤口径一致。
pub fn is_builtin_direct(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 链路本地
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
                || v6.is_multicast()
        }
    }
}

// ── 单测（设计 §六：CIDR v4/v6 边界、GeoIP 二分、优先级、容错解析）───────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn decide_str(eng: &RuleEngine, target: &str) -> Decision {
        eng.decide(target.parse().unwrap())
    }

    fn mk_dat(v4: &[(u32, u32)], v6: &[(u128, u128)]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&GEOIP_MAGIC);
        d.extend_from_slice(&(v4.len() as u32).to_be_bytes());
        for (s, e) in v4 {
            d.extend_from_slice(&s.to_be_bytes());
            d.extend_from_slice(&e.to_be_bytes());
        }
        d.extend_from_slice(&(v6.len() as u32).to_be_bytes());
        for (s, e) in v6 {
            d.extend_from_slice(&s.to_be_bytes());
            d.extend_from_slice(&e.to_be_bytes());
        }
        d
    }

    // ── CIDR v4 边界 ──（注意用公网段：私网段会被内置 DIRECT（R5）先命中）
    #[test]
    fn cidr_v4_边界含端点() {
        let eng = RuleEngine::from_bytes(b"IP-CIDR,9.1.2.0/24,DIRECT\n");
        assert_eq!(decide_str(&eng, "9.1.2.0:80"), Decision::Direct);
        assert_eq!(decide_str(&eng, "9.1.2.255:443"), Decision::Direct);
        // 边界外
        assert_eq!(decide_str(&eng, "9.1.3.0:80"), Decision::Proxy);
        assert_eq!(decide_str(&eng, "9.1.1.255:80"), Decision::Proxy);
    }

    // ── CIDR v6 边界 ──
    #[test]
    fn cidr_v6_边界含端点() {
        let eng = RuleEngine::from_bytes(b"IP-CIDR,2001:db8::/32,DIRECT\nIP-CIDR,::ffff:0:0/96,PROXY\n");
        assert_eq!(decide_str(&eng, "[2001:db8::]:443"), Decision::Direct);
        assert_eq!(decide_str(&eng, "[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:443"), Decision::Direct);
        assert_eq!(decide_str(&eng, "[::ffff:1.2.3.4]:443"), Decision::Proxy); // ::ffff/96
        assert_eq!(decide_str(&eng, "[2001:db9::]:443"), Decision::Proxy); // 未命中 → 默认
    }

    #[test]
    fn cidr_v6_默认策略() {
        let eng = RuleEngine::from_bytes(b"IP-CIDR,2001:db8::/32,PROXY\n");
        assert_eq!(decide_str(&eng, "[2001:db9::]:443"), Decision::Proxy); // 默认
        assert_eq!(decide_str(&eng, "[2001:db8:1::1]:80"), Decision::Proxy); // 规则命中同为 PROXY
        let eng2 = RuleEngine::from_bytes(b"IP-CIDR,2001:db8::/32,DIRECT\n");
        assert_eq!(decide_str(&eng2, "[2001:db8:1::1]:80"), Decision::Direct);
        assert_eq!(decide_str(&eng2, "[2001:db9::1]:80"), Decision::Proxy);
    }

    // ── GeoIP 表解析 + 二分 ──
    #[test]
    fn geoip_二分与边界() {
        let dat = mk_dat(
            &[(0x0A00_0000, 0x0A00_00FF), (0xC629_0000, 0xC629_FFFF)], // 10.0.0.0/24, 198.41.0.0/16
            &[
                ((0x2001u128 << 112) | (0x0db8u128 << 96), (0x2001u128 << 112) | (0x0db8u128 << 96) | 0xffff_ffff),
                (1, 2),
            ],
        );
        let t = GeoTables::from_bytes(&dat).unwrap();
        assert_eq!(t.len(), (2, 2));
        assert!(t.contains_v4(0x0A00_0000)); // start
        assert!(t.contains_v4(0x0A00_00FF)); // end
        assert!(!t.contains_v4(0x0A00_0100));
        assert!(!t.contains_v4(0x09FF_FFFF));
        assert!(t.contains_v4(0xC629_1234));
        assert!(t.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));
        assert!(!t.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db9, 0, 0, 0, 0, 0, 1))));
        // 段间空洞
        assert!(!t.contains_v4(0x0B00_0000));
    }

    #[test]
    fn geoip_坏数据拒收() {
        assert!(GeoTables::from_bytes(b"XXXX").is_err());
        assert!(GeoTables::from_bytes(b"HGI1\x00\x00\x00\x05").is_err()); // 截断
    }

    // ── 内置表（构建产物）：CN 段直连、非 CN 默认代理 ──
    #[test]
    fn builtin_cn_嵌入表生效() {
        let eng = RuleEngine::builtin_cn();
        assert!(eng.geoip_enabled());
        let (n4, n6) = geoip_cn_tables().len();
        assert!(n4 > 1000, "v4 段数异常: {n4}");
        assert!(n6 > 100, "v6 段数异常（评审 R6）: {n6}");
        // 公共 DNS 114.114.114.114（江苏南京，CNNIC 分配段）应在 CN 表内
        assert_eq!(decide_str(&eng, "114.114.114.114:53"), Decision::Direct);
        // 8.8.8.8（Google）不在 CN 表 → 默认 Proxy
        assert_eq!(decide_str(&eng, "8.8.8.8:443"), Decision::Proxy);
    }

    // ── 匹配优先级 ──
    #[test]
    fn 优先级_私网内置最高() {
        // 即便规则写 PROXY，私网仍内置 DIRECT（R5）
        let eng = RuleEngine::from_bytes(b"IP-CIDR,192.168.1.0/24,PROXY\nGEOIP,CN,DIRECT\n");
        assert_eq!(decide_str(&eng, "192.168.1.1:80"), Decision::Direct);
        assert_eq!(decide_str(&eng, "127.0.0.1:8080"), Decision::Direct);
        assert_eq!(decide_str(&eng, "[fe80::1]:443"), Decision::Direct);
        assert_eq!(decide_str(&eng, "[fd12::1]:443"), Decision::Direct); // ULA
    }

    #[test]
    fn 优先级_端口与自定义_cidr先于_geoip() {
        // 8.8.8.8 非 CN；端口 53 放行直连（DST-PORT 例外形态，评审 §2.3）
        let eng = RuleEngine::from_bytes(b"DST-PORT,53,DIRECT\nGEOIP,CN,DIRECT\n");
        assert_eq!(decide_str(&eng, "8.8.8.8:53"), Decision::Direct);
        assert_eq!(decide_str(&eng, "8.8.8.8:443"), Decision::Proxy);
        // 自定义 CIDR 先于 GeoIP：非 CN 段显式 DIRECT
        let eng2 = RuleEngine::from_bytes(b"IP-CIDR,8.8.8.0/24,DIRECT\nGEOIP,CN,DIRECT\n");
        assert_eq!(decide_str(&eng2, "8.8.8.8:443"), Decision::Direct);
    }

    // ── R10：≥50 条 CIDR 构建排序合并段二分 ──
    #[test]
    fn 大量cidr_二分索引生效() {
        let mut rules = String::new();
        for i in 0..60u32 {
            rules.push_str(&format!("IP-CIDR,20.{i}.0.0/16,DIRECT\n"));
        }
        let eng = RuleEngine::from_bytes(rules.as_bytes());
        assert!(eng.cidr4_sorted.is_some(), "≥50 条应构建二分索引");
        assert_eq!(decide_str(&eng, "20.30.123.45:80"), Decision::Direct);
        assert_eq!(decide_str(&eng, "20.59.255.255:80"), Decision::Direct);
        assert_eq!(decide_str(&eng, "20.60.0.1:80"), Decision::Proxy);
        assert!(eng.cidr6_sorted.is_none(), "v4 阈值不影响 v6");
    }

    #[test]
    fn 大量cidr_重叠合并保持先出现优先() {
        let mut rules = String::from("IP-CIDR,21.0.0.0/8,PROXY\n");
        for i in 0..60u32 {
            rules.push_str(&format!("IP-CIDR,21.{i}.0.0/16,DIRECT\n"));
        }
        let eng = RuleEngine::from_bytes(rules.as_bytes());
        // 先出现的 21/8 PROXY 覆盖全部 DIRECT 子段（首中即返回语义）
        assert_eq!(decide_str(&eng, "21.30.0.1:80"), Decision::Proxy);
        assert_eq!(decide_str(&eng, "22.0.0.1:80"), Decision::Proxy);
    }

    // ── R8 容错解析 ──
    #[test]
    #[allow(non_snake_case)]
    fn 解析容错_BOM_CRLF_内联注释_空白() {
        let src = "\u{FEFF}# 整行注释\r\nIP-CIDR,1.2.3.0/24, direct   # 行内注释\r\n  \r\nDST-PORT,53,direct\r\nGEOIP,CN,direct\r\n";
        let eng = RuleEngine::from_bytes(src.as_bytes());
        assert_eq!(eng.skipped_lines, 0);
        assert_eq!(decide_str(&eng, "1.2.3.4:443"), Decision::Direct);
        assert_eq!(decide_str(&eng, "4.4.4.4:53"), Decision::Direct);
        assert_eq!(decide_str(&eng, "4.4.4.4:443"), Decision::Proxy); // GEOIP 生效后默认
    }

    #[test]
    #[allow(non_snake_case)]
    fn 解析容错_非法UTF8行跳过不整表失效() {
        // 第二行为非法 UTF-8（模拟 GBK 中文注释），首尾规则必须仍生效
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"IP-CIDR,1.2.3.0/24,DIRECT\n");
        bytes.extend_from_slice(&[0xB1, 0xBE, 0xB5, 0xD8, 0xB7, 0xD6, 0xC1, 0xF7, b'\n']); // GBK "本地分流"
        bytes.extend_from_slice(b"GEOIP,CN,DIRECT\n");
        let eng = RuleEngine::from_bytes(&bytes);
        assert_eq!(eng.skipped_lines, 1);
        assert_eq!(decide_str(&eng, "1.2.3.4:80"), Decision::Direct);
        assert_eq!(decide_str(&eng, "114.114.114.114:53"), Decision::Direct);
    }

    #[test]
    fn 解析容错_语法非法行计数跳过() {
        let eng = RuleEngine::from_bytes(
            b"BOGUS,x,DIRECT\nIP-CIDR,1.2.3.4/33,DIRECT\nDST-PORT,abc,DIRECT\nIP-CIDR,9.9.9.0/24,DIRECT\n",
        );
        assert_eq!(eng.skipped_lines, 3);
        assert_eq!(decide_str(&eng, "9.9.9.9:80"), Decision::Direct);
    }

    // ── 内置直连判定（R5）──
    #[test]
    fn 内置直连_口径完整() {
        for t in [
            "10.0.0.1:1", "172.16.0.1:1", "192.168.1.1:1", "127.0.0.1:1",
            "169.254.1.1:1", "100.64.0.1:1", "0.1.2.3:1", "255.255.255.255:1",
            "224.0.0.1:1", "[::1]:1", "[fe80::1]:1", "[fc00::1]:1", "[ff02::1]:1",
        ] {
            assert_eq!(
                decide_str(&RuleEngine::builtin_cn(), t),
                Decision::Direct,
                "{t} 应内置 DIRECT"
            );
        }
    }

    // ── merge 辅助：跨动作裁剪后的二分正确性 ──
    #[test]
    fn 合并裁剪_二分查找无假阳() {
        let mut segs: Vec<(u32, u32, Action)> = vec![
            (10, 20, Action::Direct),
            (15, 25, Action::Proxy), // 与前段重叠：交界起裁剪
            (30, 40, Action::Direct),
        ];
        let merged = merge_cidr4(&mut segs);
        let hit = |ip| lookup_sorted(&merged, ip);
        assert_eq!(hit(12), Some(Action::Direct));
        // 交界 IP（20）归先出现规则（Direct）
        assert_eq!(hit(20), Some(Action::Direct));
        // 21-25 属后段（PROXY，前段 Direct 只到 20）
        assert_eq!(hit(22), Some(Action::Proxy));
        assert_eq!(hit(35), Some(Action::Direct));
        assert_eq!(hit(26), None);
        assert_eq!(hit(5), None);
    }
}
