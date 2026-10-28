package dev.hydra.vpn

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * M1/R8：节点配置与密钥的安全存储。
 *
 * EncryptedSharedPreferences：Keystore 生成 Android Keystore 主密钥（StrongBox
 * 可用时硬件级），AES256-GCM 加密整个 preferences 文件——密钥不落明文。
 * `allowBackup=false`（Manifest）保证不会随云备份泄漏。
 *
 * 字段（v1）：
 * - nodes：节点列表，每行一条 `addr:port`（IPv6 用 `[::1]:443` 字面量）
 * - auth_key_hex：64 hex（32B PSK）
 * - sni：可空（缺省 hydra.node）
 * - trust_mode：`pinned` / `ca`
 * - cert_der_b64：pin 模式证书 DER（base64；**全局回落项**——单证书部署与
 *   未携带 cc 的手动节点承接）
 * - node_certs：按节点地址索引的证书表（每行 `addr\tb64`），多节点各自
 *   独立证书互不覆盖；缺项回落 cert_der_b64（ISSUE 安卓多节点证书）
 * - listen_port：进程内 SOCKS5 端口（0 = 随机）
 */
class SecureStore(context: Context) {

    private val prefs: SharedPreferences = try {
        EncryptedSharedPreferences.create(
            context,
            FILE_NAME,
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (e: Exception) {
        // 部分厂商 ROM 的 Keystore 损坏会让 EncryptedSharedPreferences 创建
        // 持续抛异常（启动即崩溃循环）——降级普通存储保可用性：应用沙箱 +
        // allowBackup=false 仍是底线，但不再对抗本机 root（日志明确留痕）
        android.util.Log.w("HydraSecureStore", "加密存储不可用，降级普通存储: $e")
        context.getSharedPreferences("${FILE_NAME}_fallback", Context.MODE_PRIVATE)
    }

    /** 一次性读出全部配置（UI 表单回填与服务端启动共用）。 */
    fun load(): HydraConfig = HydraConfig(
        nodesText = prefs.getString(KEY_NODES, "").orEmpty(),
        authKeyHex = prefs.getString(KEY_AUTH_KEY, "").orEmpty(),
        sni = prefs.getString(KEY_SNI, "").orEmpty(),
        trustMode = prefs.getString(KEY_TRUST_MODE, TRUST_PINNED).orEmpty(),
        certDerB64 = prefs.getString(KEY_CERT_B64, "").orEmpty(),
        nodeCertB64Map = parseNodeCerts(prefs.getString(KEY_NODE_CERTS, "").orEmpty()),
        listenPort = prefs.getInt(KEY_LISTEN_PORT, DEFAULT_PORT),
        runMode = prefs.getString(KEY_RUN_MODE, MODE_VPN).orEmpty(),
        vpnKillSwitch = prefs.getBoolean(KEY_VPN_KILL_SWITCH, true),
        vpnBootStart = prefs.getBoolean(KEY_VPN_BOOT_START, false),
        appFilterMode = prefs.getInt(KEY_APP_FILTER_MODE, APP_FILTER_ALL),
        appFilterPkgs = prefs.getString(KEY_APP_FILTER_PKGS, "").orEmpty(),
        runRuleMode = prefs.getBoolean(KEY_RUN_RULE_MODE, false),
        // 健康检查间隔（秒）：0 = 关闭；非法历史值归一化到默认 300s
        healthProbeSecs = normalizeProbeSecs(
            prefs.getInt(KEY_HEALTH_PROBE_SECS, HEALTH_PROBE_DEFAULT_SECS),
        ),
    )

    fun save(c: HydraConfig) {
        prefs.edit()
            .putString(KEY_NODES, c.nodesText)
            .putString(KEY_AUTH_KEY, c.authKeyHex)
            .putString(KEY_SNI, c.sni)
            .putString(KEY_TRUST_MODE, c.trustMode)
            .putString(KEY_CERT_B64, c.certDerB64)
            .putString(KEY_NODE_CERTS, encodeNodeCerts(c.nodeCertB64Map))
            .putInt(KEY_LISTEN_PORT, c.listenPort)
            .putString(KEY_RUN_MODE, c.runMode)
            .putBoolean(KEY_VPN_KILL_SWITCH, c.vpnKillSwitch)
            .putBoolean(KEY_VPN_BOOT_START, c.vpnBootStart)
            .putInt(KEY_APP_FILTER_MODE, c.appFilterMode)
            .putString(KEY_APP_FILTER_PKGS, c.appFilterPkgs)
            .putBoolean(KEY_RUN_RULE_MODE, c.runRuleMode)
            .putInt(KEY_HEALTH_PROBE_SECS, normalizeProbeSecs(c.healthProbeSecs))
            // commit() 同步落盘（企业评审）：apply() 异步刷盘在进程意外终止/
            // 系统回收时可能丢失（实测：深链导入成功后启动读到空配置）。配置
            // 体量小、写入频率低，同步开销可接受——正确性优先。
            .commit()
    }

    companion object {
        private const val FILE_NAME = "hydra_secure"
        private const val KEY_NODES = "nodes"
        private const val KEY_AUTH_KEY = "auth_key_hex"
        private const val KEY_SNI = "sni"
        private const val KEY_TRUST_MODE = "trust_mode"
        private const val KEY_CERT_B64 = "cert_der_b64"
        private const val KEY_NODE_CERTS = "node_certs"
        private const val KEY_LISTEN_PORT = "listen_port"
        private const val KEY_RUN_MODE = "run_mode"
        private const val KEY_VPN_KILL_SWITCH = "vpn_kill_switch"
        private const val KEY_VPN_BOOT_START = "vpn_boot_start"
        private const val KEY_APP_FILTER_MODE = "app_filter_mode"
        private const val KEY_APP_FILTER_PKGS = "app_filter_pkgs"
        /** 智能分流开关（规则模式：命中 CN 规则直连，其余走节点；默认关闭=全局） */
        private const val KEY_RUN_RULE_MODE = "run_rule_mode"
        /** 健康检查间隔秒数（0=关闭；默认 300s，方案 §二.B 定稿） */
        private const val KEY_HEALTH_PROBE_SECS = "health_probe_secs"

        const val TRUST_PINNED = "pinned"
        const val TRUST_CA = "ca"
        const val DEFAULT_PORT = 1080
        /** 运行模式：vpn = 全局 VPN（VpnService，M2）；local = 本地端口（浏览器代理） */
        const val MODE_VPN = "vpn"
        const val MODE_LOCAL = "local"

        /** 分应用代理模式（M2.1） */
        const val APP_FILTER_ALL = 0        // 全部应用走 VPN（默认）
        const val APP_FILTER_ALLOW = 1      // 白名单：仅所选应用走 VPN
        const val APP_FILTER_DISALLOW = 2   // 黑名单：所选应用不走 VPN
    }
}

/** 不可变配置快照（UI ↔ 存储 ↔ 服务 之间传递）。 */
data class HydraConfig(
    val nodesText: String,
    val authKeyHex: String,
    val sni: String,
    val trustMode: String,
    val certDerB64: String,
    /** 按节点地址索引的证书 DER base64（addr → b64）：多节点各自独立证书，
     *  缺项回落 certDerB64（ISSUE 安卓多节点证书；旧配置无此表 = 空表，
     *  全部由全局回落承接，行为与修复前一致） */
    val nodeCertB64Map: Map<String, String> = emptyMap(),
    val listenPort: Int,
    /** "vpn"（默认）/ "local" */
    val runMode: String,
    /** 断线阻断：隧道中断时保持接管路由黑洞流量并自动重连，防真实 IP 泄漏（默认开） */
    val vpnKillSwitch: Boolean = true,
    /** 开机自动启动 VPN（需已授权过；Android 15+ 可能限制，系统 Always-on 更可靠） */
    val vpnBootStart: Boolean = false,
    /** 分应用代理模式：0=全部 / 1=白名单 / 2=黑名单 */
    val appFilterMode: Int = SecureStore.APP_FILTER_ALL,
    /** 分应用代理应用包名列表（换行分隔） */
    val appFilterPkgs: String = "",
    /** 智能分流（规则模式）：命中 CN 规则直连 · 其余走节点（默认 false = 全局代理，
     *  行为与关闭前逐字节一致）。切换在下次启动 VPN 时生效（运行中不热切换） */
    val runRuleMode: Boolean = false,
    /** 健康检查间隔秒数（1m/3m/5m/10m/关 → 60/180/300/600/0；默认 300s）。
     *  连接建立与网络切换瞬间各额外触发一次即时探测（不占用本间隔） */
    val healthProbeSecs: Int = HEALTH_PROBE_DEFAULT_SECS,
)

/**
 * node_certs 表序列化（每行 `addr\tb64`）。addr 是 IP:port / [v6]:port 字面量、
 * b64 是标准 base64——两者都不含 tab/换行，行切分无歧义；无需引入 JSON 依赖。
 * internal 供桌面 JVM 单测覆盖（EncryptedSharedPreferences 依赖 Android 框架，
 * SecureStore 本体无法在纯 JVM 构造）。
 */
internal fun encodeNodeCerts(m: Map<String, String>): String =
    m.entries.joinToString("\n") { "${it.key}\t${it.value}" }

internal fun parseNodeCerts(s: String): Map<String, String> =
    s.lines().filter { it.isNotBlank() }.mapNotNull { line ->
        val i = line.indexOf('\t')
        if (i <= 0 || i == line.length - 1) {
            null // 坏行跳过（半写/手工篡改不致命——缺项回落全局证书）
        } else {
            line.substring(0, i).trim() to line.substring(i + 1).trim()
        }
    }.toMap()
