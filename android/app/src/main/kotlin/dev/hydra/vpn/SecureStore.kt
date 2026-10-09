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
 * - cert_der_b64：pin 模式证书 DER（base64；多节点共用同一自签证书是当前
 *   部署惯例，v1 单证书）
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
        listenPort = prefs.getInt(KEY_LISTEN_PORT, DEFAULT_PORT),
        runMode = prefs.getString(KEY_RUN_MODE, MODE_VPN).orEmpty(),
        vpnKillSwitch = prefs.getBoolean(KEY_VPN_KILL_SWITCH, true),
        vpnBootStart = prefs.getBoolean(KEY_VPN_BOOT_START, false),
        appFilterMode = prefs.getInt(KEY_APP_FILTER_MODE, APP_FILTER_ALL),
        appFilterPkgs = prefs.getString(KEY_APP_FILTER_PKGS, "").orEmpty(),
    )

    fun save(c: HydraConfig) {
        prefs.edit()
            .putString(KEY_NODES, c.nodesText)
            .putString(KEY_AUTH_KEY, c.authKeyHex)
            .putString(KEY_SNI, c.sni)
            .putString(KEY_TRUST_MODE, c.trustMode)
            .putString(KEY_CERT_B64, c.certDerB64)
            .putInt(KEY_LISTEN_PORT, c.listenPort)
            .putString(KEY_RUN_MODE, c.runMode)
            .putBoolean(KEY_VPN_KILL_SWITCH, c.vpnKillSwitch)
            .putBoolean(KEY_VPN_BOOT_START, c.vpnBootStart)
            .putInt(KEY_APP_FILTER_MODE, c.appFilterMode)
            .putString(KEY_APP_FILTER_PKGS, c.appFilterPkgs)
            .apply()
    }

    companion object {
        private const val FILE_NAME = "hydra_secure"
        private const val KEY_NODES = "nodes"
        private const val KEY_AUTH_KEY = "auth_key_hex"
        private const val KEY_SNI = "sni"
        private const val KEY_TRUST_MODE = "trust_mode"
        private const val KEY_CERT_B64 = "cert_der_b64"
        private const val KEY_LISTEN_PORT = "listen_port"
        private const val KEY_RUN_MODE = "run_mode"
        private const val KEY_VPN_KILL_SWITCH = "vpn_kill_switch"
        private const val KEY_VPN_BOOT_START = "vpn_boot_start"
        private const val KEY_APP_FILTER_MODE = "app_filter_mode"
        private const val KEY_APP_FILTER_PKGS = "app_filter_pkgs"

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
)
