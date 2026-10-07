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

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        FILE_NAME,
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /** 一次性读出全部配置（UI 表单回填与服务端启动共用）。 */
    fun load(): HydraConfig = HydraConfig(
        nodesText = prefs.getString(KEY_NODES, "").orEmpty(),
        authKeyHex = prefs.getString(KEY_AUTH_KEY, "").orEmpty(),
        sni = prefs.getString(KEY_SNI, "").orEmpty(),
        trustMode = prefs.getString(KEY_TRUST_MODE, TRUST_PINNED).orEmpty(),
        certDerB64 = prefs.getString(KEY_CERT_B64, "").orEmpty(),
        listenPort = prefs.getInt(KEY_LISTEN_PORT, DEFAULT_PORT),
    )

    fun save(c: HydraConfig) {
        prefs.edit()
            .putString(KEY_NODES, c.nodesText)
            .putString(KEY_AUTH_KEY, c.authKeyHex)
            .putString(KEY_SNI, c.sni)
            .putString(KEY_TRUST_MODE, c.trustMode)
            .putString(KEY_CERT_B64, c.certDerB64)
            .putInt(KEY_LISTEN_PORT, c.listenPort)
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

        const val TRUST_PINNED = "pinned"
        const val TRUST_CA = "ca"
        const val DEFAULT_PORT = 1080
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
)
