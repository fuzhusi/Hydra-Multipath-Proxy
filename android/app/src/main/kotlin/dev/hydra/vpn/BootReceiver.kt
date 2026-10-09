package dev.hydra.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * M2.1 开机自启（设置页开关，默认关）：BOOT_COMPLETED 后按存储配置拉起全局
 * VPN。约束与语义：
 * - 仅 VPN 模式且已授权过（consent 持久化后 `VpnService.prepare` 返回 null）
 *   才静默启动；未授权静默跳过（开屏后由用户手动启动走正常授权流程）；
 * - Android 15+ 对 BOOT_COMPLETED 启动 dataSync 前台服务有限制——失败仅记
 *   日志不崩溃；**可靠的 Always-on 路径是系统设置**（系统自行拉起 VpnService，
 *   免疫该限制），设置页提供深链引导；
 * - intent action 显式用 [HydraVpnService.ACTION_START]（未知 action 不得
   被 service 当启动——见启停修复记录）。
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val cfg = runCatching { SecureStore(context).load() }.getOrElse { return }
        if (cfg.runMode != SecureStore.MODE_VPN || !cfg.vpnBootStart) return
        if (cfg.nodesText.isBlank() || cfg.authKeyHex.isEmpty()) return
        // consent 未授权（清了应用数据/从未授权）→ 静默跳过
        if (VpnService.prepare(context) != null) {
            android.util.Log.i("HydraBoot", "开机自启跳过：VPN 未授权")
            return
        }
        runCatching {
            context.startForegroundService(
                Intent(context, HydraVpnService::class.java)
                    .setAction(HydraVpnService.ACTION_START),
            )
            android.util.Log.i("HydraBoot", "开机自启：已请求启动全局 VPN")
        }.onFailure {
            android.util.Log.w("HydraBoot", "开机自启失败（Android 15+ 可能限制后台启动）: $it")
        }
    }
}
