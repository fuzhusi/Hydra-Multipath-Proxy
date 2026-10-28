package dev.hydra.vpn.ui

import android.content.Context
import dev.hydra.vpn.EngineState
import dev.hydra.vpn.SecureStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import uniffi.hydra_android.parseShareText

/*
 * 分享导入（R11 拆分去处）：Activity 深链与 Compose 粘贴/扫码共用。
 * 目录 ui/import/（Kotlin 包名不能含硬关键字 `import`，故包名取 dev.hydra.vpn.ui）。
 */

/** 导入成功反馈总线（R5 深链导入动线）：首页 Snackbar + 节点 Tab 徽标同源。 */
object ImportFeedback {
    /** 最近一次成功导入的节点数；消费方展示后置 null 防重复。 */
    val importedNodes = MutableStateFlow<Int?>(null)
}

/** 导入逻辑唯一实现：深链（hydra://）与节点页粘贴/扫码共用。 */
object ShareImporter {
    suspend fun import(context: Context, text: String): String =
        withContext(Dispatchers.IO) {
            try {
                val p = parseShareText(text.trim())
                val store = SecureStore(context)
                val cur = store.load()
                // 合并而非替换：手动添加的节点不因导入丢失；链接节点去重后追加
                val existing = cur.nodesText.lines().map { it.trim() }.filter { it.isNotEmpty() }
                val mergedNodes = (existing + p.nodes.filter { it !in existing })
                    .joinToString("\n")
                val merged = cur.copy(
                    nodesText = mergedNodes,
                    authKeyHex = p.authKeyHex.ifEmpty { cur.authKeyHex },
                    certDerB64 = p.certDerB64.ifEmpty { cur.certDerB64 },
                    // 按节点证书：各链接携带的 cc= 写入**各自地址**的条目，多节点
                    // 独立证书互不覆盖（ISSUE 安卓多节点证书）；同地址重复导入
                    // 以新为准——证书漂移的修复路径。全局 certDerB64 仍保留
                    // （单证书部署惯例 + 无 cc 手动节点的回落承接）
                    nodeCertB64Map = if (p.nodeCerts.isEmpty()) cur.nodeCertB64Map
                        else cur.nodeCertB64Map + p.nodeCerts,
                    // 紧凑链接（cf= 指纹）按节点记录——节点行显示预期指纹、
                    // 与本地证书比对可确认信任锚/诊断证书漂移
                    nodeCertFpMap = if (p.nodeCertFps.isEmpty()) cur.nodeCertFpMap
                        else cur.nodeCertFpMap + p.nodeCertFps,
                )
                store.save(merged)
                val extra = buildString {
                    if (p.authKeyHex.isNotEmpty()) append("，密钥✓")
                    if (p.nodeCerts.isNotEmpty()) append("，证书✓×${p.nodeCerts.size}")
                    else if (p.certDerB64.isNotEmpty()) append("，证书✓")
                    // 紧凑链接（仅指纹）：明确告知需另行导入证书本体
                    if (p.nodeCertFps.isNotEmpty() && p.nodeCerts.isEmpty()) {
                        append("，证书指纹✓×${p.nodeCertFps.size}（紧凑链接未带证书本体——" +
                            "请在设置页导入证书 DER，或向管理员索取完整分享链接）")
                    }
                    if (p.skipped > 0u) append("（跳过 ${p.skipped} 条：域名节点/坏行）")
                }
                if (p.nodes.isNotEmpty()) {
                    ImportFeedback.importedNodes.value = p.nodes.size
                }
                EngineState.addLog("导入成功：${p.nodes.size} 个节点$extra")
                "导入成功：${p.nodes.size} 个节点$extra"
            } catch (e: Exception) {
                EngineState.addLog("导入失败：${e.message}")
                "导入失败：${e.message}"
            }
        }
}
