package dev.hydra.vpn

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import java.util.Base64

/**
 * M1 主界面：节点配置（落 EncryptedSharedPreferences）→ 前台服务启停引擎 →
 * 状态卡（监听地址/流量/连接数）。
 *
 * M1 使用模型：引擎在本机 [boundAddr] 监听 SOCKS5/HTTP——手机浏览器（如
 * Firefox Android）手动配代理指向该地址即可走节点出网。M2 全局 VPN（TUN）
 * 上线后无需手动配代理。
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 通知权限（API 33+）：前台服务通知需要
        if (Build.VERSION.SDK_INT >= 33 &&
            ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        setContent { HydraApp() }
    }
}

@Composable
private fun HydraApp() {
    val context = LocalContext.current
    val store = remember { SecureStore(context) }
    val saved = remember { store.load() }

    var nodesText by remember { mutableStateOf(saved.nodesText) }
    var authKey by remember { mutableStateOf(saved.authKeyHex) }
    var sni by remember { mutableStateOf(saved.sni) }
    var trustMode by remember { mutableStateOf(saved.trustMode) }
    var certB64 by remember { mutableStateOf(saved.certDerB64) }
    var listenPort by remember {
        mutableStateOf(saved.listenPort.takeIf { it != 0 }?.toString() ?: SecureStore.DEFAULT_PORT.toString())
    }
    var showKey by remember { mutableStateOf(false) }

    val ui by EngineState.ui.collectAsState()

    val certPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            context.contentResolver.openInputStream(uri)?.use { ins ->
                val der = ins.readBytes()
                certB64 = Base64.getEncoder().encodeToString(der)
                Toast.makeText(context, "证书已导入（${der.size} 字节）", Toast.LENGTH_SHORT).show()
            }
        }
    }

    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Hydra", style = MaterialTheme.typography.headlineMedium)
            Text(
                "M1 · 本地 SOCKS5/HTTP 代理引擎\n浏览器手动配代理到下方监听地址即可",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ── 配置区 ──────────────────────────────────────────────────────
            OutlinedTextField(
                value = nodesText,
                onValueChange = { nodesText = it },
                label = { Text("节点（每行一条 addr:port）") },
                placeholder = { Text("1.2.3.4:443") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
            )
            OutlinedTextField(
                value = authKey,
                onValueChange = { authKey = it.trim() },
                label = { Text("认证密钥（64 hex）") },
                visualTransformation = if (showKey) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    TextButton(onClick = { showKey = !showKey }) {
                        Text(if (showKey) "隐藏" else "显示")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = sni,
                onValueChange = { sni = it },
                label = { Text("SNI（留空 = hydra.node）") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = trustMode == SecureStore.TRUST_PINNED,
                    onClick = { trustMode = SecureStore.TRUST_PINNED },
                    label = { Text("自签 pin") },
                )
                FilterChip(
                    selected = trustMode == SecureStore.TRUST_CA,
                    onClick = { trustMode = SecureStore.TRUST_CA },
                    label = { Text("真证书 CA") },
                )
            }
            if (trustMode == SecureStore.TRUST_PINNED) {
                OutlinedButton(onClick = { certPicker.launch(arrayOf("*/*")) }) {
                    Text(if (certB64.isEmpty()) "导入节点证书 DER" else "已导入证书 ✓（重新选）")
                }
            }
            OutlinedTextField(
                value = listenPort,
                onValueChange = { listenPort = it.filter(Char::isDigit).take(5) },
                label = { Text("本地监听端口（1080）") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            fun persist() {
                store.save(
                    HydraConfig(
                        nodesText = nodesText, authKeyHex = authKey, sni = sni,
                        trustMode = trustMode, certDerB64 = certB64,
                        listenPort = listenPort.toIntOrNull() ?: SecureStore.DEFAULT_PORT,
                    ),
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    persist()
                    Toast.makeText(context, "配置已加密保存", Toast.LENGTH_SHORT).show()
                }) { Text("保存配置") }
            }

            // ── 启停 ────────────────────────────────────────────────────────
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        // 启动前先落盘（服务从 SecureStore 读配置）
                        persist()
                        val intent = Intent(context, EngineService::class.java)
                            .setAction(EngineService.ACTION_START)
                        if (Build.VERSION.SDK_INT >= 26) {
                            context.startForegroundService(intent)
                        } else {
                            context.startService(intent)
                        }
                    },
                    enabled = !ui.running && ui.transition == null,
                ) { Text("▶ 启动") }
                OutlinedButton(
                    onClick = {
                        context.startService(
                            Intent(context, EngineService::class.java)
                                .setAction(EngineService.ACTION_STOP),
                        )
                    },
                    enabled = ui.running || ui.transition != null,
                ) { Text("■ 停止") }
            }

            // ── 状态卡 ──────────────────────────────────────────────────────
            StatusCard(ui = ui, onCopy = { addr ->
                val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("hydra", addr))
                Toast.makeText(context, "已复制 $addr", Toast.LENGTH_SHORT).show()
            })

            ui.transition?.let { msg ->
                Text(
                    msg,
                    color = if (msg.startsWith("启动失败")) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun StatusCard(ui: EngineState.Ui, onCopy: (String) -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text("状态", style = MaterialTheme.typography.titleMedium)
        Text(
            if (ui.running) "● 运行中" else "○ 已停止",
            color = if (ui.running) Color(0xFF2E7D32) else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (ui.running) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("监听：${ui.boundAddr ?: "…"}", fontFamily = FontFamily.Monospace)
                ui.boundAddr?.let { addr ->
                    TextButton(onClick = { onCopy(addr) }) { Text("复制") }
                }
            }
            Text("↑ ${fmt(ui.sentBytes)}   ↓ ${fmt(ui.receivedBytes)}", fontFamily = FontFamily.Monospace)
            Text("连接：活跃 ${ui.activeConns} / 累计 ${ui.totalConns}   运行 ${ui.uptimeSecs}s")
        }
    }
}

private fun fmt(bytes: Long): String = when {
    bytes >= 1 shl 20 -> "%.1f MB".format(bytes.toDouble() / (1 shl 20))
    bytes >= 1 shl 10 -> "%.1f KB".format(bytes.toDouble() / (1 shl 10))
    else -> "$bytes B"
}
