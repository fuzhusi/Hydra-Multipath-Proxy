# Hydra Android

Hydra 移动端工程（Kotlin + Jetpack Compose 壳，Rust core 经 uniffi 绑定）。
架构与里程碑见 `../docs/design/移动端Android方案-v2.md`（v2.1，已评审）。

## 结构

```
android/
├── app/                          # 唯一 app 模块
│   ├── build.gradle.kts          # abiFilters: arm64-v8a + x86_64；JVM 单测注入 java.library.path
│   ├── proguard-rules.pro        # uniffi/JNI keep 规则
│   └── src/
│       ├── main/kotlin/dev/hydra/vpn/    # 应用代码（M0：骨架 MainActivity）
│       ├── main/kotlin/uniffi/hydra_android/ # uniffi 生成绑定（勿手改，脚本再生成）
│       ├── test/kotlin/dev/hydra/vpn/    # JVM 冒烟测试（桌面加载 host 动态库跑 uniffi 启停）
│       └── main/jniLibs/         # cargo-ndk 产物（gitignore，构建脚本生成）
├── scripts/
│   ├── build-rust.sh / .ps1      # cargo-ndk 交叉编译 libhydra_android.so → jniLibs
│   └── gen-bindings.sh           # uniffi Kotlin 绑定再生成
└── gradle/libs.versions.toml     # 版本集中管理
```

Rust 侧：`../hydra-android`（cdylib + uniffi 导出 HydraEngine）依赖 `../hydra-core`
（跨平台核心，桌面与 Android 共用）。

## 环境准备

1. JDK 17+（Android Studio 自带 JBR 可用）
2. Android SDK（platform 36 / build-tools），`android/local.properties` 写 `sdk.dir`
3. 原生交叉编译（进 APK 必需；纯 JVM 单测不需要）：
   ```
   cargo install cargo-ndk
   rustup target add aarch64-linux-android x86_64-linux-android
   # NDK 经 Android Studio SDK Manager 安装，或 sdkmanager "ndk;28.x"
   ```

## 常用命令

```bash
# 0) 一次性：先在仓库根构建 host 动态库（供 JVM 冒烟加载）
cargo build -p hydra-android

# 1) 桌面 JVM 冒烟：Kotlin 经 uniffi/JNA 启停引擎（无需设备/NDK）
cd android && ./gradlew :app:testDebugUnitTest

# 2) 交叉编译原生库并打 debug 包（需 cargo-ndk + NDK）
./gradlew :app:assembleDebug
```

环境注记（Windows 实测）：
- Gradle 9.5.1（wrapper 自带分发下载；**9.6+ 与 AGP 8.13 不兼容**，升级 AGP 前勿动）
- JAVA_HOME 可指向 Android Studio 自带 JBR
- 国内网络建议给 gradle 加镜像 init 脚本（google/mavenCentral → 阿里云），
  否则依赖下载极慢；distributionUrl 亦可换腾讯镜像
  `https://mirrors.cloud.tencent.com/gradle/gradle-9.5.1-bin.zip`
- `scripts/build-rust.ps1` 需 UTF-8 BOM 编码（PowerShell GBK 环境解析中文注释）

## 当前状态（M0）

- hydra-core 抽取完成，桌面全量测试绿
- HydraEngine uniffi 接口：start/stop/stats + SocketProtect 防环回回调（R4，
  运行时接线随 M2 tun_core）
- M1（Compose 节点表单 + 进程内 SOCKS 可用）、M2（VpnService 全局 VPN）未开工
