import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// 桌面 JVM 冒烟单测的动态库目录（Windows dll / Linux so / macOS dylib，
// `cargo build -p hydra-android` 产出；经 JNA 加载）
val rustDebugLibDir: String = file("${rootProject.projectDir}/../target/debug").absolutePath

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "dev.hydra.vpn"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.hydra.vpn"
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.2.2"
        // 首发 ABI（设计 v2.1 §6）：arm64-v8a 真机 + x86_64 模拟器；armeabi-v7a 延后
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
    // cargo-ndk 产物（scripts/build-rust 产出）；目录不存在时不报错
    sourceSets["main"].jniLibs.srcDir("src/main/jniLibs")

    testOptions {
        unitTests.isReturnDefaultValues = true
        // AGP 官方 DSL 注入库搜索路径（withType<Test> 对 AGP 单测任务不生效）：
        // java.library.path + jna.library.path 双保险，跨平台找 hydra_android 动态库
        unitTests.all { test ->
            test.systemProperty("java.library.path", rustDebugLibDir)
            test.systemProperty("jna.library.path", rustDebugLibDir)
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    // 基础图标集（Home/List/Settings/Add/Delete；扩展图标用文案/emoji 替代以免引入 10MB extended 包）
    implementation("androidx.compose.material:material-icons-core")
    implementation(libs.kotlinx.coroutines.android)
    // R8 密钥存储：EncryptedSharedPreferences（Keystore 主密钥 + AES-GCM 文件级加密）
    implementation(libs.androidx.security.crypto)
    // 扫码导入桌面端分享二维码
    implementation(libs.zxing.android.embedded)
    // uniffi 0.29 生成的 Kotlin 绑定经 JNA 调 FFI。必须选 aar 变体（含各 ABI 的
    // libjnidispatch.so）：默认解析到桌面 jar，真机必 UnsatisfiedLinkError。
    implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}") {
        artifact { type = "aar" }
    }

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    // 桌面 JVM 冒烟：JNA 从 java.library.path 加载 target/debug/hydra_android.dll
    testImplementation(libs.jna.jvm)
}

// Kotlin 2.x 统一 DSL（project 级，非 android{} 内）
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// ── Rust 侧任务 ─────────────────────────────────────────────────────────────
// M0 冒烟单测（EngineSmokeTest）在桌面 JVM 跑：加载仓库 target/debug 的
// hydra_android.dll/so（host 架构），经 uniffi 绑定真实启停引擎。
// 交叉编译 .so（进 APK）用 scripts/build-rust.sh，需 NDK + cargo-ndk。
val isWindows = System.getProperty("os.name").lowercase().contains("windows")
tasks.register<Exec>("cargoBuildRelease") {
    description = "cargo-ndk 交叉编译 libhydra_android.so 到 app jniLibs（需 NDK + cargo-ndk）"
    workingDir = file("${rootProject.projectDir}/scripts")
    if (isWindows) {
        commandLine("powershell", "-ExecutionPolicy", "Bypass", "-File", "build-rust.ps1")
    } else {
        commandLine("bash", "build-rust.sh")
    }
}
tasks.named("preBuild") {
    dependsOn("cargoBuildRelease")
}
