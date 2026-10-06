import org.jetbrains.kotlin.gradle.dsl.JvmTarget

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
        versionCode = 1
        versionName = "0.1.0"
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
    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }
    buildFeatures {
        compose = true
    }
    // cargo-ndk 产物（scripts/build-rust 产出）；目录不存在时不报错
    sourceSets["main"].jniLibs.srcDir("src/main/jniLibs")

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}

// ── Rust 侧任务 ─────────────────────────────────────────────────────────────
// M0 冒烟单测（EngineSmokeTest）在桌面 JVM 跑：加载仓库 target/debug 的
// hydra_android.dll/so（host 架构），经 uniffi 绑定真实启停引擎。
// 交叉编译 .so（进 APK）用 scripts/build-rust.sh，需 NDK + cargo-ndk。
val rustDebugLibDir: String = file("${rootProject.projectDir}/../target/debug").absolutePath

tasks.withType<Test>().configureEach {
    systemProperty("java.library.path", rustDebugLibDir)
    // Windows 上 JVM 找 hydra_android.dll；Linux/macOS 同机制找对应后缀
}

tasks.register<Exec>("cargoBuildRelease") {
    description = "cargo-ndk 交叉编译 libhydra_android.so 到 app jniLibs（需 NDK + cargo-ndk）"
    workingDir = file("${rootProject.projectDir}/scripts")
    when {
        org.gradle.internal.os.OperatingSystem.current().isWindows -> {
            commandLine("powershell", "-ExecutionPolicy", "Bypass", "-File", "build-rust.ps1")
        }
        else -> commandLine("bash", "build-rust.sh")
    }
}
tasks.named("preBuild") {
    dependsOn("cargoBuildRelease")
}
