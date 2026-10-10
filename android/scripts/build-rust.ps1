# 交叉编译 libhydra_android.so → android/app/src/main/jniLibs/{abi}/（Windows 版）
# 依赖：cargo-ndk（cargo install cargo-ndk）+ NDK。缺 cargo-ndk 时打印提示并以 0 退出。
$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot "..\.."

if (-not (Get-Command cargo-ndk -ErrorAction SilentlyContinue)) {
    Write-Host "[build-rust] 未安装 cargo-ndk，跳过原生库交叉编译（JVM 单测不受影响）"
    Write-Host "[build-rust] 安装：cargo install cargo-ndk；并准备 NDK 与 target:"
    Write-Host "[build-rust]   rustup target add aarch64-linux-android x86_64-linux-android"
    exit 0
}

rustup target add aarch64-linux-android x86_64-linux-android
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $null
# NDK 缺失同样跳过（JVM 单测不需要交叉编译产物）
$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = "$env:LOCALAPPDATA\Android\Sdk" }
$ndkDirs = Get-ChildItem -Directory -Path (Join-Path $sdk "ndk") -ErrorAction SilentlyContinue
if (-not $ndkDirs) {
    Write-Host "[build-rust] 未检测到 NDK（$sdk\ndk 为空），跳过交叉编译"
    Write-Host "[build-rust] 安装：Android Studio SDK Manager 或 sdkmanager ndk;28.2.13676358"
    exit 0
}

# 输出必须用绝对路径（$root = 仓库根）：Gradle 调本脚本时 CWD 是 android/scripts/
# 而非仓库根，相对路径会把 .so 写进 android/scripts/android/ 嵌套目录（审查修复）
$out = Join-Path $root "android/app/src/main/jniLibs"
New-Item -ItemType Directory -Force -Path "$out/arm64-v8a", "$out/x86_64" | Out-Null

cargo ndk -t arm64-v8a -t x86_64 -o $out build -p hydra-android --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[build-rust] 完成：$out/{arm64-v8a,x86_64}/libhydra_android.so"
