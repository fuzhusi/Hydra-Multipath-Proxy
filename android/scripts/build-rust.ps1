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
$out = "android/app/src/main/jniLibs"
New-Item -ItemType Directory -Force -Path "$out/arm64-v8a", "$out/x86_64" | Out-Null

cargo ndk -t arm64-v8a -t x86_64 -o $out build -p hydra-android --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[build-rust] 完成：$out/{arm64-v8a,x86_64}/libhydra_android.so"
