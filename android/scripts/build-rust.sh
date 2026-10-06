# 交叉编译 libhydra_android.so → android/app/src/main/jniLibs/{abi}/
# 依赖：cargo-ndk（cargo install cargo-ndk）+ NDK（Android Studio SDK Manager 或
# sdkmanager "ndk;28.2.13676358"）。缺 cargo-ndk 时打印提示并以 0 退出——
# 使 gradle 纯 JVM 任务（单测）在无 NDK 环境仍可跑。
set -euo pipefail
cd "$(dirname "$0")/../.."

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "[build-rust] 未安装 cargo-ndk，跳过原生库交叉编译（JVM 单测不受影响）"
    echo "[build-rust] 安装：cargo install cargo-ndk；并准备 NDK 与 target:"
    echo "[build-rust]   rustup target add aarch64-linux-android x86_64-linux-android"
    exit 0
fi

rustup target add aarch64-linux-android x86_64-linux-android

OUT=android/app/src/main/jniLibs
mkdir -p "$OUT/arm64-v8a" "$OUT/x86_64"

# ABI 首发矩阵（设计 v2.1 §6）：arm64-v8a 真机 + x86_64 模拟器
cargo ndk -t arm64-v8a -t x86_64 -o "$OUT" build -p hydra-android --release

echo "[build-rust] 完成：$OUT/{arm64-v8a,x86_64}/libhydra_android.so"
