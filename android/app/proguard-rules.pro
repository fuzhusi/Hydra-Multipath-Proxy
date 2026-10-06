# Hydra Android R8 规则（评审 R 项：uniffi 生成绑定需 keep）

# uniffi：FFI 入口经 JNI 反射调用，禁止混淆/剔除
-keep class uniffi.** { *; }
-dontwarn uniffi.**

# jni：Rust 侧 JNIEnv 按名查找
-keepclasseswithmembernames class * {
    native <methods>;
}
