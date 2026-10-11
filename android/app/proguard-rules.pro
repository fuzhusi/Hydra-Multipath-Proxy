# Hydra Android R8 规则（评审 R 项：uniffi 生成绑定需 keep）

# uniffi：FFI 入口经 JNI 反射调用，禁止混淆/剔除
-keep class uniffi.** { *; }
-dontwarn uniffi.**

# jni：Rust 侧 JNIEnv 按名查找
-keepclasseswithmembernames class * {
    native <methods>;
}

# JNA（uniffi 绑定经 JNA 调 FFI）：反射重度使用，禁止混淆/剔除
-keep class com.sun.jna.** { *; }
-dontwarn com.sun.jna.**
-keepclassmembers class * extends com.sun.jna.** { *; }
# Tink/Guava（security-crypto 依赖）的编译期注解类不在运行时 classpath：
# 仅注解引用，R8 缺类报错用 dontwarn 安全豁免（企业评审修复轮）
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
-dontwarn org.checkerframework.**
-dontwarn com.google.j2objc.annotations.**