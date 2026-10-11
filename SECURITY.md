# 安全政策（Security Policy）

## 支持版本

| 版本 | 支持状态 |
|---|---|
| 0.2.x | ✅ |
| < 0.2 | ❌ |

## 漏洞报告

**请勿通过公开 GitHub Issues 报告安全漏洞。**

报告方式：通过 GitHub [Security Advisories](https://github.com/fuzhusi/Hydra-Multipath-Proxy/security/advisories/new) 私密报告。

**响应说明（如实）**：本项目为个人维护，无法承诺商业化 SLA（如"72 小时确认、7 天修复"）。
报告会收到确认，但修复时间取决于维护者的空闲程度——可能是几天，也可能更久；
严重问题会优先，有空即修。若需确定性时效，请自行 fork 修复。

## 安全设计说明

本项目传输安全基于 TLS 1.3 + Noise-PSK（前向安全），所有隧道流量端到端加密。
密钥材料存储：Android = Android Keystore（硬件级），Unix = 0600 文件，Windows = 用户目录 ACL。

## 已知限制（如实声明）

- Windows GUI 密钥明文落盘（依赖目录 ACL，DPAPI 加密待做）
- 单一 PSK 全设备共享（无按用户隔离）
- 本项目不防本机 root/administrator 攻击者
