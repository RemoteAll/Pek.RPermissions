# Pek.RPermissions · 项目指令

> 全项目通用规则见用户级《跨项目接续协议》（本机 `%APPDATA%\Code\User\prompts\跨项目接续协议.instructions.md`；模板在 `tools/continuity/templates/`）。
> **开工先读（存在则读，按序）**：`.github/copilot-instructions.md` → `docs/项目接续指南.md` → `docs/用户档案.md` → `docs/项目记忆.md` → `docs/审计记录.md` 最新节。

## 项目速览

- **定位**：Pek 生态权限组装件（Rust）——与 C# 端（Pek.Permissions / DHDeploy 使用的 NewLife `JwtBuilder`）**同套 JWT 方案、字节级互通**的公共库。凡"令牌需与 C# 生态互认"的 Rust 项目统一引入本库（**勿逐仓复制**；对齐 `Pek.RAdmin` 的组装件模式）。
- **技术栈**：crate `pek-rpermissions`（edition 2024）；依赖 `dhrust`（path `../DH.RustBase`）+ `serde_json` + `chrono`；模块 `jwt` / `claims` / `revoke`。
- **消费方**：Pek.RCard（首个消费方，path 依赖）；互通验证脚本在 `Pek.RCard/tools/jwt-interop.ps1`。

## 关键约定（改动前必读）

- **互通是最高红线**：header `{"alg":"HS256"}` 紧凑 JSON；`exp`/`iat` 为 Unix 秒；签名 = `HMAC-SHA256(secret UTF-8 字节, "header.payload")` → **URL 安全 Base64 无填充**；密钥格式「算法:密钥」（`Split(':')` 取第二段；**密钥不要含冒号**）。
- **验签按规范形态**（2026-10-11 审计定稿）：签名段必须是 URL 安全、无填充原文（拒绝 `=` 填充/空白/标准字母表变体）——对齐 C# `enc(...).ToUrlBase64() == ts[2]` 的字符串精确比较；改动前先读 `src/jwt.rs` 模块文档与 `docs/审计记录.md`。
- **安全约定**：固定 HMAC-SHA256、不读 header 算法；验签常量时间比较；密钥不落 `Debug`；吊销名单键=规范化令牌哈希（重启清空为既定权衡）。
- **改 JWT/互通行为必须实跑** `Pek.RCard/tools/jwt-interop.ps1`（C#↔Rust 双向，期望 `=== JWT INTEROP PASSED ===`），并维护 C# 黄金样本单测。
- 中文 `.ps1` 必须 **UTF-8 with BOM**；公共能力优先下沉 `dhrust::sign`，本库只承载权限/JWT 约定。

## 构建与验证

```powershell
cargo test                                          # 13 项（含 C# 黄金样本）
cargo clippy --all-targets -- -D warnings
powershell -NoProfile -File G:\Code\Rust\Pek.RCard\tools\jwt-interop.ps1   # 跨仓互通 E2E（需 dotnet）
```

## 每轮收尾（务必）

① `docs/审计记录.md` 新增一节（**含用户原话**）；② `tools/continuity/sync-memory.ps1` 同步记忆（需在项目根目录运行或传 `-ProjectPath`）；③ 跑回归验证并如实汇报。
