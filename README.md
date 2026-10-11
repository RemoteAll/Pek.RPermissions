# Pek.RPermissions（Rust 版权限组装件）

与 C# 端（**Pek.Permissions / DHDeploy**）**同套的 JWT 方案**（NewLife `JwtBuilder` 兼容、字节级互通）。
凡"令牌需要与 C# 生态互认"的 Rust 项目统一引入本库（勿逐仓复制；对齐 `Pek.RAdmin` 的组装件定位）。

## 内容

| 模块 | 说明 |
|---|---|
| `jwt` | HS256 JWT——配置 `算法:密钥`（如 `HS256:xxxx`，密钥不要含冒号）；header `{"alg":"HS256"}`；签名 `HMAC-SHA256(secret, "header.payload")` + base64url 无填充；`exp/iat` 为 Unix 秒；`Jwt::{encode*, validate*}`（`*_at` 版本供测试注入时间）；验签与 C# 一致要求签名段为**规范形态**（URL 安全、无填充） |
| `claims` | 标准 claims（`sub` / `name` / `from` / `clientType`）构造与解析（`Claims::admin/app` 快捷构造） |
| `revoke` | 内存吊销名单（登出即失效；重启清空）；`TokenRevoker::revoke_with(&jwt, token)` 按 exp 保留 |

## 互通验证（C# ↔ Rust）

- 黄金样本（C# `NewLife.Web.JwtBuilder` 实测生成）固化在 `jwt.rs` 单测（含过期/篡改/换密钥反证）；
- 双向互签互验脚本：`Pek.RCard/tools/jwt-interop.ps1` → `=== JWT INTEROP PASSED ===`。

## 安全说明（2026-10-11 审计补强）

- 只按固定 HMAC-SHA256 验签、不读取 header 中的算法（规避 `alg=none` 类攻击）；验签比对为常量时间；
- 签名段必须是**规范形态**（URL 安全、无填充、无空白）——与 C# `enc(...).ToUrlBase64() == ts[2]` 的字符串精确比较口径一致；
- 空密钥在 `Jwt::new` 构造时拒绝（对齐 C#「未设置密钥」）；`JwtOptions` 的 `Debug` 输出对密钥脱敏；
- 吊销名单按**规范化令牌**（签名段解码→重编码）计算键：同一令牌的填充/空白/字母表变体共享一条吊销记录，无法换拼写绕过。

## 接入

```toml
# Cargo.toml
pek-rpermissions = { path = "../Pek.RPermissions" }
```

```rust
use pek_rpermissions::claims::Claims;
use pek_rpermissions::jwt::Jwt;
use pek_rpermissions::revoke::TokenRevoker;

let jwt = Jwt::from_secret("HS256:your-secret")?;           // 与 C# 端配相同密钥即可互认
let token = jwt.encode(&Claims::app(user_id.to_string(), user_name).to_map());
let claims = jwt.validate(&token)?;                          // 验签 + 过期检查

let revoker = TokenRevoker::new();                           // 登出吊销
revoker.revoke_with(&jwt, &token);
assert!(revoker.is_revoked(&token));
```

## 依赖

`dhrust`（加密原语 `hmac_sha256` / `base64url` / `fixed_time_eq`）+ `serde_json` + `chrono`（零额外依赖）。
