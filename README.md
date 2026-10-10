# Pek.RPermissions（Rust 版权限组装件）

与 C# 端（**Pek.Permissions / DHDeploy**）**同套的 JWT 方案**（NewLife `JwtBuilder` 兼容、字节级互通）。
凡"令牌需要与 C# 生态互认"的 Rust 项目统一引入本库（勿逐仓复制；对齐 `Pek.RAdmin` 的组装件定位）。

## 内容

| 模块 | 说明 |
|---|---|
| `jwt` | HS256 JWT——配置 `算法:密钥`（如 `HS256:xxxx`，密钥不要含冒号）；header `{"alg":"HS256"}`；签名 `HMAC-SHA256(secret, "header.payload")` + base64url 无填充；`exp/iat` 为 Unix 秒；`Jwt::{encode*, validate*}`（`*_at` 版本供测试注入时间） |
| `claims` | 标准 claims（`sub` / `name` / `from` / `clientType`）构造与解析（`Claims::admin/app` 快捷构造） |
| `revoke` | 内存吊销名单（登出即失效；重启清空）；`TokenRevoker::revoke_with(&jwt, token)` 按 exp 保留 |

## 互通验证（C# ↔ Rust）

- 黄金样本（C# `NewLife.Web.JwtBuilder` 实测生成）固化在 `jwt.rs` 单测（含过期/篡改/换密钥反证）；
- 双向互签互验脚本：`Pek.RCard/tools/jwt-interop.ps1` → `=== JWT INTEROP PASSED ===`。

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
