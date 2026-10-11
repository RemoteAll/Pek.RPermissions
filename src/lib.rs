//! Pek.RPermissions（Rust 版权限组装件）：**与 C# 端（Pek.Permissions / DHDeploy）同套的 JWT 方案**。
//!
//! 定位（对齐 `Pek.RAdmin` 的组装件模式）：凡"令牌需要与 C# 生态互认"
//! 的 Rust 项目一律引入本库、勿逐仓复制实现；基础加密原语在 `dhrust::sign`，本库只承载权限体系约定。
//!
//! - [`jwt`]：NewLife `JwtBuilder` 兼容 JWT（HS256，字节级互通；C# 黄金样本固化在单测）；
//! - [`claims`]：标准 claims（`sub` / `name` / `from` / `clientType`）构造与解析；
//! - [`revoke`]：内存吊销名单（登出即失效；重启清空——JWT 无状态会话的既定权衡）。
//!
//! 互通验证：`Pek.RCard/tools/jwt-interop.ps1`（C# 真实 `NewLife.Web.JwtBuilder` ↔ 本库，双向互签互验）。

pub mod claims;
pub mod jwt;
pub mod revoke;

/// 当前 Unix 秒。
pub(crate) fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}
