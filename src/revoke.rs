//! 令牌吊销名单（登出即失效；**重启即清空**——JWT 无状态会话的既定权衡，与 C# 侧"缓存存储"语义一致）。
//!
//! 键为令牌的 SHA-256（不存原文）；每条记录保留至其 `exp`，插入时顺带清理过期项。

use std::collections::HashMap;
use std::sync::Mutex;

use crate::jwt::Jwt;

/// 内存吊销名单（线程安全）。
#[derive(Default)]
pub struct TokenRevoker {
    inner: Mutex<HashMap<String, i64>>,
}

impl TokenRevoker {
    /// 新建空名单。
    pub fn new() -> Self {
        Self::default()
    }

    /// 吊销令牌（保留至 `until` Unix 秒；插入时顺带清理已过期项）。
    pub fn revoke(&self, token: &str, until: i64) {
        let now = crate::now_ts();
        if let Ok(mut m) = self.inner.lock() {
            m.retain(|_, t| *t > now);
            m.insert(dhrust::sign::sha256_hex(token.as_bytes()), until);
        }
    }

    /// 吊销令牌并按 `jwt` 解析其 `exp`（已过期/无法解析时按 24 小时兜底）。
    pub fn revoke_with(&self, jwt: &Jwt, token: &str) {
        let now = crate::now_ts();
        let exp = jwt
            .validate(token)
            .ok()
            .and_then(|c| c.get("exp").and_then(|v| v.as_i64()))
            .filter(|exp| *exp > now)
            .unwrap_or(now + 24 * 3600);
        self.revoke(token, exp);
    }

    /// 令牌是否已被吊销。
    pub fn is_revoked(&self, token: &str) -> bool {
        match self.inner.lock() {
            Ok(m) => m.contains_key(&dhrust::sign::sha256_hex(token.as_bytes())),
            Err(_) => false,
        }
    }

    /// 当前名单容量（测试/诊断用）。
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// 名单是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::Jwt;

    #[test]
    fn revoke_and_check() {
        let revoker = TokenRevoker::new();
        assert!(revoker.is_empty());
        revoker.revoke("token-a", crate::now_ts() + 3600);
        assert!(revoker.is_revoked("token-a"));
        assert!(!revoker.is_revoked("token-b"));
        assert_eq!(revoker.len(), 1);
    }

    #[test]
    fn expired_entries_are_cleaned_on_revoke() {
        let revoker = TokenRevoker::new();
        // 写入一条"立即过期"的记录（until 在过去）
        revoker.revoke("old", crate::now_ts() - 1);
        assert!(revoker.is_revoked("old"), "插入后仍在名单中");
        // 再吊销一条 → 清理过期项
        revoker.revoke("new", crate::now_ts() + 100);
        assert!(!revoker.is_revoked("old"), "过期项应被清理");
        assert!(revoker.is_revoked("new"));
        assert_eq!(revoker.len(), 1);
    }

    #[test]
    fn revoke_with_parses_exp() {
        let jwt = Jwt::from_secret("HS256:revoke-test").unwrap();
        let token = jwt.encode_at(&serde_json::Map::new(), 60, crate::now_ts());
        let revoker = TokenRevoker::new();
        revoker.revoke_with(&jwt, &token);
        assert!(revoker.is_revoked(&token));
        // 非法令牌 → 兜底 24 小时，同样进名单
        revoker.revoke_with(&jwt, "not-a-token");
        assert!(revoker.is_revoked("not-a-token"));
        assert_eq!(revoker.len(), 2);
    }
}
