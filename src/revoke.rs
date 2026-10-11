//! 令牌吊销名单（登出即失效；**重启即清空**——JWT 无状态会话的既定权衡，与 C# 侧"缓存存储"语义一致）。
//!
//! 键为**规范化令牌**的 SHA-256（不存原文；签名段容错解码后按 URL 安全、无填充重编码——
//! 同一令牌的填充/空白变体共享一个吊销记录，堵"换拼写绕过吊销"的路径；2026-10-11 审计补强）；
//! 每条记录保留至其 `exp`，插入时顺带清理过期项。

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
            m.insert(token_key(token), until);
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
            Ok(m) => m.contains_key(&token_key(token)),
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

/// 名单键：令牌 → 规范化原文 → SHA-256（十六进制；2026-10-11 审计补强，详见 `canonical_token`）。
fn token_key(token: &str) -> String {
    dhrust::sign::sha256_hex(canonical_token(token).as_bytes())
}

/// 规范化令牌：仅将**签名段**容错解码后按 URL 安全、无填充重编码（其余两段参与 HMAC 原文，
/// 改动即验签失败、无需规范化）；非三段或签名段无法解码时按原文兜底。
///
/// 例：`H.P.S`、`H.P.S=`、`H.P.S<换行>` 规范化为同一 `H.P.S`——吊销记录因此对拼写变体免疫。
fn canonical_token(token: &str) -> String {
    let mut segs = token.splitn(3, '.');
    let (Some(h), Some(p), Some(s)) = (segs.next(), segs.next(), segs.next()) else {
        return token.to_string();
    };
    let Some(sig) = dhrust::sign::base64_decode(s) else {
        return token.to_string();
    };
    format!("{h}.{p}.{}", dhrust::sign::base64_url_no_pad(&sig))
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

    #[test]
    fn respelled_signature_shares_revocation_key() {
        let jwt = Jwt::from_secret("HS256:respelled-test").unwrap();
        let token = jwt.encode_at(&serde_json::Map::new(), 60, crate::now_ts());
        let revoker = TokenRevoker::new();

        // 规范令牌入名单 → 补 `=` 填充的变体同样命中
        revoker.revoke(&token, crate::now_ts() + 3600);
        assert!(revoker.is_revoked(&format!("{token}=")), "补填充变体应命中同一记录");

        // 签名段插入空白 → 同样命中
        let (h, rest) = token.split_once('.').unwrap();
        let (p, s) = rest.split_once('.').unwrap();
        let spaced = format!("{}\n{}", &s[..5], &s[5..]);
        assert!(revoker.is_revoked(&format!("{h}.{p}.{spaced}")), "含空白变体应命中同一记录");

        // 反向：以变体吊销 → 规范原文同样命中（双向一致）
        let revoker2 = TokenRevoker::new();
        revoker2.revoke(&format!("{token}="), crate::now_ts() + 3600);
        assert!(revoker2.is_revoked(&token));
    }
}
