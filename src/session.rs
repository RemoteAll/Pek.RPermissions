//! 会话登记与吊销（**JWT 始终有效；外部存储只做「登记 / 吊销 / 共享」**）。
//!
//! # 口径（2026-10-24 定稿）
//! 1. 令牌**永远是 JWT**（与 C# `Pek.Permissions` / DHDeploy 互认；进程重启、换机器都不掉线）；
//! 2. 外部存储（Redis / 数据库 / 内存）**不保存令牌本体**，只保存「这个令牌还在不在 / 何时到期 / 口令指纹 / 客户端」；
//!    键名用**令牌的 SHA-256**（不存原文），即使存储被读走也拿不到可用令牌；
//! 3. 存储不可用 → 自动回到「纯 JWT」模式（验签+过期即放行），**绝不因为缓存挂了把所有人挡在外面**；
//! 4. 存储可用时：登出即删记录 → 令牌即刻失效（JWT 本身没法撤销，靠这条记录实现）。
//!
//! # 客户端（端）区分
//! 登录时登记 `client`（`web` / `app` / `h5` / `mini` / `pos` …），支持：
//! - **按端踢线**：`revoke_client(uid, client)` 只让该端失效（如只踢手机端、留 Web）；
//! - **全部踢线**：`revoke_user(uid)` 一次清掉该账号所有端；
//! - **在线会话列表**：`sessions(uid)` 给后台展示「这个账号在哪几端登录」。
//!
//! 版本号有两级（都是 O(1)，不需要遍历令牌）：全局 `userver:{uid}` 与按端 `userver:{uid}:{client}`，
//! 令牌记录里同时带 `ver` / `cver`，任一不匹配即失效。
//!
//! # 滑动续期与安全边界
//! - 空闲（`idle_secs`）不动才失效，活跃时按「剩余不足一半」才刷新一次，**不是每请求都写**；
//! - **绝对上限**（`max_secs`）：无论多活跃，登记满上限后必须重新登录（防无限续期）；
//! - **口令指纹**（`pwd_tag`）：改密后旧记录对不上 → 旧会话全部失效，无需遍历删令牌。
//!
//! # 设备/模组不要用这套
//! IoT 设备、模组、扫码枪等**没有“人”的凭据**应走设备凭据（deviceId + secret/证书 + 设备 ACL），
//! 与账号会话分离——一次刷机/复制不应污染账号安全模型。

use std::sync::Arc;

/// 外部存储抽象（Redis / 数据库 / 内存均可实现）。
///
/// 约定：所有方法失败时返回 `None` / `false`，**不要 panic**（缓存故障不能影响业务）。
/// 集合类方法给了默认实现（返回空/失败）——不支持集合的存储只需实现前四个基础方法，
/// 代价是失去「在线会话列表」，不影响登记/吊销/踢线。
pub trait SessionStore: Send + Sync {
    /// 存储是否可用（不可用时按「纯 JWT」放行，不能当作「已吊销」）。
    fn available(&self) -> bool;
    /// 读取记录（JSON 文本）。
    fn get(&self, key: &str) -> Option<String>;
    /// 写入记录并设置过期（秒）。
    fn set(&self, key: &str, value: &str, ttl_secs: i64) -> bool;
    /// 删除记录（登出）。
    fn del(&self, key: &str) -> bool;

    /// 加入集合（用户 → 其令牌散列）；可选能力。
    fn sadd(&self, _key: &str, _member: &str, _ttl_secs: i64) -> bool {
        false
    }
    /// 从集合移除；可选能力。
    fn srem(&self, _key: &str, _member: &str) -> bool {
        false
    }
    /// 读取集合成员；可选能力。
    fn smembers(&self, _key: &str) -> Vec<String> {
        Vec::new()
    }
}

/// 会话策略。
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    /// 空闲有效期（秒）；`<=0` 表示不做滑动续期
    pub idle_secs: i64,
    /// 绝对上限（秒）；`<=0` 表示不限制
    pub max_secs: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_secs: 7 * 24 * 3600,
            max_secs: 30 * 24 * 3600,
        }
    }
}

/// 会话校验结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// 存储可用且记录有效（附口令指纹与客户端）
    Active { pwd_tag: String, client: String },
    /// 存储可用但记录不存在 / 已过期 / 已踢线 → **拒绝**
    Invalid,
    /// 存储不可用 → 调用方按「纯 JWT」处理（验签 + 过期）
    Untracked,
}

/// 一条在线会话（后台展示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// 客户端（web/app/h5/…）
    pub client: String,
    /// 登录时间（Unix 秒）
    pub iat: i64,
    /// 空闲到期（Unix 秒）
    pub exp: i64,
}

/// 会话登记器：把 JWT 与「可撤销」结合起来。
pub struct SessionKeeper {
    store: Option<Arc<dyn SessionStore>>,
    key_prefix: String,
    policy: SessionPolicy,
}

impl SessionKeeper {
    /// 构造。`store=None` 即纯 JWT 模式（不做登记/吊销）。
    pub fn new(store: Option<Arc<dyn SessionStore>>, key_prefix: &str, policy: SessionPolicy) -> Self {
        Self {
            store,
            key_prefix: key_prefix.to_string(),
            policy,
        }
    }

    /// 令牌键：**存令牌的 SHA-256**（不存原文）。
    fn key(&self, token: &str) -> String {
        format!(
            "{}session:{}",
            self.key_prefix,
            dhrust::sign::sha256_hex(token.as_bytes())
        )
    }

    /// 全局令牌版本键（一次踢掉所有端）。
    fn user_ver_key(&self, uid: i64) -> String {
        format!("{}userver:{uid}", self.key_prefix)
    }

    /// 按端令牌版本键（只踢某一端）。
    fn client_ver_key(&self, uid: i64, client: &str) -> String {
        format!("{}userver:{uid}:{}", self.key_prefix, client)
    }

    /// 用户在线会话索引（集合：成员 = 令牌散列键）。
    fn index_key(&self, uid: i64) -> String {
        format!("{}sessions:{uid}", self.key_prefix)
    }

    fn ver(&self, store: &Arc<dyn SessionStore>, key: &str) -> i64 {
        store
            .get(key)
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0)
    }

    /// 版本键 TTL（取绝对上限，避免版本键先过期导致旧令牌“复活”）。
    fn ver_ttl(&self) -> i64 {
        if self.policy.max_secs > 0 {
            self.policy.max_secs
        } else {
            self.policy.idle_secs.max(3600)
        }
    }

    /// 存储方式（`store` / `jwt`）。
    pub fn store_kind(&self) -> &'static str {
        match (&self.store, self.store.as_ref().map(|s| s.available())) {
            (Some(_), Some(true)) => "store",
            _ => "jwt",
        }
    }

    /// 登录成功后登记（纯 JWT 模式返回 `false`）。
    pub fn register(&self, token: &str, uid: i64, pwd_tag: &str, client: &str) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        if !store.available() {
            return false;
        }
        let now = crate::now_ts();
        let abs = if self.policy.max_secs > 0 {
            now + self.policy.max_secs
        } else {
            0
        };
        let idle = if self.policy.idle_secs > 0 {
            self.policy.idle_secs
        } else {
            0
        };
        let exp = if idle > 0 { now + idle } else { abs };
        let ver = self.ver(store, &self.user_ver_key(uid));
        let cver = self.ver(store, &self.client_ver_key(uid, client));
        let value = format!(
            r#"{{"uid":{uid},"pwd":"{}","client":"{}","ver":{ver},"cver":{cver},"iat":{now},"abs":{abs},"exp":{exp}}}"#,
            escape(pwd_tag),
            escape(client)
        );
        let ttl = if idle > 0 { idle } else { abs };
        let ok = store.set(&self.key(token), &value, ttl);
        // 在线会话索引（失败不影响登录）
        if ok {
            store.sadd(&self.index_key(uid), &self.key(token), ttl);
        }
        ok
    }

    /// 校验登记状态（**不验 JWT 本身**，JWT 由调用方按各自 claim 口径验）。
    pub fn check(&self, token: &str) -> SessionState {
        let Some(store) = &self.store else {
            return SessionState::Untracked;
        };
        if !store.available() {
            return SessionState::Untracked;
        }
        let key = self.key(token);
        let Some(text) = store.get(&key) else {
            // 存储可用却没有记录：已登出 / 已过期 / 被清 → 视为无效（“可撤销”的来源）
            return SessionState::Invalid;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            return SessionState::Invalid;
        };
        let now = crate::now_ts();
        let exp = value.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
        let abs = value.get("abs").and_then(|v| v.as_i64()).unwrap_or(0);
        if (exp > 0 && exp <= now) || (abs > 0 && abs <= now) {
            let _ = store.del(&key);
            return SessionState::Invalid;
        }
        let uid = value.get("uid").and_then(|v| v.as_i64()).unwrap_or(0);
        let client = value
            .get("client")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let pwd_tag = value
            .get("pwd")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // 两级版本校验：全局（所有端）与按端，任一被踢即失效
        if uid > 0 {
            let ver = value.get("ver").and_then(|v| v.as_i64()).unwrap_or(0);
            if ver != self.ver(store, &self.user_ver_key(uid)) {
                let _ = store.del(&key);
                return SessionState::Invalid;
            }
            let cver = value.get("cver").and_then(|v| v.as_i64()).unwrap_or(0);
            if cver != self.ver(store, &self.client_ver_key(uid, &client)) {
                let _ = store.del(&key);
                return SessionState::Invalid;
            }
        }

        // 滑动续期：剩余不足一半才重写，且不越过绝对上限
        if self.policy.idle_secs > 0 && exp - now < self.policy.idle_secs / 2 {
            let mut next = now + self.policy.idle_secs;
            if abs > 0 && next > abs {
                next = abs;
            }
            let renewed = format!(
                r#"{{"uid":{uid},"pwd":"{}","client":"{}","ver":{},"cver":{},"iat":{},"abs":{abs},"exp":{next}}}"#,
                escape(&pwd_tag),
                escape(&client),
                value.get("ver").and_then(|v| v.as_i64()).unwrap_or(0),
                value.get("cver").and_then(|v| v.as_i64()).unwrap_or(0),
                value.get("iat").and_then(|v| v.as_i64()).unwrap_or(now),
            );
            let ttl = (next - now).max(1);
            let _ = store.set(&key, &renewed, ttl);
            let _ = store.sadd(&self.index_key(uid), &key, ttl);
        }
        SessionState::Active { pwd_tag, client }
    }

    /// 撤销（登出）：删记录并顺手从在线索引摘掉；纯 JWT 模式返回 `false`。
    pub fn revoke(&self, token: &str) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        if !store.available() {
            return false;
        }
        let key = self.key(token);
        if let Some(uid) = self.token_uid(&key, store) {
            store.srem(&self.index_key(uid), &key);
        }
        store.del(&key)
    }

    /// 从记录里取 uid（登出时清理索引用）。
    fn token_uid(&self, key: &str, store: &Arc<dyn SessionStore>) -> Option<i64> {
        let text = store.get(key)?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        v.get("uid").and_then(|x| x.as_i64()).filter(|n| *n > 0)
    }

    /// **踢掉某用户的全部令牌**（所有端）：全局版本 +1。
    pub fn revoke_user(&self, uid: i64) -> bool {
        self.bump(&self.user_ver_key(uid), uid)
    }

    /// **只踢某一端**（如只要手机端下线）：该端版本 +1，其它端不受影响。
    pub fn revoke_client(&self, uid: i64, client: &str) -> bool {
        let client = client.trim();
        if client.is_empty() {
            return false;
        }
        self.bump(&self.client_ver_key(uid, client), uid)
    }

    /// 版本 +1（内部）。
    fn bump(&self, key: &str, uid: i64) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        if !store.available() || uid <= 0 {
            return false;
        }
        let next = self.ver(store, key) + 1;
        store.set(key, &next.to_string(), self.ver_ttl())
    }

    /// 某用户的在线会话（后台展示；存储不支持集合时返回空）。
    pub fn sessions(&self, uid: i64) -> Vec<SessionInfo> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        if !store.available() || uid <= 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for key in store.smembers(&self.index_key(uid)) {
            let Some(text) = store.get(&key) else {
                // 记录已过期：顺手从索引摘掉
                store.srem(&self.index_key(uid), &key);
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                store.srem(&self.index_key(uid), &key);
                continue;
            };
            out.push(SessionInfo {
                client: v
                    .get("client")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                iat: v.get("iat").and_then(|x| x.as_i64()).unwrap_or(0),
                exp: v.get("exp").and_then(|x| x.as_i64()).unwrap_or(0),
            });
        }
        out.sort_by(|a, b| b.iat.cmp(&a.iat));
        out
    }
}

/// JSON 字符串转义（只需要处理 `\` 与 `"`；口令指纹/客户端标识都是 ASCII）。
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    /// 测试用内存存储（含集合）。
    struct MemStore {
        map: Mutex<HashMap<String, String>>,
        sets: Mutex<HashMap<String, HashSet<String>>>,
        up: bool,
    }

    impl MemStore {
        fn new(up: bool) -> Self {
            Self {
                map: Mutex::new(HashMap::new()),
                sets: Mutex::new(HashMap::new()),
                up,
            }
        }
    }

    impl SessionStore for MemStore {
        fn available(&self) -> bool {
            self.up
        }
        fn get(&self, key: &str) -> Option<String> {
            self.map.lock().ok()?.get(key).cloned()
        }
        fn set(&self, key: &str, value: &str, _ttl: i64) -> bool {
            if let Ok(mut m) = self.map.lock() {
                m.insert(key.to_string(), value.to_string());
                true
            } else {
                false
            }
        }
        fn del(&self, key: &str) -> bool {
            self.map
                .lock()
                .map(|mut m| m.remove(key).is_some())
                .unwrap_or(false)
        }
        fn sadd(&self, key: &str, member: &str, _ttl: i64) -> bool {
            if let Ok(mut s) = self.sets.lock() {
                s.entry(key.to_string()).or_default().insert(member.to_string());
                true
            } else {
                false
            }
        }
        fn srem(&self, key: &str, member: &str) -> bool {
            self.sets
                .lock()
                .map(|mut s| s.get_mut(key).map(|x| x.remove(member)).unwrap_or(false))
                .unwrap_or(false)
        }
        fn smembers(&self, key: &str) -> Vec<String> {
            self.sets
                .lock()
                .ok()
                .and_then(|s| s.get(key).cloned())
                .map(|x| x.into_iter().collect())
                .unwrap_or_default()
        }
    }

    fn keeper(up: bool) -> (SessionKeeper, Arc<MemStore>) {
        let store = Arc::new(MemStore::new(up));
        let k = SessionKeeper::new(
            Some(store.clone()),
            "t:",
            SessionPolicy {
                idle_secs: 3600,
                max_secs: 7200,
            },
        );
        (k, store)
    }

    #[test]
    fn register_then_check_is_active() {
        let (k, _s) = keeper(true);
        assert_eq!(k.store_kind(), "store");
        assert!(k.register("tok", 9, "abc123", "web"));
        assert_eq!(
            k.check("tok"),
            SessionState::Active {
                pwd_tag: "abc123".to_string(),
                client: "web".to_string(),
            }
        );
    }

    #[test]
    fn revoke_makes_it_invalid() {
        let (k, _s) = keeper(true);
        k.register("tok", 9, "abc123", "web");
        assert!(k.revoke("tok"));
        assert_eq!(k.check("tok"), SessionState::Invalid);
    }

    #[test]
    fn store_down_falls_back_to_jwt() {
        let (k, _s) = keeper(false);
        assert_eq!(k.store_kind(), "jwt");
        assert_eq!(k.check("anything"), SessionState::Untracked);
        assert!(!k.register("tok", 1, "x", "web"));
    }

    #[test]
    fn no_store_is_pure_jwt() {
        let k = SessionKeeper::new(None, "t:", SessionPolicy::default());
        assert_eq!(k.check("anything"), SessionState::Untracked);
        assert!(k.sessions(1).is_empty());
    }

    #[test]
    fn pwd_tag_is_carried_back() {
        let (k, _s) = keeper(true);
        k.register("tok", 3, "", "h5");
        assert_eq!(
            k.check("tok"),
            SessionState::Active {
                pwd_tag: String::new(),
                client: "h5".to_string(),
            }
        );
    }

    /// 多端登录：同一用户多个令牌，`revoke_user` 一次全部失效；之后重新登录仍可用。
    #[test]
    fn revoke_user_kills_all_devices() {
        let (k, _s) = keeper(true);
        k.register("pc", 42, "tag", "web");
        k.register("phone", 42, "tag", "app");
        k.register("other", 43, "tag", "web");
        assert!(k.revoke_user(42));
        assert_eq!(k.check("pc"), SessionState::Invalid);
        assert_eq!(k.check("phone"), SessionState::Invalid);
        // 别的用户不受影响
        assert!(matches!(k.check("other"), SessionState::Active { .. }));
        // 踢线后重新登录的新令牌版本已更新 → 正常可用
        k.register("pc2", 42, "tag", "web");
        assert!(matches!(k.check("pc2"), SessionState::Active { .. }));
    }

    /// 按端踢线：只踢 app，web 照常；全踢则两者都没。
    #[test]
    fn revoke_client_only_kills_that_client() {
        let (k, _s) = keeper(true);
        k.register("pc", 7, "tag", "web");
        k.register("phone", 7, "tag", "app");
        assert!(k.revoke_client(7, "app"));
        assert_eq!(k.check("phone"), SessionState::Invalid);
        assert!(matches!(k.check("pc"), SessionState::Active { .. }));
        // 重新登录 app 正常
        k.register("phone2", 7, "tag", "app");
        assert!(matches!(k.check("phone2"), SessionState::Active { .. }));
        // 全部踢
        assert!(k.revoke_user(7));
        assert_eq!(k.check("pc"), SessionState::Invalid);
        assert_eq!(k.check("phone2"), SessionState::Invalid);
    }

    /// 在线会话列表：能列出各端；登出后该端消失。
    #[test]
    fn sessions_lists_clients() {
        let (k, _s) = keeper(true);
        k.register("pc", 5, "tag", "web");
        k.register("phone", 5, "tag", "app");
        let mut clients: Vec<String> = k.sessions(5).into_iter().map(|s| s.client).collect();
        clients.sort();
        assert_eq!(clients, vec!["app".to_string(), "web".to_string()]);
        k.revoke("phone");
        let clients: Vec<String> = k.sessions(5).into_iter().map(|s| s.client).collect();
        assert_eq!(clients, vec!["web".to_string()]);
    }

    /// 存储不可用时 `revoke_user` 不报错（回退纯 JWT，由调用方提示）。
    #[test]
    fn revoke_user_without_store_is_noop() {
        let (k, _s) = keeper(false);
        assert!(!k.revoke_user(1));
        let k2 = SessionKeeper::new(None, "t:", SessionPolicy::default());
        assert!(!k2.revoke_user(1));
        assert!(!k2.revoke_client(1, "web"));
    }
}
