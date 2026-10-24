//! 会话登记与吊销（**JWT 始终有效；外部存储只做「登记 / 吊销 / 共享」**）。
//!
//! # 口径（2026-10-24 定稿，用户确认）
//! 1. 令牌**永远是 JWT**（与 C# `Pek.Permissions` / DHDeploy 互认；进程重启、换机器都不掉线）；
//! 2. 外部存储（Redis / 数据库 / 内存）**不保存令牌本体**，只保存「这个令牌还在不在 / 什么时候到期 / 口令指纹」；
//! 3. 存储不可用 → 自动回到「纯 JWT」模式（验签+过期即放行），**绝不因为缓存挂了把所有人挡在外面**；
//! 4. 存储可用时：登出即删记录 → 令牌即刻失效（JWT 本身没法撤销，靠这条记录实现）。
//!
//! 为什么不在本库直接依赖 Redis：Pek.RPermissions 是**权限组装件**，不应绑死某个缓存产品；
//! 这里只定义 [`SessionStore`] 抽象，消费方用自己的 Redis 客户端实现（见 HLZX.EIP `admin::session`，
//! 基于 Pek.RRedis）。
//!
//! # 存储里到底存什么
//! 存的是「令牌的登记记录」，**不是令牌本体**；键名用**令牌的 SHA-256**（不存原文），
//! 即使 Redis 被读走也拿不到可直接使用的令牌。令牌本体永远是 JWT（自包含）。
//!
//! # 滑动续期与安全边界
//! - 空闲（`idle_secs`）不动才失效，活跃时按「剩余不足一半」才刷新一次，**不是每请求都写**；
//! - **绝对上限**（`max_secs`）：无论多活跃，登记满上限后必须重新登录（防无限续期）；
//! - **口令指纹**（`pwd_tag`）：改密后旧记录对不上 → 旧会话全部失效，无需遍历删令牌。

use std::sync::Arc;

/// 外部存储抽象（Redis / 数据库 / 内存均可实现）。
///
/// 约定：所有方法失败时返回 `None` / `false`，**不要 panic**（缓存故障不能影响业务）。
pub trait SessionStore: Send + Sync {
    /// 存储是否可用（不可用时按「纯 JWT」放行，不能当作「已吊销」）。
    fn available(&self) -> bool;
    /// 读取记录（JSON 文本）。
    fn get(&self, key: &str) -> Option<String>;
    /// 写入记录并设置过期（秒）。
    fn set(&self, key: &str, value: &str, ttl_secs: i64) -> bool;
    /// 删除记录（登出）。
    fn del(&self, key: &str) -> bool;
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
    /// 存储可用且记录有效（附口令指纹）
    Active { pwd_tag: String },
    /// 存储可用但记录不存在 / 已过期 / 已达绝对上限 → **拒绝**
    Invalid,
    /// 存储不可用 → 调用方按「纯 JWT」处理（验签 + 过期）
    Untracked,
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

    /// 键名：**存令牌的 SHA-256**（不存原文）——即使 Redis 被读，也拿不到可直接使用的令牌。
    fn key(&self, token: &str) -> String {
        format!(
            "{}session:{}",
            self.key_prefix,
            dhrust::sign::sha256_hex(token.as_bytes())
        )
    }

    /// 用户级令牌版本键（多端登录时用来「一次踢掉全部令牌」）。
    fn user_ver_key(&self, uid: i64) -> String {
        format!("{}userver:{uid}", self.key_prefix)
    }

    /// 读当前用户令牌版本（无记录 = 0）。
    fn user_ver(&self, store: &Arc<dyn SessionStore>, uid: i64) -> i64 {
        store
            .get(&self.user_ver_key(uid))
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0)
    }

    /// 存储方式（`redis`-类的展示口径）。
    pub fn store_kind(&self) -> &'static str {
        match (&self.store, self.store.as_ref().map(|s| s.available())) {
            (Some(_), Some(true)) => "store",
            _ => "jwt",
        }
    }

    /// 登录成功后登记（纯 JWT 模式返回 `false`）。
    pub fn register(&self, token: &str, uid: i64, pwd_tag: &str) -> bool {
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
        // 当前用户令牌版本：多端登录各自登记同一个版本；「踢线」= 版本 +1
        let ver = self.user_ver(store, uid);
        let value = format!(
            r#"{{"uid":{uid},"pwd":"{}","ver":{ver},"iat":{now},"abs":{abs},"exp":{exp}}}"#,
            escape(pwd_tag)
        );
        store.set(&self.key(token), &value, if idle > 0 { idle } else { abs })
    }

    /// 校验登记状态（**不验 JWT 本身**，JWT 由调用方按各自 claim 口径验）。
    pub fn check(&self, token: &str) -> SessionState {
        let Some(store) = &self.store else {
            return SessionState::Untracked;
        };
        if !store.available() {
            return SessionState::Untracked;
        }
        let Some(text) = store.get(&self.key(token)) else {
            // 存储可用却没有记录：已登出 / 已过期 / 被清 → 视为无效（这正是“可撤销”的来源）
            return SessionState::Invalid;
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return SessionState::Invalid,
        };
        let now = crate::now_ts();
        let exp = value.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
        let abs = value.get("abs").and_then(|v| v.as_i64()).unwrap_or(0);
        if (exp > 0 && exp <= now) || (abs > 0 && abs <= now) {
            let _ = store.del(&self.key(token));
            return SessionState::Invalid;
        }
        let pwd_tag = value
            .get("pwd")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        // 用户级版本校验：踢线后（版本 +1）旧令牌全部失效——多端登录一次清掉
        let uid = value.get("uid").and_then(|v| v.as_i64()).unwrap_or(0);
        let ver = value.get("ver").and_then(|v| v.as_i64()).unwrap_or(0);
        if uid > 0 && ver != self.user_ver(store, uid) {
            let _ = store.del(&self.key(token));
            return SessionState::Invalid;
        }

        // 滑动续期：剩余不足一半才重写，且不越过绝对上限
        if self.policy.idle_secs > 0 && exp - now < self.policy.idle_secs / 2 {
            let mut next = now + self.policy.idle_secs;
            if abs > 0 && next > abs {
                next = abs;
            }
            let renewed = format!(
                r#"{{"uid":{},"pwd":"{}","iat":{},"abs":{abs},"exp":{next}}}"#,
                value.get("uid").and_then(|v| v.as_i64()).unwrap_or(0),
                escape(&pwd_tag),
                value.get("iat").and_then(|v| v.as_i64()).unwrap_or(now),
            );
            let ttl = (next - now).max(1);
            let _ = store.set(&self.key(token), &renewed, ttl);
        }
        SessionState::Active { pwd_tag }
    }

    /// 撤销（登出）：存储可用时删记录；纯 JWT 模式返回 `false`。
    pub fn revoke(&self, token: &str) -> bool {
        match &self.store {
            Some(store) if store.available() => store.del(&self.key(token)),
            _ => false,
        }
    }

    /// **踢掉某用户的全部令牌**（多端登录一次性下线）：版本 +1，不需遍历令牌。
    ///
    /// 版本键的 TTL 取绝对上限（≥ 会话寿命），避免版本键先过期后旧令牌“复活”。
    /// 纯 JWT 模式返回 `false`（无共享存储，无法撤销——只能等过期或用改密/停用）。
    pub fn revoke_user(&self, uid: i64) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        if !store.available() || uid <= 0 {
            return false;
        }
        let next = self.user_ver(store, uid) + 1;
        let ttl = if self.policy.max_secs > 0 {
            self.policy.max_secs
        } else {
            self.policy.idle_secs.max(3600)
        };
        store.set(&self.user_ver_key(uid), &next.to_string(), ttl)
    }
}

/// JSON 字符串转义（只需要处理 `\` 与 `"`，口令指纹是 hex/ASCII）。
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// 测试用内存存储。
    struct MemStore {
        map: Mutex<HashMap<String, String>>,
        up: bool,
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
            self.map.lock().map(|mut m| m.remove(key).is_some()).unwrap_or(false)
        }
    }

    fn keeper(up: bool) -> (SessionKeeper, Arc<MemStore>) {
        let store = Arc::new(MemStore {
            map: Mutex::new(HashMap::new()),
            up,
        });
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
        assert!(k.register("tok", 9, "abc123"));
        assert_eq!(
            k.check("tok"),
            SessionState::Active {
                pwd_tag: "abc123".to_string()
            }
        );
    }

    #[test]
    fn revoke_makes_it_invalid() {
        let (k, _s) = keeper(true);
        k.register("tok", 9, "abc123");
        assert!(k.revoke("tok"));
        assert_eq!(k.check("tok"), SessionState::Invalid);
    }

    #[test]
    fn store_down_falls_back_to_jwt() {
        let (k, _s) = keeper(false);
        assert_eq!(k.store_kind(), "jwt");
        assert_eq!(k.check("anything"), SessionState::Untracked);
        assert!(!k.register("tok", 1, "x"));
    }

    #[test]
    fn no_store_is_pure_jwt() {
        let k = SessionKeeper::new(None, "t:", SessionPolicy::default());
        assert_eq!(k.check("anything"), SessionState::Untracked);
    }

    #[test]
    fn pwd_tag_is_carried_back() {
        let (k, _s) = keeper(true);
        k.register("tok", 3, "");
        // 空口令指纹也要能读回（表示“无从校验”，由调用方决定）
        assert_eq!(
            k.check("tok"),
            SessionState::Active {
                pwd_tag: String::new()
            }
        );
    }

    /// 多端登录：同一用户多个令牌，`revoke_user` 一次全部失效；之后重新登录仍可用。
    #[test]
    fn revoke_user_kills_all_devices() {
        let (k, _s) = keeper(true);
        k.register("pc", 42, "tag");
        k.register("phone", 42, "tag");
        k.register("other", 43, "tag");
        assert_eq!(
            k.check("pc"),
            SessionState::Active {
                pwd_tag: "tag".to_string()
            }
        );
        assert!(k.revoke_user(42));
        assert_eq!(k.check("pc"), SessionState::Invalid);
        assert_eq!(k.check("phone"), SessionState::Invalid);
        // 别的用户不受影响
        assert_eq!(
            k.check("other"),
            SessionState::Active {
                pwd_tag: "tag".to_string()
            }
        );
        // 踢线后重新登录的新令牌版本已更新 → 正常可用
        k.register("pc2", 42, "tag");
        assert_eq!(
            k.check("pc2"),
            SessionState::Active {
                pwd_tag: "tag".to_string()
            }
        );
    }

    /// 存储不可用时 `revoke_user` 不报错（回退纯 JWT，由调用方提示）。
    #[test]
    fn revoke_user_without_store_is_noop() {
        let (k, _s) = keeper(false);
        assert!(!k.revoke_user(1));
        let k2 = SessionKeeper::new(None, "t:", SessionPolicy::default());
        assert!(!k2.revoke_user(1));
    }
}
