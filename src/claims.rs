//! 标准 claims（Pek 生态约定；与 C# DHDeploy 的 payload 字段同族）。
//!
//! 字段：`sub`（主体/用户标识）、`name`（显示名）、`from`（来源：`panel` 管理端 / `app` 用户端）、
//! `clientType`（客户端类型，对齐 Pek `clientType` 概念：`admin` / `app`）。

use serde_json::{Map, Value, json};

/// 标准 claims。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// 主体（用户标识；始终为字符串——与 C# 端 `sub` 形态一致）
    pub sub: String,
    /// 显示名（用户名）
    pub name: String,
    /// 来源（`panel` 管理端 / `app` 用户端）
    pub from: String,
    /// 客户端类型（`admin` / `app`）
    pub client_type: String,
}

impl Claims {
    /// 自定义构造。
    pub fn new(
        sub: impl Into<String>,
        name: impl Into<String>,
        from: impl Into<String>,
        client_type: impl Into<String>,
    ) -> Self {
        Self {
            sub: sub.into(),
            name: name.into(),
            from: from.into(),
            client_type: client_type.into(),
        }
    }

    /// 管理端 claims（`from=panel`、`clientType=admin`；sub/name 均为用户名）。
    pub fn admin(user: impl Into<String>) -> Self {
        let user = user.into();
        Self::new(user.clone(), user, "panel", "admin")
    }

    /// 用户端 claims（`from=app`、`clientType=app`）。
    pub fn app(user_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(user_id, name, "app", "app")
    }

    /// 转 JSON 负载（键序：sub/name/from/clientType）。
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("sub".to_string(), json!(self.sub));
        m.insert("name".to_string(), json!(self.name));
        m.insert("from".to_string(), json!(self.from));
        m.insert("clientType".to_string(), json!(self.client_type));
        m
    }

    /// 从负载解析（`sub` 必填；其余缺失时为空串——宽容解析，便于跨系统对接）。
    pub fn from_map(map: &Map<String, Value>) -> Result<Self, String> {
        let field = |k: &str| {
            map.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_default()
        };
        let sub = field("sub");
        if sub.is_empty() {
            return Err("claims 缺少 sub".to_string());
        }
        Ok(Self {
            sub,
            name: field("name"),
            from: field("from"),
            client_type: field("clientType"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_roundtrip_and_helpers() {
        let admin = Claims::admin("alice");
        assert_eq!(admin.from, "panel");
        assert_eq!(admin.client_type, "admin");
        let map = admin.to_map();
        assert_eq!(Claims::from_map(&map).unwrap(), admin);

        let app = Claims::app("42", "bob");
        assert_eq!(app.sub, "42");
        assert_eq!(Claims::from_map(&app.to_map()).unwrap(), app);

        // 宽容解析：仅 sub 必填
        let mut m = Map::new();
        m.insert("sub".to_string(), json!("7"));
        let c = Claims::from_map(&m).unwrap();
        assert_eq!(c.name, "");
        assert!(Claims::from_map(&Map::new()).is_err());
    }
}
