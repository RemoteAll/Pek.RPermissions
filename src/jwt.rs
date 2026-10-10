//! NewLife `JwtBuilder` 兼容 JWT（HS256）——**与 C# 端（DHDeploy / Pek 平台）字节级互通**。
//!
//! 字节级约定（2026-10-10 对照 C# 端实测样本逐项确认；黄金样本见测试）：
//! - Header：`{"alg":"HS256"}`（紧凑 JSON、无 `typ`）；
//! - Payload：紧凑 JSON；`exp` / `iat` 为 **Unix 秒**；键序不限（验证按令牌原文验签）；
//! - 签名：`HMAC-SHA256(key = secret 的 UTF-8 字节, data = "header.payload")` → **base64url 无填充**；
//! - Secret 配置格式 `算法:密钥`（按 `:` 分隔取第二段——与 C# `Split(':')[1]` 严格一致；**密钥不要包含冒号**）；
//! - 时间检查与 C# `JwtBuilder.TryDecode` 一致：`now > exp` → 过期；`now < nbf` → 未生效（仅当声明存在）。
//!
//! 安全说明：只按固定 HMAC-SHA256 验签、不读取 header 中的算法（天然规避 `alg=none` 类攻击）。

use serde_json::{Map, Value, json};

/// JWT 选项（对齐 C# `Pek.Security.JwtOptions` 的常用字段）。
#[derive(Clone, Debug)]
pub struct JwtOptions {
    /// 密钥（格式「算法:密钥」，如 `HS256:xxxx`；密钥不要包含冒号）
    pub secret: String,
    /// 发行方（`iss`；`None` = 不注入）
    pub issuer: Option<String>,
    /// 受众（`aud`；`None` = 不注入）
    pub audience: Option<String>,
    /// 访问令牌有效期（分钟；默认 120——对齐 NewLife `JwtBuilder` 默认 2 小时）
    pub access_expire_minutes: i64,
    /// 刷新令牌有效期（分钟；**预留**——当前版本不生成刷新令牌）
    pub refresh_expire_minutes: i64,
}

impl Default for JwtOptions {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: None,
            audience: None,
            access_expire_minutes: 120,
            refresh_expire_minutes: 120,
        }
    }
}

impl JwtOptions {
    /// 仅密钥（其余取默认值）。
    pub fn from_secret(secret: &str) -> Self {
        Self {
            secret: secret.to_string(),
            ..Default::default()
        }
    }
}

/// JWT 编解码器（HS256）。
#[derive(Clone)]
pub struct Jwt {
    /// 选项（`issuer`/`audience` 在 `encode*` 时注入；`encode` 用 `access_expire_minutes`）
    options: JwtOptions,
    /// HMAC 密钥（secret 原文的 UTF-8 字节）
    key: Vec<u8>,
}

impl Jwt {
    /// 按选项构建（仅支持 HS256；密钥不要包含冒号）。
    pub fn new(options: JwtOptions) -> Result<Self, String> {
        let parts: Vec<&str> = options.secret.split(':').collect();
        if parts.len() < 2 {
            return Err("Jwt 密钥格式需为「算法:密钥」（如 HS256:xxxx）".to_string());
        }
        if !parts[0].eq_ignore_ascii_case("HS256") {
            return Err(format!("暂不支持的 JWT 算法：{}（当前仅 HS256）", parts[0]));
        }
        Ok(Self {
            key: parts[1].as_bytes().to_vec(),
            options,
        })
    }

    /// 便捷构建（仅密钥）。
    pub fn from_secret(secret: &str) -> Result<Self, String> {
        Self::new(JwtOptions::from_secret(secret))
    }

    /// 选项快照。
    pub fn options(&self) -> &JwtOptions {
        &self.options
    }

    /// 签发令牌（有效期 = `options.access_expire_minutes`）。
    pub fn encode(&self, claims: &Map<String, Value>) -> String {
        self.encode_with(claims, self.options.access_expire_minutes)
    }

    /// 以指定有效期（分钟）签发令牌。
    pub fn encode_with(&self, claims: &Map<String, Value>, expire_minutes: i64) -> String {
        self.encode_at(claims, expire_minutes, crate::now_ts())
    }

    /// 以指定时间签发令牌（测试/调试用）。
    ///
    /// `claims` 中缺失时自动注入：`iss`（选项 issuer）、`aud`（选项 audience）、
    /// `exp = now + expire_minutes * 60`、`iat = now`。
    pub fn encode_at(&self, claims: &Map<String, Value>, expire_minutes: i64, now: i64) -> String {
        let mut map = claims.clone();
        if let Some(iss) = &self.options.issuer {
            map.entry("iss").or_insert(json!(iss));
        }
        if let Some(aud) = &self.options.audience {
            map.entry("aud").or_insert(json!(aud));
        }
        map.entry("exp").or_insert(json!(now + expire_minutes * 60));
        map.entry("iat").or_insert(json!(now));
        let header = r#"{"alg":"HS256"}"#;
        let payload =
            serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| "{}".to_string());
        let h = dhrust::sign::base64_url_no_pad(header.as_bytes());
        let p = dhrust::sign::base64_url_no_pad(payload.as_bytes());
        let data = format!("{h}.{p}");
        let sig = dhrust::sign::hmac_sha256(&self.key, data.as_bytes());
        format!("{data}.{}", dhrust::sign::base64_url_no_pad(&sig))
    }

    /// 校验令牌（验签 + 过期/未生效检查），返回负载。
    pub fn validate(&self, token: &str) -> Result<Map<String, Value>, String> {
        self.validate_at(token, crate::now_ts())
    }

    /// 以指定时间校验令牌（测试/调试用）。
    ///
    /// 返回负载（claims）；失败返回中文原因（与 C# 消息口径一致）。
    pub fn validate_at(&self, token: &str, now: i64) -> Result<Map<String, Value>, String> {
        let segs: Vec<&str> = token.split('.').collect();
        if segs.len() != 3 {
            return Err("JWT 格式不正确".to_string());
        }

        // 验签（常量时间比较；只认 HS256 原文，不读 header 算法）
        let data = format!("{}.{}", segs[0], segs[1]);
        let expect = dhrust::sign::hmac_sha256(&self.key, data.as_bytes());
        let Some(given) = dhrust::sign::base64_decode(segs[2]) else {
            return Err("签名解码失败".to_string());
        };
        if !dhrust::sign::fixed_time_eq(&expect, &given) {
            return Err("签名验证失败".to_string());
        }

        // 解析负载
        let Some(bytes) = dhrust::sign::base64_decode(segs[1]) else {
            return Err("负载解码失败".to_string());
        };
        let payload: Map<String, Value> =
            serde_json::from_slice(&bytes).map_err(|e| format!("负载解析失败：{e}"))?;

        // 时间检查（对齐 C#：仅当声明存在）
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64())
            && now > exp
        {
            return Err("令牌已过期".to_string());
        }
        if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64())
            && now < nbf
        {
            return Err("令牌未生效".to_string());
        }

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTEROP_SECRET: &str = "HS256:rcard-interop-key-2026";

    /// C#（`NewLife.Web.JwtBuilder`）实测生成的黄金样本（2026-10-10 `Pek.RCard/tools/csharp/JwtInterop`）：
    /// payload = {"sub":"42","name":"alice","from":"rcard","clientType":"app","iss":"Pek.RCard","exp":1791600338,"iat":1791593138,"jti":"42"}
    const CSHARP_GOLDEN_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsIm5hbWUiOiJhbGljZSIsImZyb20iOiJyY2FyZCIsImNsaWVudFR5cGUiOiJhcHAiLCJpc3MiOiJQZWsuUkNhcmQiLCJleHAiOjE3OTE2MDAzMzgsImlhdCI6MTc5MTU5MzEzOCwianRpIjoiNDIifQ.4fiepkRzWbMCix2zjk3TxRnvQfvwO0hzIGzPCSyxv6M";
    const GOLDEN_IAT: i64 = 1791593138;
    const GOLDEN_EXP: i64 = 1791600338;

    #[test]
    fn csharp_golden_token_validates() {
        let jwt = Jwt::from_secret(INTEROP_SECRET).unwrap();
        // 以签发后 60 秒的时点校验 → 通过（与 C# 端互验的核心证据）
        let claims = jwt.validate_at(CSHARP_GOLDEN_TOKEN, GOLDEN_IAT + 60).unwrap();
        assert_eq!(claims.get("sub").and_then(|v| v.as_str()), Some("42"));
        assert_eq!(claims.get("name").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(claims.get("from").and_then(|v| v.as_str()), Some("rcard"));
        assert_eq!(claims.get("iss").and_then(|v| v.as_str()), Some("Pek.RCard"));
        assert_eq!(claims.get("exp").and_then(|v| v.as_i64()), Some(GOLDEN_EXP));

        // 过期判断（exp 之后 1 秒 → 过期；对齐 C# `Expire < now`）
        assert_eq!(
            jwt.validate_at(CSHARP_GOLDEN_TOKEN, GOLDEN_EXP + 1).unwrap_err(),
            "令牌已过期"
        );
        // 篡改负载 → 签名验证失败
        let tampered = CSHARP_GOLDEN_TOKEN.replacen("eyJzdWIiOiI0MiI", "eyJzdWIiOiI0MyI", 1);
        assert_eq!(
            jwt.validate_at(&tampered, GOLDEN_IAT + 60).unwrap_err(),
            "签名验证失败"
        );
        // 换密钥 → 签名验证失败
        let other = Jwt::from_secret("HS256:another-key").unwrap();
        assert_eq!(
            other.validate_at(CSHARP_GOLDEN_TOKEN, GOLDEN_IAT + 60).unwrap_err(),
            "签名验证失败"
        );
    }

    #[test]
    fn encode_and_validate_roundtrip() {
        let jwt = Jwt::from_secret(INTEROP_SECRET).unwrap();
        let mut claims = Map::new();
        claims.insert("sub".to_string(), json!("42"));
        claims.insert("name".to_string(), json!("alice"));
        claims.insert("from".to_string(), json!("rcard"));

        let token = jwt.encode_at(&claims, 120, GOLDEN_IAT);
        // 生成格式固定：三段；header 恰为 C# 同款
        let segs: Vec<&str> = token.split('.').collect();
        assert_eq!(segs.len(), 3);
        assert_eq!(
            dhrust::sign::base64_decode(segs[0]).unwrap(),
            br#"{"alg":"HS256"}"#
        );
        // 自验通过（同一时间基准）
        let back = jwt.validate_at(&token, GOLDEN_IAT + 60).unwrap();
        assert_eq!(back.get("sub").and_then(|v| v.as_str()), Some("42"));
        assert_eq!(back.get("exp").and_then(|v| v.as_i64()), Some(GOLDEN_IAT + 7200));
        assert_eq!(back.get("iat").and_then(|v| v.as_i64()), Some(GOLDEN_IAT));
        // 过期
        assert!(jwt.validate_at(&token, GOLDEN_IAT + 7200 + 1).is_err());
        // 已显式提供的 exp/iat 不被覆盖
        let mut fixed = Map::new();
        fixed.insert("exp".to_string(), json!(GOLDEN_EXP));
        fixed.insert("iat".to_string(), json!(GOLDEN_IAT));
        let token2 = jwt.encode_at(&fixed, 1, 1);
        let back2 = jwt.validate_at(&token2, GOLDEN_IAT + 60).unwrap();
        assert_eq!(back2.get("exp").and_then(|v| v.as_i64()), Some(GOLDEN_EXP));
    }

    #[test]
    fn options_inject_issuer_and_audience() {
        let mut options = JwtOptions::from_secret("HS256:opt-key");
        options.issuer = Some("Pek.RCard".to_string());
        options.audience = Some("rcard-clients".to_string());
        options.access_expire_minutes = 60;
        let jwt = Jwt::new(options).unwrap();
        let token = jwt.encode_at(&Map::new(), 60, GOLDEN_IAT);
        let claims = jwt.validate_at(&token, GOLDEN_IAT + 1).unwrap();
        assert_eq!(claims.get("iss").and_then(|v| v.as_str()), Some("Pek.RCard"));
        assert_eq!(claims.get("aud").and_then(|v| v.as_str()), Some("rcard-clients"));
        assert_eq!(claims.get("exp").and_then(|v| v.as_i64()), Some(GOLDEN_IAT + 3600));
    }

    #[test]
    fn secret_parsing_rules() {
        assert!(Jwt::from_secret("HS256:key123").is_ok());
        assert!(Jwt::from_secret("hs256:key123").is_ok(), "算法大小写不敏感（对齐 C#）");
        assert!(Jwt::from_secret("no-colon").is_err());
        assert!(Jwt::from_secret("RS256:key123").is_err(), "暂不支持非 HS256");
        // 与 C# Split(':')[1] 一致：密钥取第一个冒号后的第二段（故密钥不应含冒号）
        let jwt = Jwt::from_secret("HS256:part1:part2").unwrap();
        let mut claims = Map::new();
        claims.insert("x".to_string(), json!(1));
        let token = jwt.encode_at(&claims, 1, GOLDEN_IAT);
        // 用 "part1" 才能验通（对齐 C# 行为）
        let ok = Jwt::from_secret("HS256:part1").unwrap();
        assert!(ok.validate_at(&token, GOLDEN_IAT).is_ok());
        let wrong = Jwt::from_secret("HS256:part2").unwrap();
        assert!(wrong.validate_at(&token, GOLDEN_IAT).is_err());
    }

    #[test]
    fn nbf_checked_like_csharp() {
        let jwt = Jwt::from_secret(INTEROP_SECRET).unwrap();
        let mut claims = Map::new();
        claims.insert("nbf".to_string(), json!(GOLDEN_IAT + 3600));
        let token = jwt.encode_at(&claims, 120, GOLDEN_IAT);
        assert_eq!(
            jwt.validate_at(&token, GOLDEN_IAT + 60).unwrap_err(),
            "令牌未生效"
        );
        assert!(jwt.validate_at(&token, GOLDEN_IAT + 3600).is_ok());
    }
}
