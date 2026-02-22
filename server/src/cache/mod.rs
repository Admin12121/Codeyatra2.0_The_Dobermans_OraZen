use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::{Serialize, de::DeserializeOwned};

pub struct CacheService {
    conn: ConnectionManager,
}

impl CacheService {
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    pub async fn get<T: DeserializeOwned>(&mut self, key: &str) -> Option<T> {
        let result: Option<String> = self.conn.get(key).await.ok()?;
        result.and_then(|s| serde_json::from_str(&s).ok())
    }

    pub async fn set<T: Serialize>(
        &mut self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), redis::RedisError> {
        let json = serde_json::to_string(value).unwrap();
        self.conn.set_ex(key, json, ttl_seconds).await
    }

    pub async fn delete(&mut self, key: &str) -> Result<(), redis::RedisError> {
        self.conn.del(key).await
    }

    pub async fn check_rate_limit(
        &mut self,
        key: &str,
        max_requests: u32,
        window_seconds: u64,
    ) -> Result<(bool, u32, u64), redis::RedisError> {
        let cache_key = format!("ratelimit:{}", key);
        let current: u32 = self.conn.get(&cache_key).await.unwrap_or(0);

        if current >= max_requests {
            let ttl: i64 = self.conn.ttl(&cache_key).await.unwrap_or(0);
            return Ok((false, 0, ttl.max(0) as u64));
        }

        let new_count: u32 = self.conn.incr(&cache_key, 1).await?;

        if new_count == 1 {
            let _: () = self.conn.expire(&cache_key, window_seconds as i64).await?;
        }

        let ttl: i64 = self
            .conn
            .ttl(&cache_key)
            .await
            .unwrap_or(window_seconds as i64);
        let remaining = max_requests.saturating_sub(new_count);

        Ok((true, remaining, ttl.max(0) as u64))
    }

    pub fn guard_cache_key(prompt_hash: &str) -> String {
        format!("guard:scan:{}", prompt_hash)
    }

    pub fn rate_limit_key(api_key_id: &str) -> String {
        format!("ratelimit:{}", api_key_id)
    }

    pub fn session_key(token: &str) -> String {
        format!("session:{}", token)
    }
}
