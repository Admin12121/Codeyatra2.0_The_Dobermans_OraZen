use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub ml_sidecar_url: String,
    pub jwt_secret: String,
    pub environment: Environment,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Staging,
    Production,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config = config::Config::builder()
            .add_source(config::Environment::default())
            .build()?;

        config.try_deserialize()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url:
                "postgresql://orafinite_user:orafinite_dev_password@localhost:5432/orazen"
                    .to_string(),
            redis_url: "redis://127.0.0.1:6379".to_string(),
            server_host: "0.0.0.0".to_string(),
            server_port: 8080,
            ml_sidecar_url: "http://127.0.0.1:50051".to_string(),
            jwt_secret: "dev-secret-change-in-production".to_string(),
            environment: Environment::Development,
        }
    }
}
