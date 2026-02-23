mod api;
mod cache;
mod config;
mod db;
mod grpc;
mod middleware;
mod models;
mod utils;

use std::{env, net::SocketAddr};

use api::{health, routes};
use axum::{
    Router,
    http::{HeaderValue, Method},
    routing::get,
};
use db::write_buffer::WriteBuffer;
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

fn parse_allowed_origins(raw: &str) -> Vec<HeaderValue> {
    raw.split(',')
        .filter_map(|origin| {
            let trimmed = origin.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed.parse::<HeaderValue>().ok()
        })
        .collect()
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "server=info,tower_http=info".into()),
        )
        .init();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://orafinite_user:orafinite_dev_password@localhost:5432/orazen".to_string()
    });
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let ml_sidecar_url =
        env::var("ML_SIDECAR_URL").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("SERVER_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(8080);

    let db = match PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => {
            eprintln!("failed to connect to postgres: {err}");
            std::process::exit(1);
        }
    };

    let redis_client = match redis::Client::open(redis_url.clone()) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("failed to create redis client for {redis_url}: {err}");
            std::process::exit(1);
        }
    };

    let redis = match ConnectionManager::new(redis_client).await {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("failed to connect to redis: {err}");
            std::process::exit(1);
        }
    };

    let write_buffer = WriteBuffer::spawn(db.clone());
    let state = api::AppState::new(db, redis, ml_sidecar_url, write_buffer);

    let allowed_origins_raw = env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost,http://frontend:3000,http://nginx".to_string());
    let allowed_origins = parse_allowed_origins(&allowed_origins_raw);

    let cors = {
        let base = CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers(Any);

        if allowed_origins.is_empty() {
            base.allow_origin(Any)
        } else {
            base.allow_origin(allowed_origins)
        }
    };

    let app = Router::new()
        .route("/ping", get(health::ping))
        .route("/health", get(health::health_check))
        .nest("/v1", routes::v1_routes())
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let addr = format!("{host}:{port}")
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)));

    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to bind {addr}: {err}");
            std::process::exit(1);
        }
    };

    println!("server listening on http://{addr}");

    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}
