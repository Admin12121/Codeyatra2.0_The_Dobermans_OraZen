// Server-Sent Events (SSE) for Real-Time Guard Log Streaming

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures::stream::Stream;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::AppState;
use crate::db::write_buffer::GuardLogEvent;
use crate::middleware::{ErrorResponse, require_session_from_headers};


const SSE_TICKET_TTL_SECS: u64 = 30;
const SSE_TICKET_PREFIX: &str = "sse_ticket:";

struct GuardEventStream {
    rx: mpsc::Receiver<Event>,
}

impl Stream for GuardEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(Some(Ok(event))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}


#[derive(Debug, Deserialize, Default)]
pub struct SseQueryParams {
    pub ticket: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SseTicketPayload {
    user_id: String,
    email: String,
    name: Option<String>,
    session_id: String,
}


#[derive(Debug, Serialize)]
pub struct SseTicketResponse {
    pub ticket: String,
    pub expires_in: u64,
}

fn extract_session_token_from_headers<'a>(headers: &'a HeaderMap) -> Option<&'a str> {
    if let Some(auth) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        if !auth.is_empty() {
            return Some(auth);
        }
    }

    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookie_header.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("better-auth.session_token=") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }

    None
}

async fn redeem_sse_ticket(
    redis: &mut redis::aio::ConnectionManager,
    ticket: &str,
) -> Option<crate::middleware::auth::AuthenticatedUser> {
    let key = format!("{}{}", SSE_TICKET_PREFIX, ticket);

    let payload: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(redis)
        .await
        .ok()?;

    let payload = payload?;

    let ticket_data: SseTicketPayload = serde_json::from_str(&payload).ok()?;

    Some(crate::middleware::auth::AuthenticatedUser {
        user_id: ticket_data.user_id,
        email: ticket_data.email,
        name: ticket_data.name,
        session_id: ticket_data.session_id,
    })
}

async fn validate_session_token(
    db: &sqlx::PgPool,
    token: &str,
) -> Result<crate::middleware::auth::AuthenticatedUser, (StatusCode, Json<ErrorResponse>)> {
    use sqlx::Row;

    let result = sqlx::query(
        r#"
        SELECT
            s.id as session_id,
            s.user_id,
            u.email,
            u.name
        FROM session s
        JOIN "user" u ON s.user_id = u.id
        WHERE s.token = $1
          AND s.expires_at > NOW()
        "#,
    )
    .bind(token)
    .fetch_optional(db)
    .await;

    match result {
        Ok(Some(row)) => Ok(crate::middleware::auth::AuthenticatedUser {
            session_id: row.get("session_id"),
            user_id: row.get("user_id"),
            email: row.get("email"),
            name: row.get("name"),
        }),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Invalid or expired session token",
                "SESSION_INVALID",
            )),
        )),
        Err(_e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Authentication service unavailable",
                "AUTH_ERROR",
            )),
        )),
    }
}

async fn get_user_org_id(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let row = sqlx::query_scalar::<_, Uuid>(
        "SELECT organization_id FROM organization_member WHERE user_id = $1 LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Organization lookup unavailable",
                "ORG_ERROR",
            )),
        )
    })?;

    match row {
        Some(org_id) => Ok(org_id),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Organization not found",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}

pub async fn create_sse_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SseTicketResponse>, (StatusCode, Json<ErrorResponse>)> {
    let token = extract_session_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Session token required. Use Authorization header or session cookie.",
                "SESSION_REQUIRED",
            )),
        )
    })?;

    let user = validate_session_token(&state.db, token).await?;

    let ticket = Uuid::new_v4().to_string();

    let payload = SseTicketPayload {
        user_id: user.user_id,
        email: user.email,
        name: user.name,
        session_id: user.session_id,
    };

    let payload_json = serde_json::to_string(&payload).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to create ticket",
                "TICKET_ERROR",
            )),
        )
    })?;

    let key = format!("{}{}", SSE_TICKET_PREFIX, ticket);
    let mut redis = state.redis.clone();

    redis
        .set_ex::<_, _, ()>(&key, &payload_json, SSE_TICKET_TTL_SECS)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Failed to store ticket", "TICKET_ERROR")),
            )
        })?;

    tracing::debug!(
        "SSE ticket created for user={}, expires in {}s",
        payload.user_id,
        SSE_TICKET_TTL_SECS
    );

    Ok(Json(SseTicketResponse {
        ticket,
        expires_in: SSE_TICKET_TTL_SECS,
    }))
}


pub async fn guard_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SseQueryParams>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let user = if let Some(ref ticket) = query.ticket {
        if ticket.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Empty ticket provided",
                    "TICKET_INVALID",
                )),
            ));
        }

        let mut redis = state.redis.clone();
        redeem_sse_ticket(&mut redis, ticket).await.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Invalid, expired, or already-used ticket. \
                     Obtain a new ticket via POST /v1/guard/events/ticket.",
                    "TICKET_INVALID",
                )),
            )
        })?
    } else if let Some(token) = extract_session_token_from_headers(&headers) {
        validate_session_token(&state.db, token).await?
    } else {
        require_session_from_headers(&state.db, &headers)
            .await
            .map_err(|(status, json)| {
                (
                    status,
                    Json(ErrorResponse::new(
                        format!(
                            "{}. For SSE connections, obtain a ticket via POST /v1/guard/events/ticket \
                             and pass it as ?ticket= query parameter, or use cookie-based auth.",
                            json.error
                        ),
                        json.code.clone(),
                    )),
                )
            })?
    };

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    tracing::info!(
        "SSE client connected: user={}, org={}",
        user.user_id,
        org_id
    );

    let (tx, rx) = mpsc::channel::<Event>(256);

    let connected_event = Event::default().event("connected").data(
        serde_json::json!({
            "organization_id": org_id.to_string(),
            "user_id": user.user_id,
            "message": "Connected to real-time guard log stream"
        })
        .to_string(),
    );

    if tx.send(connected_event).await.is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to initialize SSE stream",
                "SSE_INIT_FAILED",
            )),
        ));
    }

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let tx_clone = tx.clone();
    let db_pool = state.db.clone();

    tokio::spawn(async move {
        let client = match redis::Client::open(redis_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("SSE: Failed to create Redis client: {}", e);
                return;
            }
        };

        let mut pubsub_conn = match client.get_async_pubsub().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("SSE: Failed to connect to Redis pub/sub: {}", e);
                return;
            }
        };

        if let Err(e) = pubsub_conn.subscribe("guard_log_events").await {
            tracing::error!("SSE: Failed to subscribe to guard_log_events: {}", e);
            return;
        }

        tracing::debug!("SSE: Subscribed to guard_log_events for org {}", org_id);

        let tx_stats = tx_clone.clone();
        let stats_org_id = org_id;
        let stats_db = db_pool.clone();

        let stats_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                let stats = fetch_org_stats(&stats_db, stats_org_id).await;
                let event = Event::default()
                    .event("stats_update")
                    .data(serde_json::to_string(&stats).unwrap_or_default());

                if tx_stats.send(event).await.is_err() {
                    break;
                }
            }
        });
        use futures::StreamExt;
        let mut msg_stream = pubsub_conn.on_message();

        while let Some(msg) = msg_stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let event: GuardLogEvent = match serde_json::from_str(&payload) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if event.organization_id != Some(org_id) {
                continue;
            }

            let sse_event = Event::default().event("guard_log").data(payload);

            if tx_clone.send(sse_event).await.is_err() {
                tracing::debug!("SSE client disconnected: org={}", org_id);
                break;
            }
        }

        stats_handle.abort();
        tracing::debug!("SSE: Pub/sub listener exiting for org {}", org_id);
    });

    let stream = GuardEventStream { rx };
    let sse = Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    );

    Ok(sse.into_response())
}


#[derive(serde::Serialize)]
struct OrgStats {
    total_scans: i64,
    threats_blocked: i64,
    safe_prompts: i64,
    avg_latency: i64,
}

async fn fetch_org_stats(db: &sqlx::PgPool, org_id: Uuid) -> OrgStats {
    use sqlx::Row;

    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) as total_scans,
            COUNT(*) FILTER (WHERE is_safe = true) as safe_prompts,
            COUNT(*) FILTER (WHERE is_safe = false) as threats_blocked,
            COALESCE(AVG(latency_ms)::BIGINT, 0) as avg_latency
        FROM guard_log
        WHERE organization_id = $1
        "#,
    )
    .bind(org_id)
    .fetch_one(db)
    .await;

    match row {
        Ok(r) => OrgStats {
            total_scans: r.get("total_scans"),
            threats_blocked: r.get("threats_blocked"),
            safe_prompts: r.get("safe_prompts"),
            avg_latency: r.get("avg_latency"),
        },
        Err(e) => {
            tracing::error!("Failed to fetch org stats for SSE: {}", e);
            OrgStats {
                total_scans: 0,
                threats_blocked: 0,
                safe_prompts: 0,
                avg_latency: 0,
            }
        }
    }
}
