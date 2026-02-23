use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post},
};
use futures::{Stream, StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap, convert::Infallible, env, net::SocketAddr, sync::Arc, time::Duration,
};
use tokio::{net::TcpListener, sync::RwLock, time::Instant};
use uuid::Uuid;

const TICKET_TTL_SECS: u64 = 30;

#[derive(Clone, Default)]
struct AppState {
    tickets: Arc<RwLock<HashMap<String, Instant>>>,
}

#[derive(Serialize)]
struct PingResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
    code: &'static str,
}

#[derive(Serialize)]
struct TicketResponse {
    ticket: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct ConnectedEvent {
    organization_id: String,
    user_id: String,
    message: String,
}

#[derive(Serialize)]
struct StatsUpdateEvent {
    total_scans: u64,
    threats_blocked: u64,
    safe_prompts: u64,
    avg_latency: u64,
}

#[derive(Deserialize)]
struct GuardEventsQuery {
    ticket: Option<String>,
}

async fn ping() -> Json<PingResponse> {
    Json(PingResponse { status: "ok" })
}

fn sse_json_event<T: Serialize>(event_name: &str, payload: &T) -> Result<Event, Infallible> {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Ok(Event::default().event(event_name).data(data))
}

async fn create_guard_events_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TicketResponse>, (StatusCode, Json<ErrorResponse>)> {
    let is_authorized = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    if !is_authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing Authorization header",
                code: "UNAUTHORIZED",
            }),
        ));
    }

    let ticket = Uuid::new_v4().to_string();
    let expires_at = Instant::now() + Duration::from_secs(TICKET_TTL_SECS);

    state.tickets.write().await.insert(ticket.clone(), expires_at);

    Ok(Json(TicketResponse {
        ticket,
        expires_in: TICKET_TTL_SECS,
    }))
}

async fn guard_events_stream(
    State(state): State<AppState>,
    Query(query): Query<GuardEventsQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<ErrorResponse>)> {
    let Some(ticket) = query.ticket else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing ticket query parameter",
                code: "TICKET_INVALID",
            }),
        ));
    };

    let mut tickets = state.tickets.write().await;
    let is_valid = tickets
        .remove(&ticket)
        .map(|expires_at| expires_at > Instant::now())
        .unwrap_or(false);
    drop(tickets);

    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid, expired, or already used ticket",
                code: "TICKET_INVALID",
            }),
        ));
    }

    let connected_event = ConnectedEvent {
        organization_id: "unknown".to_string(),
        user_id: "unknown".to_string(),
        message: "Connected to guard events stream".to_string(),
    };

    let initial = stream::once(async move { sse_json_event("connected", &connected_event) });

    let periodic = stream::unfold((), |_| async move {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let stats = StatsUpdateEvent {
            total_scans: 0,
            threats_blocked: 0,
            safe_prompts: 0,
            avg_latency: 0,
        };
        Some((sse_json_event("stats_update", &stats), ()))
    });

    let events = initial.chain(periodic);

    Ok(Sse::new(events).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

#[tokio::main]
async fn main() {
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("SERVER_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let addr = format!("{host}:{port}")
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)));

    let state = AppState::default();

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/v1/guard/events/ticket", post(create_guard_events_ticket))
        .route("/v1/guard/events", get(guard_events_stream))
        .with_state(state);

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
