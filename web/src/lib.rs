use axum::{response::Html, routing::get, Json, Router};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    phase: &'static str,
}

pub fn app() -> Router {
    Router::new()
        .route("/", get(home))
        .route("/api/health", get(health))
}

async fn home() -> Html<&'static str> {
    Html(include_str!("../index.html"))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        phase: "homologation",
    })
}
