use axum::{
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    phase: &'static str,
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct ApiErrorResponse {
    error: ApiError,
}

pub fn app() -> Router {
    Router::new()
        .route("/", get(home))
        .route("/api/health", get(health))
        .route("/api/jobs", post(create_job))
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

async fn create_job(headers: HeaderMap) -> (StatusCode, Json<ApiErrorResponse>) {
    let is_multipart = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("multipart/form-data"));

    if !is_multipart {
        return api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "envie um arquivo PCAP ou PCAPNG via multipart",
        );
    }

    api_error(
        StatusCode::NOT_IMPLEMENTED,
        "job_upload_not_enabled",
        "upload de captura será habilitado na próxima etapa",
    )
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> (StatusCode, Json<ApiErrorResponse>) {
    (
        status,
        Json(ApiErrorResponse {
            error: ApiError { code, message },
        }),
    )
}
