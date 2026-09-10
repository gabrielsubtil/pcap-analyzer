pub mod capture;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::Html,
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Serialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};
use uuid::Uuid;

const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
const JOB_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct AppState {
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    temp_dir: PathBuf,
}

#[derive(Clone)]
struct Job {
    expires_at: SystemTime,
    result: JobResult,
}

#[derive(Clone, Serialize)]
struct JobResult {
    job_id: String,
    status: &'static str,
    format: Option<&'static str>,
    bytes: u64,
    limited_result: bool,
    message: String,
}

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
    app_with_state(AppState {
        jobs: Arc::new(Mutex::new(HashMap::new())),
        temp_dir: std::env::temp_dir().join("pcap-doctor-jobs"),
    })
}

pub fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/api/health", get(health))
        .route("/api/jobs", post(create_job))
        .route("/api/jobs/{job_id}", get(get_job))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES as usize))
        .with_state(state)
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

async fn create_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Result<(StatusCode, Json<JobResult>), (StatusCode, Json<ApiErrorResponse>)> {
    if !headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("multipart/form-data"))
    {
        return Err(api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "envie um arquivo PCAP ou PCAPNG via multipart",
        ));
    }
    let mut multipart = multipart.map_err(bad_multipart)?;
    cleanup_expired(&state).await;
    let job_id = Uuid::new_v4().simple().to_string();
    let path = state.temp_dir.join(format!("{job_id}.capture"));
    fs::create_dir_all(&state.temp_dir)
        .await
        .map_err(internal_error)?;
    let mut file = fs::File::create(&path).await.map_err(internal_error)?;
    let mut header = Vec::with_capacity(4);
    let mut bytes = 0u64;
    let mut found_file = false;

    while let Some(field) = multipart.next_field().await.map_err(bad_multipart)? {
        if field.name() != Some("file") || found_file {
            continue;
        }
        found_file = true;
        let mut stream = field;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(bad_multipart)?;
            bytes = bytes.saturating_add(chunk.len() as u64);
            if bytes > MAX_UPLOAD_BYTES {
                let _ = fs::remove_file(&path).await;
                return Err(api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "upload_too_large",
                    "o arquivo excede o limite de 64 MiB",
                ));
            }
            if header.len() < 4 {
                let needed = 4 - header.len();
                header.extend_from_slice(&chunk[..chunk.len().min(needed)]);
            }
            file.write_all(&chunk).await.map_err(internal_error)?;
        }
    }
    file.flush().await.map_err(internal_error)?;
    drop(file);
    let result = match capture::detect_format(&header) {
        Ok(format) if found_file => JobResult {
            job_id: job_id.clone(),
            status: "complete",
            format: Some(match format {
                capture::CaptureFormat::Pcap => "pcap",
                capture::CaptureFormat::PcapNg => "pcapng",
            }),
            bytes,
            limited_result: true,
            message: "Resultado limitado: formato e tamanho validados; análise de pacotes ainda não está disponível.".into(),
        },
        _ => JobResult {
            job_id: job_id.clone(),
            status: "failed",
            format: None,
            bytes,
            limited_result: true,
            message: "arquivo rejeitado: assinatura PCAP/PCAPNG não reconhecida ou campo file ausente".into(),
        },
    };
    let status = if result.status == "complete" {
        StatusCode::CREATED
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let _ = fs::remove_file(&path).await;
    state.jobs.lock().await.insert(
        job_id,
        Job {
            expires_at: SystemTime::now() + JOB_TTL,
            result: result.clone(),
        },
    );
    Ok((status, Json(result)))
}

async fn get_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResult>, (StatusCode, Json<ApiErrorResponse>)> {
    cleanup_expired(&state).await;
    state
        .jobs
        .lock()
        .await
        .get(&job_id)
        .map(|job| Json(job.result.clone()))
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job não encontrado ou expirado",
            )
        })
}

async fn cleanup_expired(state: &AppState) {
    let now = SystemTime::now();
    state
        .jobs
        .lock()
        .await
        .retain(|_, job| job.expires_at > now);
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

fn internal_error(_: impl std::fmt::Debug) -> (StatusCode, Json<ApiErrorResponse>) {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "erro interno ao processar upload",
    )
}

fn bad_multipart(_: impl std::fmt::Debug) -> (StatusCode, Json<ApiErrorResponse>) {
    api_error(
        StatusCode::BAD_REQUEST,
        "invalid_multipart",
        "multipart inválido",
    )
}
