pub mod capture;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{
        HeaderMap, StatusCode,
        header::{CONTENT_TYPE, HeaderValue},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{fs, io::AsyncWriteExt, sync::Mutex, time::timeout};
use uuid::Uuid;

const DESKTOP_INDEX: &[u8] = include_bytes!("../../src/frontend/index.html");
const DESKTOP_STYLES: &[u8] = include_bytes!("../../src/frontend/styles.css");
const DESKTOP_APP: &[u8] = include_bytes!("../../src/frontend/app.js");
const DESKTOP_LOGO: &[u8] = include_bytes!("../../src/frontend/assets/logo.png");
const DESKTOP_APP_SCRIPT_TAG: &str = "    <script src=\"app.js\"></script>";
const WEB_APP_SCRIPT_TAGS: &str =
    "    <script src=\"/pywebview-compat.js\"></script>\n    <script src=\"app.js\"></script>";
const PYWEBVIEW_COMPAT: &str = r#"(() => {
  const call = (method, payload = {}) => fetch(`/api/pywebview/${method}`, {
    method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(payload)
  }).then(async response => {
    const data = await response.json();
    if (!response.ok) throw new Error(data?.error?.message || data?.message || `Falha em ${method}`);
    return data;
  });
  const input = document.createElement('input'); input.type = 'file'; input.multiple = true;
  let selectedFiles = [];
  const sum = (a, b) => a + (Number(b) || 0);
  const mergeCounts = (items, key) => items.reduce((out, item) => {
    const name = String(item[key]); out[name] = sum(out[name] || 0, item.packets); return out;
  }, {});
  const aggregate = results => {
    const metrics = results.map(result => result.metrics).filter(Boolean);
    const summaries = metrics.map(metric => metric.summary || {});
    const top = key => Object.values(summaries.flatMap(summary => summary[key] || []).reduce((out, item) => {
      const name = item.value; out[name] = {...item, packets: sum(out[name]?.packets || 0, item.packets)}; return out;
    }, {})).sort((a, b) => b.packets - a.packets || a.value.localeCompare(b.value)).slice(0, 10);
    const threats = Object.values(metrics.flatMap(metric => metric.threat_summary || []).reduce((out, item) => {
      out[item.rule_id] = {...item, count: sum(out[item.rule_id]?.count || 0, item.count)}; return out;
    }, {})).sort((a, b) => b.count - a.count || a.rule_id.localeCompare(b.rule_id));
    return {
      totalPackets: summaries.reduce((total, summary) => sum(total, summary.packet_count), 0),
      totalBytes: metrics.reduce((total, metric) => sum(total, metric.captured_bytes), 0),
      uniqueSrcIpsCount: summaries.reduce((total, summary) => sum(total, summary.unique_source_ips), 0),
      uniqueDstIpsCount: summaries.reduce((total, summary) => sum(total, summary.unique_destination_ips), 0),
      topTalkers: top('top_talkers'), topDestinations: top('top_destinations'),
      protocolStats: summaries.reduce((out, summary) => { for (const [name, count] of Object.entries(summary.protocol_counts || {})) out[name] = sum(out[name] || 0, count); return out; }, {}),
      portStats: mergeCounts(summaries.flatMap(summary => summary.destination_ports || []), 'port'),
      srcPortStats: mergeCounts(summaries.flatMap(summary => summary.source_ports || []), 'port'),
      packetSizeStats: {}, threatStats: threats
    };
  };
  const analyze = async () => {
    if (!selectedFiles.length) throw new Error('Nenhum arquivo selecionado.');
    const results = [];
    for (const file of selectedFiles) {
      const form = new FormData(); form.append('file', file, file.name);
      const response = await fetch('/api/jobs', {method: 'POST', body: form});
      const data = await response.json();
      if (!response.ok || data.status === 'failed') throw new Error(data?.error?.message || data?.message || 'Falha no job de análise.');
      results.push(data);
    }
    return aggregate(results);
  };
  window.pywebview = { api: {
    get_app_version: () => call('get_app_version'),
    get_catalog: () => call('get_catalog').then(data => data.rules || data),
    pick_files: () => new Promise(resolve => { input.value = ''; input.onchange = () => { selectedFiles = Array.from(input.files || []).slice(0, 50); resolve(selectedFiles.map(file => file.name)); }; input.click(); }),
    analyze_files: () => analyze(),
    get_string_filter_types: () => call('get_string_filter_types'),
    get_analysis_strings: args => call('get_analysis_strings', { args }),
    get_dns_records: args => call('get_dns_records', { args }),
    get_all_strings: args => call('get_all_strings', { args })
  }};
  window.dispatchEvent(new Event('pywebviewready'));
})();
"#;

const MAX_UPLOAD_BYTES: u64 = 64 * 1024 * 1024;
const JOB_TTL: Duration = Duration::from_secs(15 * 60);
const PARSE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AppState {
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    temp_dir: PathBuf,
}
#[derive(Clone)]
struct Job {
    expires_at: SystemTime,
    result: JobResult,
    dns: Vec<capture::DnsEntry>,
}

#[derive(Clone, Serialize)]
struct JobResult {
    contract_version: &'static str,
    job_id: String,
    status: &'static str,
    format: Option<&'static str>,
    bytes: u64,
    limited_result: bool,
    metrics: Option<capture::CaptureMetrics>,
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
    app_with_temp_dir(std::env::temp_dir().join("pcap-doctor-jobs"))
}
pub fn app_with_temp_dir(temp_dir: PathBuf) -> Router {
    app_with_state(AppState {
        jobs: Arc::new(Mutex::new(HashMap::new())),
        temp_dir,
    })
}
pub fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(app_script))
        .route("/assets/logo.png", get(logo))
        .route("/pywebview-compat.js", get(pywebview_compat))
        .route("/api/health", get(health))
        .route("/api/threat-catalog", get(threat_catalog))
        .route("/api/pywebview/{method}", post(pywebview_api))
        .route("/api/jobs", post(create_job))
        .route("/api/jobs/{job_id}", get(get_job))
        .route("/api/jobs/{job_id}/dns", get(get_dns))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES as usize))
        .with_state(state)
}
fn static_asset(body: impl IntoResponse, content_type: &'static str) -> Response {
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}
async fn index() -> Response {
    let html =
        String::from_utf8_lossy(DESKTOP_INDEX).replace(DESKTOP_APP_SCRIPT_TAG, WEB_APP_SCRIPT_TAGS);
    let mut response = html.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}
async fn styles() -> Response {
    static_asset(DESKTOP_STYLES, "text/css; charset=utf-8")
}
async fn app_script() -> Response {
    static_asset(DESKTOP_APP, "text/javascript; charset=utf-8")
}
async fn logo() -> Response {
    static_asset(DESKTOP_LOGO, "image/png")
}
async fn pywebview_compat() -> Response {
    static_asset(
        PYWEBVIEW_COMPAT.as_bytes(),
        "text/javascript; charset=utf-8",
    )
}

async fn pywebview_api(
    Path(method): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiErrorResponse>)> {
    match method.as_str() {
        "get_app_version" => Ok(Json(serde_json::json!("5.0"))),
        "get_catalog" => Ok(Json(serde_json::json!({
            "contract_version": "pcap-doctor.threat-catalog.v1",
            "rules": capture::catalog()
        }))),
        "pick_files"
        | "analyze_files"
        | "get_string_filter_types"
        | "get_analysis_strings"
        | "get_dns_records"
        | "get_all_strings" => {
            let _ = payload;
            Err(api_error(
                StatusCode::NOT_IMPLEMENTED,
                "method_not_implemented",
                "método ainda sem backend de paridade",
            ))
        }
        _ => Err(api_error(
            StatusCode::NOT_FOUND,
            "unknown_method",
            "método pywebview desconhecido",
        )),
    }
}
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        phase: "homologation",
    })
}

#[derive(Serialize)]
struct ThreatCatalogResponse {
    contract_version: &'static str,
    heuristic_notice: &'static str,
    rules: Vec<capture::ThreatSummaryEntry>,
}

async fn threat_catalog() -> Json<ThreatCatalogResponse> {
    Json(ThreatCatalogResponse {
        contract_version: "pcap-doctor.threat-catalog.v1",
        heuristic_notice: "Estas regras são heurísticas; não provam comprometimento.",
        rules: capture::catalog(),
    })
}

async fn create_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Result<(StatusCode, Json<JobResult>), (StatusCode, Json<ApiErrorResponse>)> {
    if !headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("multipart/form-data"))
    {
        return Err(api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "envie um arquivo PCAP ou PCAPNG via multipart",
        ));
    }
    let mut multipart = multipart.map_err(|error| json_error(bad_multipart(error)))?;
    cleanup_expired(&state).await;
    let job_id = Uuid::new_v4().simple().to_string();
    let path = state.temp_dir.join(format!("{job_id}.capture"));
    fs::create_dir_all(&state.temp_dir)
        .await
        .map_err(|error| json_error(internal_error(error)))?;
    let outcome = receive_and_parse(&mut multipart, &path).await;
    let _ = fs::remove_file(&path).await;
    let result = match outcome {
        Ok(metrics) => JobResult {
            contract_version: "pcap-doctor.job-result.v1",
            job_id: job_id.clone(),
            status: "complete",
            format: Some(metrics.format),
            bytes: metrics.file_bytes,
            limited_result: true,
            metrics: Some(metrics),
            message:
                "captura processada; o resultado contém métricas limitadas e não expõe payloads"
                    .into(),
        },
        Err((status, error)) => {
            if status == StatusCode::UNPROCESSABLE_ENTITY {
                JobResult {
                    contract_version: "pcap-doctor.job-result.v1",
                    job_id: job_id.clone(),
                    status: "failed",
                    format: None,
                    bytes: 0,
                    limited_result: true,
                    metrics: None,
                    message: error.error.message.into(),
                }
            } else {
                return Err((status, Json(error)));
            }
        }
    };
    let status = if result.status == "complete" {
        StatusCode::CREATED
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let dns = result
        .metrics
        .as_ref()
        .map(|m| m.dns_entries.clone())
        .unwrap_or_default();
    state.jobs.lock().await.insert(
        job_id,
        Job {
            expires_at: SystemTime::now() + JOB_TTL,
            result: result.clone(),
            dns,
        },
    );
    Ok((status, Json(result)))
}

#[derive(Debug, Deserialize)]
struct DnsQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}
#[derive(Serialize)]
struct DnsResponse {
    contract_version: &'static str,
    job_id: String,
    limit: u64,
    offset: u64,
    total: u64,
    items: Vec<capture::DnsEntry>,
}
async fn get_dns(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Query(query): Query<DnsQuery>,
) -> Result<Json<DnsResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    let limit = query.limit.unwrap_or(25);
    let offset = query.offset.unwrap_or(0);
    if !(1..=100).contains(&limit) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "limit deve estar entre 1 e 100",
        ));
    }
    let mut jobs = state.jobs.lock().await;
    jobs.retain(|_, job| job.expires_at > SystemTime::now());
    let job = jobs.get(&job_id).ok_or_else(|| {
        api_error(
            StatusCode::NOT_FOUND,
            "job_not_found",
            "job não encontrado ou expirado",
        )
    })?;
    let total = job.dns.len() as u64;
    if offset > total {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_pagination",
            "offset excede o total de itens",
        ));
    }
    let start = offset as usize;
    let end = (start + limit as usize).min(job.dns.len());
    Ok(Json(DnsResponse {
        contract_version: "pcap-doctor.dns-page.v1",
        job_id,
        limit,
        offset,
        total,
        items: job.dns[start..end].to_vec(),
    }))
}

async fn receive_and_parse(
    multipart: &mut Multipart,
    path: &std::path::Path,
) -> Result<capture::CaptureMetrics, (StatusCode, ApiErrorResponse)> {
    let mut file = fs::File::create(path).await.map_err(internal_error)?;
    let mut bytes = 0u64;
    let mut found_file = false;
    while let Some(field) = multipart.next_field().await.map_err(bad_multipart)? {
        if field.name() != Some("file") || found_file {
            continue;
        }
        found_file = true;
        let mut field = field;
        while let Some(chunk) = field.next().await {
            let chunk = chunk.map_err(bad_multipart)?;
            bytes = bytes.saturating_add(chunk.len() as u64);
            if bytes > MAX_UPLOAD_BYTES {
                return Err(raw_api_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "upload_too_large",
                    "o arquivo excede o limite de 64 MiB",
                ));
            }
            file.write_all(&chunk).await.map_err(internal_error)?;
        }
    }
    file.flush().await.map_err(internal_error)?;
    drop(file);
    if !found_file || bytes == 0 {
        return Err(raw_api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_capture",
            "captura inválida ou campo file ausente",
        ));
    }
    let parse_path = path.to_path_buf();
    match timeout(
        PARSE_DEADLINE,
        tokio::task::spawn_blocking(move || capture::parse_capture(&parse_path, bytes)),
    )
    .await
    {
        Ok(Ok(Ok(metrics))) => Ok(metrics),
        Ok(Ok(Err(_))) | Ok(Err(_)) | Err(_) => Err(raw_api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_capture",
            "captura inválida, truncada ou fora dos limites",
        )),
    }
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
fn json_error(
    (status, error): (StatusCode, ApiErrorResponse),
) -> (StatusCode, Json<ApiErrorResponse>) {
    (status, Json(error))
}
fn raw_api_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> (StatusCode, ApiErrorResponse) {
    (
        status,
        ApiErrorResponse {
            error: ApiError { code, message },
        },
    )
}
fn api_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> (StatusCode, Json<ApiErrorResponse>) {
    let (status, error) = raw_api_error(status, code, message);
    (status, Json(error))
}
fn internal_error(_: impl std::fmt::Debug) -> (StatusCode, ApiErrorResponse) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        ApiErrorResponse {
            error: ApiError {
                code: "internal_error",
                message: "erro interno ao processar upload",
            },
        },
    )
}
fn bad_multipart(_: impl std::fmt::Debug) -> (StatusCode, ApiErrorResponse) {
    (
        StatusCode::BAD_REQUEST,
        ApiErrorResponse {
            error: ApiError {
                code: "invalid_multipart",
                message: "multipart inválido",
            },
        },
    )
}
