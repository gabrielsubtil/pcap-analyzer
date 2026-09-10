use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pcap_doctor_web::app_with_temp_dir;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

fn multipart(body: &[u8], boundary: &str) -> Body {
    let mut bytes = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"nao-confiar.pcap\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Body::from(bytes)
}

fn multipart_files(files: &[(&str, &[u8])], boundary: &str) -> Body {
    let mut bytes = Vec::new();
    for (name, body) in files {
        bytes.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Body::from(bytes)
}
async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pcap-doctor-{label}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn pcap() -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ];
    bytes.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]);
    bytes
}
fn pcapng() -> Vec<u8> {
    let mut bytes = vec![
        0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 28, 0, 0, 0,
    ];
    bytes.extend_from_slice(&[
        1, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0,
    ]);
    bytes.extend_from_slice(&[
        6, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2,
        3, 4, 0, 0, 0, 0, 40, 0, 0, 0,
    ]);
    bytes
}

#[tokio::test]
async fn create_job_requires_multipart_content_type() {
    let response = app_with_temp_dir(temp_dir("content-type"))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn valid_pcap_is_parsed_and_temp_file_removed() {
    let dir = temp_dir("pcap");
    let service = app_with_temp_dir(dir.clone());
    let bytes = pcap();
    let boundary = "pcap-boundary";
    let response = service
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(multipart(&bytes, boundary))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = json_body(response).await;
    assert_eq!(json["contract_version"], "pcap-doctor.job-result.v1");
    assert_eq!(json["metrics"]["format"], "pcap");
    assert_eq!(json["metrics"]["packet_count"], 1);
    assert_eq!(json["metrics"]["captured_bytes"], 4);
    assert_eq!(json["metrics"]["linktypes"][0]["value"], 1);
    assert!(
        fs::read_dir(&dir)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true)
    );
}

#[tokio::test]
async fn valid_pcapng_is_parsed() {
    let dir = temp_dir("pcapng");
    let response = app_with_temp_dir(dir)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs")
                .header("content-type", "multipart/form-data; boundary=ng")
                .body(multipart(&pcapng(), "ng"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = json_body(response).await;
    assert_eq!(json["metrics"]["format"], "pcapng");
    assert_eq!(json["metrics"]["packet_count"], 1);
}

#[tokio::test]
async fn dns_subresource_is_paginated_and_validates_limit() {
    let service = app_with_temp_dir(temp_dir("dns-page"));
    let response = service
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs")
                .header("content-type", "multipart/form-data; boundary=dns")
                .body(multipart(&pcap(), "dns"))
                .unwrap(),
        )
        .await
        .unwrap();
    let job = json_body(response).await;
    let id = job["job_id"].as_str().unwrap();
    assert!(job["metrics"].get("dns_entries").is_none());
    let page = service
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/jobs/{id}/dns?limit=1&offset=0"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let json = json_body(page).await;
    assert_eq!(json["contract_version"], "pcap-doctor.dns-page.v1");
    assert_eq!(json["total"], 0);
    let bad = service
        .oneshot(
            Request::builder()
                .uri(format!("/api/jobs/{id}/dns?limit=101"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_and_truncated_captures_fail_safely_and_cleanup() {
    for (label, bytes) in [
        ("invalid", b"not a capture".to_vec()),
        ("truncated", pcap()[..30].to_vec()),
    ] {
        let dir = temp_dir(label);
        let response = app_with_temp_dir(dir.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/jobs")
                    .header(
                        "content-type",
                        format!("multipart/form-data; boundary={label}"),
                    )
                    .body(multipart(&bytes, label))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{label}"
        );
        let json = json_body(response).await;
        assert_eq!(json["status"], "failed");
        assert!(
            fs::read_dir(&dir)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(true)
        );
    }
}

#[tokio::test]
async fn aggregate_job_accepts_fifty_files_and_returns_one_bounded_result() {
    let files: Vec<_> = (0..50).map(|_| ("capture.pcap", pcap())).collect();
    let refs: Vec<_> = files
        .iter()
        .map(|(name, bytes)| (*name, bytes.as_slice()))
        .collect();
    let response = app_with_temp_dir(temp_dir("aggregate-50"))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs/aggregate")
                .header("content-type", "multipart/form-data; boundary=aggregate")
                .body(multipart_files(&refs, "aggregate"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = json_body(response).await;
    assert_eq!(json["metrics"]["packet_count"], 50);
    assert!(json["metrics"]["summary"].get("source_ip_values").is_none());
    assert!(
        json["metrics"]["summary"]
            .get("destination_ip_values")
            .is_none()
    );
}

#[tokio::test]
async fn aggregate_job_rejects_more_than_fifty_files() {
    let files: Vec<_> = (0..51).map(|_| ("capture.pcap", pcap())).collect();
    let refs: Vec<_> = files
        .iter()
        .map(|(name, bytes)| (*name, bytes.as_slice()))
        .collect();
    let response = app_with_temp_dir(temp_dir("aggregate-count-limit"))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs/aggregate")
                .header("content-type", "multipart/form-data; boundary=too-many")
                .body(multipart_files(&refs, "too-many"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
