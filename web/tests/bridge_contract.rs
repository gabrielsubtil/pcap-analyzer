use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pcap_doctor_web::app_with_temp_dir;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "pcap-doctor-bridge-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

async fn text(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn browser_selection_preserves_order_and_enforces_fifty_file_limit() {
    let script = text(
        app_with_temp_dir(temp_dir())
            .oneshot(
                Request::get("/pywebview-compat.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert!(script.contains("selectedFiles"));
    assert!(script.contains("slice(0, 50)"));
    assert!(script.contains("Array.from(input.files"));
    assert!(script.contains("map(file => file.name)"));
}

#[tokio::test]
async fn browser_analysis_sends_real_files_as_multipart() {
    let script = text(
        app_with_temp_dir(temp_dir())
            .oneshot(
                Request::get("/pywebview-compat.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert!(script.contains("new FormData()"));
    assert!(script.contains("form.append('file', file, file.name)"));
    assert!(script.contains("fetch('/api/jobs'"));
    assert!(!script.contains("Content-Type"));
}

#[tokio::test]
async fn browser_bridge_maps_and_aggregates_backend_metrics_in_camel_case() {
    let script = text(
        app_with_temp_dir(temp_dir())
            .oneshot(
                Request::get("/pywebview-compat.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    for key in [
        "totalPackets",
        "totalBytes",
        "uniqueSrcIpsCount",
        "uniqueDstIpsCount",
        "topTalkers",
        "topDestinations",
        "protocolStats",
        "portStats",
        "srcPortStats",
        "packetSizeStats",
        "threatStats",
    ] {
        assert!(script.contains(key), "missing {key}");
    }
    assert!(script.contains("const metrics = results.map"));
    assert!(script.contains("for (const file of selectedFiles)"));
    assert!(script.contains("results.push(data)"));
    assert!(script.contains("summary.packet_count"));
    assert!(script.contains("metric.summary"));
}

#[tokio::test]
async fn browser_bridge_propagates_failed_job_as_controlled_error() {
    let script = text(
        app_with_temp_dir(temp_dir())
            .oneshot(
                Request::get("/pywebview-compat.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert!(script.contains("if (!response.ok)"));
    assert!(script.contains("throw new Error"));
    assert_eq!(StatusCode::UNPROCESSABLE_ENTITY.as_u16(), 422);
}
