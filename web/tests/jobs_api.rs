use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pcap_doctor_web::app;
use tower::ServiceExt;

fn multipart(body: &[u8], boundary: &str) -> Body {
    let mut bytes = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"nao-confiar.pcap\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Body::from(bytes)
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn create_job_requires_multipart_content_type() {
    let response = app()
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
async fn valid_pcap_creates_limited_result_and_it_is_retrievable() {
    let boundary = "test-boundary";
    let service = app();
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
                .body(multipart(&[0xd4, 0xc3, 0xb2, 0xa1, 1, 2, 3], boundary))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = json_body(response).await;
    assert_eq!(json["status"], "complete");
    assert_eq!(json["format"], "pcap");
    assert_eq!(json["bytes"], 7);
    assert_eq!(json["limited_result"], true);
    let job_id = json["job_id"].as_str().unwrap();
    assert_eq!(job_id.len(), 32);
    let response = service
        .oneshot(
            Request::builder()
                .uri(format!("/api/jobs/{job_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result = json_body(response).await;
    assert_eq!(result["job_id"], job_id);
}

#[tokio::test]
async fn invalid_magic_is_failed_and_not_saved_to_disk() {
    let boundary = "invalid-boundary";
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(multipart(b"not a capture", boundary))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = json_body(response).await;
    assert_eq!(json["status"], "failed");
    assert_eq!(json["format"], serde_json::Value::Null);
}

#[tokio::test]
async fn pcapng_magic_is_accepted() {
    let boundary = "pcapng-boundary";
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/jobs")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(multipart(&[0x0a, 0x0d, 0x0d, 0x0a], boundary))
                .unwrap(),
        )
        .await
        .unwrap();
    let json = json_body(response).await;
    assert_eq!(json["format"], "pcapng");
}
