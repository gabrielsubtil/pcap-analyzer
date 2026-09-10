use axum::{body::Body, http::{Request, StatusCode}};
use http_body_util::BodyExt;
use pcap_doctor_web::app;
use tower::ServiceExt;

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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        body.as_ref(),
        br#"{"error":{"code":"unsupported_media_type","message":"envie um arquivo PCAP ou PCAPNG via multipart"}}"#,
    );
}
