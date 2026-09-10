use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pcap_doctor_web::app;
use tower::ServiceExt;

#[tokio::test]
async fn health_endpoint_reports_homologation_phase() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), br#"{"status":"ok","phase":"homologation"}"#);
}
