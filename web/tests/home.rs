use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pcap_doctor_web::app;
use tower::ServiceExt;

#[tokio::test]
async fn home_page_identifies_pcap_doctor_homologation() {
    let response = app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body).unwrap().contains("PCAP Doctor"));
}
