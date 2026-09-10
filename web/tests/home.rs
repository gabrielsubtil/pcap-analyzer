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
    let html = String::from_utf8(body.to_vec()).unwrap();
    let compat = html
        .find("<script src=\"/pywebview-compat.js\"></script>")
        .unwrap();
    let app = html.find("<script src=\"app.js\"></script>").unwrap();
    assert!(compat < app, "pywebview bridge must precede app.js");
    assert_eq!(
        html,
        String::from_utf8(include_bytes!("../../src/frontend/index.html").to_vec())
            .unwrap()
            .replace(
                "    <script src=\"app.js\"></script>",
                "    <script src=\"/pywebview-compat.js\"></script>\n    <script src=\"app.js\"></script>",
            )
    );
}
