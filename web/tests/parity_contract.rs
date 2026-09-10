use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use pcap_doctor_web::app;
use tower::ServiceExt;

async fn body(response: axum::response::Response) -> Vec<u8> {
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn serves_desktop_frontend_artifacts_byte_for_byte() {
    let cases = [
        (
            "/",
            include_bytes!("../../src/frontend/index.html").as_slice(),
        ),
        (
            "/styles.css",
            include_bytes!("../../src/frontend/styles.css").as_slice(),
        ),
        (
            "/app.js",
            include_bytes!("../../src/frontend/app.js").as_slice(),
        ),
        (
            "/assets/logo.png",
            include_bytes!("../../src/frontend/assets/logo.png").as_slice(),
        ),
    ];

    for (uri, expected) in cases {
        let response = app()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(body(response).await, expected, "{uri} differs from Desktop");
    }
}

#[tokio::test]
async fn serves_frontend_assets_with_browser_content_types() {
    for (uri, expected) in [
        ("/", "text/html; charset=utf-8"),
        ("/styles.css", "text/css; charset=utf-8"),
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/assets/logo.png", "image/png"),
    ] {
        let response = app()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CONTENT_TYPE], expected, "{uri}");
    }
}

#[tokio::test]
async fn exposes_pywebview_compatibility_methods() {
    let request = Request::post("/api/pywebview/get_app_version")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, br#""5.0""#);
}

#[tokio::test]
async fn unsupported_pywebview_methods_return_controlled_errors() {
    let request = Request::post("/api/pywebview/pick_files")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let payload = body(response).await;
    let text = std::str::from_utf8(&payload).unwrap();
    assert!(text.contains("method_not_implemented"));
    assert!(!text.contains("path"));
}

#[tokio::test]
async fn serves_browser_bridge_that_uses_file_input_without_paths() {
    let response = app()
        .oneshot(
            Request::get("/pywebview-compat.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let script = String::from_utf8(body(response).await).unwrap();
    assert!(script.contains("window.pywebview"));
    assert!(script.contains("type = 'file'"));
    assert!(script.contains("/api/pywebview/"));
    assert!(!script.contains("path"));
}
