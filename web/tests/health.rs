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

#[tokio::test]
async fn threat_catalog_is_bounded_and_explanatory() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/threat-catalog")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["contract_version"], "pcap-doctor.threat-catalog.v1");
    assert!(
        json["heuristic_notice"]
            .as_str()
            .unwrap()
            .contains("heurísticas")
    );
    let rule = &json["rules"][0];
    assert_eq!(rule.as_object().unwrap().len(), 4);
    assert!(rule["description"].as_str().is_some());
}
