use pcap_doctor_web::app;

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("bind pcap-doctor-web");
    axum::serve(listener, app())
        .await
        .expect("serve pcap-doctor-web");
}
