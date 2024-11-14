use axum::{
    routing::post,
    Router,
    Json,
};
use tower_http::services::ServeDir;
use serde::{Deserialize, Serialize};
mod subdomain;

#[derive(Deserialize)]
struct DomainRequest {
    domain: String,
    deep_scan: Option<bool>,
}

#[derive(Serialize)]
struct SubdomainResponse {
    subdomains: Vec<String>,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/find-subdomains", post(find_subdomains))
        .nest_service("/", ServeDir::new("static"));

    println!("Server running on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn find_subdomains(
    Json(payload): Json<DomainRequest>,
) -> Json<SubdomainResponse> {
    let finder = subdomain::SubdomainFinder::new(payload.deep_scan.unwrap_or(false)).await;
    let subdomains = finder.find_subdomains(&payload.domain).await;
    Json(SubdomainResponse { subdomains })
} 