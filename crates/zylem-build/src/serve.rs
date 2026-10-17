//! `zylem-build serve`: hosts Rings over HTTP and keeps them current from a pruned node.

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};

use crate::builder::Builder;

async fn file(State(dir): State<Arc<PathBuf>>, Path(path): Path<String>) -> impl IntoResponse {
    // Only plain relative paths inside the directory.
    if path.split('/').any(|p| p.is_empty() || p == "." || p == ".." || p.contains('\\')) {
        return (StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "text/plain")], b"bad path".to_vec());
    }
    match tokio::fs::read(dir.join(&path)).await {
        Ok(bytes) => {
            let ct = if path.ends_with(".json") { "application/json" } else { "application/octet-stream" };
            (StatusCode::OK, [(header::CONTENT_TYPE, ct)], bytes)
        }
        Err(_) => (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain")], b"not found".to_vec()),
    }
}

/// Serves `dir` and, when a builder is given, extends it every `interval`.
pub async fn run(dir: PathBuf, listen: SocketAddr, builder: Option<Builder>, interval: Duration) -> Result<()> {
    if let Some(b) = builder {
        tokio::spawn(async move {
            loop {
                if let Err(e) = b.step(None, None).await {
                    eprintln!("serve: build step failed: {e:#}");
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
    let app = Router::new().route("/{*path}", get(file)).with_state(Arc::new(dir));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("serving Rings on http://{listen}/manifest.json");
    axum::serve(listener, app).await?;
    Ok(())
}
