mod http;
mod messages;
mod state;
mod ws;

use axum::{routing::{get, post}, Extension, Router};
use state::SharedState;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    tracing_subscriber::fmt::init();

    let state: SharedState = Default::default();

    let app = Router::new()
        .route("/ws", get(ws::handler::ws_handler))
        .route("/upload", post(http::upload::upload_handler))
        .route("/media/{path}", get(http::media::media_handler))
        .fallback(http::fallback::fallback_handler)
        .layer(Extension(state));

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    info!("Server is started on http://{:?}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
