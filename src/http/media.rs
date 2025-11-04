use axum::{
    extract::Path,
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
};
use std::path::{PathBuf, Component};
use tokio::fs;

const UPLOAD_DIR: &str = "uploads";

pub async fn media_handler(Path(path): Path<String>) -> Result<impl IntoResponse, StatusCode> {
    if path.contains("..") || path.starts_with('/') || path.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let clean_path = PathBuf::from(path);
    if clean_path.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir)) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let full_path = PathBuf::from(UPLOAD_DIR).join(clean_path.clone());

    if !full_path.exists() || !full_path.is_file() {
        return Err(StatusCode::NOT_FOUND);
    }
    
    let contents = fs::read(full_path).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let file_name = clean_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("download");

    let mut headers = header::HeaderMap::new();

    let disposition = format!("attachment; filename=\"{}\"", file_name);
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    Ok((headers, contents))
}
