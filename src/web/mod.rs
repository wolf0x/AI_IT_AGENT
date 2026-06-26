use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use std::path::PathBuf;

pub struct StaticServer;

impl StaticServer {
    fn prefer_disk_assets() -> bool {
        cfg!(debug_assertions)
    }

    /// Resolve the static files directory relative to the executable.
    fn static_dir() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("static")))
            .unwrap_or_else(|| PathBuf::from("static"))
    }

    pub fn serve_file(path: &str) -> Response {
        if Self::prefer_disk_assets() {
            let dir = Self::static_dir();
            let full_path = dir.join(path.trim_start_matches('/'));

            if full_path.exists() && full_path.is_file() {
                return match std::fs::read(&full_path) {
                    Ok(content) => {
                        let mime = mime_guess::from_path(&full_path).first_or_octet_stream();
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", mime.as_ref())
                            .body(content.into())
                            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                    Err(_) => Self::serve_embedded(path),
                };
            }
        }

        Self::serve_embedded(path)
    }

    /// Serve files embedded in the binary as fallback.
    fn serve_embedded(path: &str) -> Response {
        match path {
            "marked.min.js" => {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/javascript")
                    .body(include_str!("../../static/marked.min.js").as_bytes().to_vec().into())
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }

    pub fn serve_index() -> Response {
        if Self::prefer_disk_assets() {
            // Debug/dev: prefer disk assets for live editing.
            let exe_static = Self::static_dir().join("index.html");
            if exe_static.exists() {
                if let Ok(content) = std::fs::read_to_string(&exe_static) {
                    return Html(content).into_response();
                }
            }
            let cwd_path = PathBuf::from("static/index.html");
            if cwd_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&cwd_path) {
                    return Html(content).into_response();
                }
            }
        }

        Html(include_str!("../../static/index.html").to_string()).into_response()
    }
}
