use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use std::path::Path;

pub struct StaticServer;

impl StaticServer {
    pub fn serve_file(path: &str) -> Response {
        let full_path = format!("static/{}", path.trim_start_matches('/'));
        let p = Path::new(&full_path);

        if p.exists() && p.is_file() {
            match std::fs::read(p) {
                Ok(content) => {
                    let mime = mime_guess::from_path(p).first_or_octet_stream();
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", mime.as_ref())
                        .body(content.into())
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
                Err(_) => Self::serve_embedded(path),
            }
        } else {
            Self::serve_embedded(path)
        }
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
        // Try file system first (for hot-reload during dev), fall back to embedded
        let p = Path::new("static/index.html");
        if p.exists() {
            if let Ok(content) = std::fs::read_to_string(p) {
                return Html(content).into_response();
            }
        }
        Html(include_str!("../../static/index.html").to_string()).into_response()
    }
}
