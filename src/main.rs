use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures::TryStreamExt;
use rand::{distr::Alphanumeric, Rng};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, Pool, Sqlite};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use tokio_util::io::ReaderStream;

// --- CONFIGURATION ---
const UPLOAD_DIR: &str = "data/files";
const DB_URL: &str = "sqlite://data/db.sqlite?mode=rwc";
const MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024; // 100 MB
const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60; // 24 Hours

// --- TEMPLATES ---
// include_str! loads the file content into the binary at compile time.
const HTML_UPLOAD: &str = include_str!("../templates/upload.html");
const HTML_FILE: &str = include_str!("../templates/file.html");

#[derive(Clone)]
struct AppState {
    pool: Pool<Sqlite>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(UPLOAD_DIR).await?;
    if let Some(parent) = std::path::Path::new("data").parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all("data").await?;
        }
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(DB_URL)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS shares (
            token TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    let state = Arc::new(AppState { pool: pool.clone() });

    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_expired(&cleanup_pool).await {
                eprintln!("Cleanup error: {}", e);
            }
        }
    });

    let app = Router::new()
        .route("/", get(show_upload))
        .route("/u", post(handle_upload))
        .route("/f/{token}", get(show_file_page))
        .route("/d/{token}", get(download_file))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_SIZE))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// --- HANDLERS ---

async fn show_upload() -> impl IntoResponse {
    render_upload_page(None)
}

async fn handle_upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();

        if name == "file" {
            let original_filename = field.file_name().unwrap_or("file").to_string();
            let content_type = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_string();

            let token: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(12)
                .map(char::from)
                .collect();

            let file_path = PathBuf::from(UPLOAD_DIR).join(&token);
            let mut file = File::create(&file_path).await.map_err(AppError::Io)?;
            let mut stream = field;
            let mut size = 0;

            while let Some(chunk) = stream.try_next().await.map_err(|_| AppError::BadRequest)? {
                size += chunk.len();
                file.write_all(&chunk).await.map_err(AppError::Io)?;
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let expires_at = now + DEFAULT_TTL_SECS as i64;

            sqlx::query(
                "INSERT INTO shares (token, filename, content_type, size, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind(&token)
            .bind(&original_filename)
            .bind(&content_type)
            .bind(size as i64)
            .bind(now)
            .bind(expires_at)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;

            return Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("Location", format!("/f/{}", token))
                .body(Body::empty())
                .unwrap());
        }
    }

    Ok(render_upload_page(Some("Failed to upload file")).into_response())
}

async fn show_file_page(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row: ShareRow = sqlx::query_as("SELECT * FROM shares WHERE token = ?")
        .bind(&token)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?
        .ok_or(AppError::NotFound)?;

    // We use .replace() for basic templating to avoid pulling in external crates.
    // It's simple and effective for this scale.
    let html = HTML_FILE
        .replace("{{ filename }}", &row.filename)
        .replace("{{ token }}", &row.token)
        .replace("{{ share_url }}", &format!("/f/{}", row.token))
        .replace("{{ size }}", &format_bytes(row.size as u64))
        .replace("{{ content_type }}", &row.content_type)
        .replace("{{ created_at }}", &row.created_at.to_string())
        .replace("{{ expires_at }}", &row.expires_at.to_string());

    Ok(Html(html))
}

async fn download_file(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let row: ShareRow = sqlx::query_as("SELECT * FROM shares WHERE token = ?")
        .bind(&token)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?
        .ok_or(AppError::NotFound)?;

    let path = PathBuf::from(UPLOAD_DIR).join(&token);

    if !path.exists() {
        return Err(AppError::NotFound);
    }

    let file = File::open(path).await.map_err(AppError::Io)?;
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let headers = [
        (header::CONTENT_TYPE, row.content_type),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", row.filename),
        ),
    ];

    Ok((headers, body))
}

// --- HELPERS ---

fn render_upload_page(error: Option<&str>) -> Html<String> {
    let error_html = if let Some(err) = error {
        format!(
            r#"<p style="color:#ef4444;margin-top:10px;font-size:14px;">{}</p>"#,
            err
        )
    } else {
        String::new()
    };

    let html = HTML_UPLOAD
        .replace("{{ max_size }}", &format_bytes(MAX_UPLOAD_SIZE as u64))
        .replace("{{ ttl }}", &(DEFAULT_TTL_SECS / 3600).to_string())
        .replace("{{ error_html }}", &error_html);

    Html(html)
}

async fn cleanup_expired(pool: &Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let rows: Vec<ShareRow> = sqlx::query_as("SELECT * FROM shares WHERE expires_at < ?")
        .bind(now)
        .fetch_all(pool)
        .await?;

    for row in &rows {
        let path = PathBuf::from(UPLOAD_DIR).join(&row.token);
        if path.exists() {
            let _ = fs::remove_file(path).await;
        }
    }

    if !rows.is_empty() {
        sqlx::query("DELETE FROM shares WHERE expires_at < ?")
            .bind(now)
            .execute(pool)
            .await?;
        println!("Cleaned up {} expired files", rows.len());
    }

    Ok(())
}

fn format_bytes(b: u64) -> String {
    const UNIT: u64 = 1024;
    if b < UNIT {
        return format!("{} B", b);
    }
    let div = UNIT.pow(1);
    if b < UNIT.pow(2) {
        return format!("{:.2} KB", b as f64 / div as f64);
    }
    let div = UNIT.pow(2);
    if b < UNIT.pow(3) {
        return format!("{:.2} MB", b as f64 / div as f64);
    }
    let div = UNIT.pow(3);
    format!("{:.2} GB", b as f64 / div as f64)
}

#[derive(FromRow)]
struct ShareRow {
    token: String,
    filename: String,
    content_type: String,
    size: i64,
    created_at: i64,
    expires_at: i64,
}

enum AppError {
    Io(std::io::Error),
    Db(sqlx::Error),
    BadRequest,
    NotFound,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Io(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("IO Error: {}", e),
            ),
            AppError::Db(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database Error: {}", e),
            ),
            AppError::BadRequest => (StatusCode::BAD_REQUEST, "Bad Request".to_string()),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "File not found or expired".to_string(),
            ),
        };
        (status, msg).into_response()
    }
}

