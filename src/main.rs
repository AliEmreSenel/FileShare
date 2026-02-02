use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, State},
    http::{header, HeaderMap, StatusCode}, // Added HeaderMap
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    XChaCha20, XNonce,
};
use rand::{distr::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, Pool, Sqlite};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
};

// --- CONFIG ---
const UPLOAD_DIR: &str = "data/files";
const DB_URL: &str = "sqlite://data/db.sqlite?mode=rwc";
const MAX_SIZE: usize = 100 * 1024 * 1024; // 100 MB

// Import the separate HTML files at compile time
const HTML_UPLOAD: &str = include_str!("../templates/upload.html");
const HTML_FILE: &str = include_str!("../templates/file.html");

#[derive(Clone)]
struct AppState {
    pool: Pool<Sqlite>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(UPLOAD_DIR).await.map_err(|e| {
        eprintln!(
            "CRITICAL: Failed to create upload dir '{}': {}",
            UPLOAD_DIR, e
        );
        e
    })?;

    // 2. Connect to DB (creates file if missing due to mode=rwc)
    let pool = SqlitePoolOptions::new()
        .connect(DB_URL)
        .await
        .map_err(|e| {
            eprintln!(
                "CRITICAL: Failed to connect/create DB at '{}': {}",
                DB_URL, e
            );
            e
        })?;

    let pool = SqlitePoolOptions::new().connect(DB_URL).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS shares (
        token TEXT PRIMARY KEY, filename TEXT NOT NULL, size INTEGER, 
        created_at INTEGER, expires_at INTEGER, ip TEXT
    )",
    )
    .execute(&pool)
    .await?;

    // Note: We still need ConnectInfo for the fallback IP
    let app = Router::new()
        .route("/", get(show_upload))
        .route("/u", post(handle_upload))
        .route("/f/{token}", get(show_file))
        .route("/d/{token}", get(download_file))
        .layer(DefaultBodyLimit::max(MAX_SIZE))
        .with_state(Arc::new(AppState { pool }));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Listening on http://0.0.0.0:8080");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn gen_nonce() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

// --- HELPER: Extract Real IP ---
fn get_real_ip(headers: &HeaderMap, addr: SocketAddr) -> String {
    if let Some(val) = headers.get("x-forwarded-for") {
        if let Ok(s) = val.to_str() {
            // X-Forwarded-For can be "client, proxy1, proxy2". We want the first one.
            if let Some(first) = s.split(',').next() {
                return first.trim().to_string();
            }
        }
    }
    // Fallback to the direct connection IP (Docker gateway) if header is missing
    addr.ip().to_string()
}

async fn show_upload() -> Html<String> {
    let nonce = gen_nonce();
    Html(HTML_UPLOAD.replace("{{nonce}}", &nonce))
}

async fn handle_upload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap, // Extract headers to look for X-Forwarded-For
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let mut ttl_days = 1;

    // Resolve IP immediately
    let user_ip = get_real_ip(&headers, addr);

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");

        if name == "ttl" {
            if let Ok(txt) = field.text().await {
                if let Ok(d) = txt.parse::<u64>() {
                    if [1, 2, 5, 7, 14, 30, 60, 90, 365].contains(&d) {
                        ttl_days = d;
                    }
                }
            }
        } else if name == "file" {
            let filename = field.file_name().unwrap_or("unknown").to_string();

            let token: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            let key = Sha256::digest(token.as_bytes());
            let mut nonce = [0u8; 24];
            rand::rng().fill(&mut nonce);
            let mut cipher = XChaCha20::new(&key, XNonce::from_slice(&nonce));

            let path = PathBuf::from(UPLOAD_DIR).join(&token);
            let mut file = File::create(&path).await.map_err(AppError::Io)?;
            file.write_all(&nonce).await.map_err(AppError::Io)?;

            let mut size = 0;
            while let Ok(Some(chunk)) = field.chunk().await {
                if size + chunk.len() > MAX_SIZE {
                    let _ = fs::remove_file(path).await;
                    return Err(AppError::BadRequest);
                }
                let mut buf = chunk.to_vec();
                cipher.apply_keystream(&mut buf);
                file.write_all(&buf).await.map_err(AppError::Io)?;
                size += chunk.len();
            }
            if size == 0 {
                let _ = fs::remove_file(path).await;
                return Err(AppError::BadRequest);
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            sqlx::query("INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?)")
                .bind(&token)
                .bind(&filename)
                .bind(size as i64)
                .bind(now)
                .bind(now + (ttl_days * 86400) as i64)
                .bind(&user_ip) // Save the real IP
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
    Err(AppError::BadRequest)
}

async fn show_file(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Result<Html<String>, AppError> {
    let row: ShareRow = sqlx::query_as("SELECT * FROM shares WHERE token = ?")
        .bind(&token)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?
        .ok_or(AppError::NotFound)?;

    if SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        > row.expires_at
    {
        return Err(AppError::NotFound);
    }

    let nonce = gen_nonce();
    let html = HTML_FILE
        .replace("{{nonce}}", &nonce)
        .replace("{{filename}}", &row.filename)
        .replace("{{token}}", &row.token)
        .replace("{{size}}", &row.size.to_string())
        .replace("{{expires}}", &row.expires_at.to_string());

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

    if SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        > row.expires_at
    {
        return Err(AppError::NotFound);
    }

    let path = PathBuf::from(UPLOAD_DIR).join(&token);
    let mut file = File::open(path).await.map_err(|_| AppError::NotFound)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).await.map_err(AppError::Io)?;

    if data.len() < 24 {
        return Err(AppError::EncryptionError);
    }
    let (nonce, ciphertext) = data.split_at_mut(24);

    let key = Sha256::digest(token.as_bytes());
    let mut cipher = XChaCha20::new(&key, XNonce::from_slice(nonce));
    cipher.apply_keystream(ciphertext);

    let headers = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", row.filename),
        ),
    ];
    Ok((headers, Body::from(ciphertext.to_vec())))
}

#[derive(FromRow)]
struct ShareRow {
    token: String,
    filename: String,
    size: i64,
    created_at: i64,
    expires_at: i64,
}

enum AppError {
    Io(std::io::Error),
    Db(sqlx::Error),
    BadRequest,
    NotFound,
    EncryptionError,
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Io(e) => {
                // PRINT THE ERROR so you can see it in docker logs
                eprintln!(">> IO ERROR: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Server Error")
            }
            AppError::Db(e) => {
                // PRINT THE ERROR
                eprintln!(">> DB ERROR: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Server Error")
            }
            AppError::EncryptionError => {
                eprintln!(">> Encryption Error: File too short or corrupted");
                (StatusCode::INTERNAL_SERVER_ERROR, "Server Error")
            }
            AppError::BadRequest => (StatusCode::BAD_REQUEST, "Bad Request"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found"),
        };
        (status, msg.to_string()).into_response()
    }
}

