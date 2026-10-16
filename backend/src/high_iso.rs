//! Private, streamed ISO staging for agent-managed High VM installs.

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::{StreamExt, stream};
use hf_core::{HighImageArchitecture, HighImageFormat, HighImageSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::SystemTime};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use uuid::Uuid;

use crate::{api::AppState, auth::Principal, errors::AppError};

const MAX_ISO_UPLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Serialize)]
pub struct UploadResponse {
    pub image_source: HighImageSource,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArtifactMetadata {
    owner_id: Uuid,
    token_sha256: String,
    image_sha256: String,
    size_bytes: u64,
    uploaded_at_unix: u64,
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    token: String,
}

/// Uploads a user-selected ISO without buffering it in application memory.
/// The one-time-looking bearer URL is returned to the owner and stored with the trap config;
/// only an agent holding that URL can retrieve the staged bytes.
pub async fn upload(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<UploadResponse>, AppError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.starts_with("application/octet-stream"))
    {
        return Err(AppError::invalid(
            "ISO upload must use application/octet-stream",
        ));
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|size| size == 0 || size > MAX_ISO_UPLOAD_BYTES)
    {
        return Err(AppError::invalid(
            "ISO file must be between 1 byte and 8 GiB",
        ));
    }

    let directory = storage_dir(&state);
    fs::create_dir_all(&directory)
        .await
        .map_err(|_| AppError::internal())?;
    #[cfg(unix)]
    fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .await
    .map_err(|_| AppError::internal())?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut owner_usage = 0_u64;
    let mut entries = fs::read_dir(&directory)
        .await
        .map_err(|_| AppError::internal())?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|_| AppError::internal())?
    {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path).await else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<ArtifactMetadata>(&bytes) else {
            continue;
        };
        if now.saturating_sub(metadata.uploaded_at_unix) > 30 * 24 * 60 * 60 {
            let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Ok(artifact_id) = Uuid::parse_str(stem) else {
                continue;
            };
            let source_pattern = format!("%/api/v1/high-iso/{artifact_id}?token=%");
            let referenced: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM traps WHERE user_id=$1 AND effective_config #>> '{image_source,url}' LIKE $2)",
            )
            .bind(metadata.owner_id)
            .bind(source_pattern)
            .fetch_one(state.pool()?)
            .await?;
            if !referenced {
                let _ = fs::remove_file(directory.join(format!("{stem}.iso"))).await;
                let _ = fs::remove_file(path).await;
            } else if metadata.owner_id == principal.user.id {
                owner_usage = owner_usage.saturating_add(metadata.size_bytes);
            }
        } else if metadata.owner_id == principal.user.id {
            owner_usage = owner_usage.saturating_add(metadata.size_bytes);
        }
    }
    if owner_usage >= 16 * 1024 * 1024 * 1024 {
        return Err(AppError::conflict(
            "Custom ISO storage limit is 16 GiB per account; remove an old High trap or wait for expired uploads to be cleaned",
        ));
    }

    let artifact_id = Uuid::new_v4();
    let token = Uuid::new_v4().simple().to_string();
    let temp_path = directory.join(format!("{artifact_id}.upload"));
    let image_path = directory.join(format!("{artifact_id}.iso"));
    let metadata_path = directory.join(format!("{artifact_id}.json"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .await
        .map_err(|_| AppError::internal())?;
    let mut stream = body.into_data_stream();
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                let _ = fs::remove_file(&temp_path).await;
                return Err(AppError::invalid("ISO upload was interrupted"));
            }
        };
        size = size.saturating_add(chunk.len() as u64);
        if size > MAX_ISO_UPLOAD_BYTES || owner_usage.saturating_add(size) > 16 * 1024 * 1024 * 1024
        {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::invalid(
                "ISO exceeds the 8 GiB file limit or 16 GiB account storage quota",
            ));
        }
        digest.update(&chunk);
        if file.write_all(&chunk).await.is_err() {
            let _ = fs::remove_file(&temp_path).await;
            return Err(AppError::internal());
        }
    }
    if size == 0 || file.sync_all().await.is_err() {
        let _ = fs::remove_file(&temp_path).await;
        return Err(AppError::invalid("ISO file is empty or could not be saved"));
    }
    drop(file);
    fs::rename(&temp_path, &image_path)
        .await
        .map_err(|_| AppError::internal())?;

    let image_sha256 = hex_digest(digest.finalize().as_slice());
    let metadata = ArtifactMetadata {
        owner_id: principal.user.id,
        token_sha256: hex_digest(Sha256::digest(token.as_bytes()).as_slice()),
        image_sha256: image_sha256.clone(),
        size_bytes: size,
        uploaded_at_unix: now,
    };
    let metadata_tmp = directory.join(format!("{artifact_id}.json.upload"));
    let metadata_bytes = serde_json::to_vec(&metadata).map_err(|_| AppError::internal())?;
    if fs::write(&metadata_tmp, metadata_bytes).await.is_err()
        || fs::rename(&metadata_tmp, &metadata_path).await.is_err()
    {
        let _ = fs::remove_file(&image_path).await;
        let _ = fs::remove_file(&metadata_tmp).await;
        return Err(AppError::internal());
    }

    let url = format!(
        "{}/api/v1/high-iso/{artifact_id}?token={token}",
        state.config.app_origin.trim_end_matches('/')
    );
    Ok(Json(UploadResponse {
        image_source: HighImageSource {
            url,
            sha256: image_sha256,
            format: HighImageFormat::Iso,
            architecture: HighImageArchitecture::X86_64,
        },
        size_bytes: size,
    }))
}

/// Serves an uploaded ISO to the agent using its unguessable, read-only URL.
/// Range support lets the agent resume multi-gigabyte downloads after a reconnect.
pub async fn download(
    State(state): State<AppState>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<DownloadQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if query.token.len() != 32 || !query.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::not_found());
    }
    let directory = storage_dir(&state);
    let metadata_path = directory.join(format!("{artifact_id}.json"));
    let image_path = directory.join(format!("{artifact_id}.iso"));
    let metadata: ArtifactMetadata = serde_json::from_slice(
        &fs::read(&metadata_path)
            .await
            .map_err(|_| AppError::not_found())?,
    )
    .map_err(|_| AppError::not_found())?;
    let presented = hex_digest(Sha256::digest(query.token.as_bytes()).as_slice());
    if !constant_time_equal(&presented, &metadata.token_sha256) {
        return Err(AppError::not_found());
    }
    let disk_metadata = fs::symlink_metadata(&image_path)
        .await
        .map_err(|_| AppError::not_found())?;
    if !disk_metadata.is_file() || disk_metadata.len() != metadata.size_bytes {
        return Err(AppError::not_found());
    }

    let etag = format!("\"{}\"", metadata.image_sha256);
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .filter(|_| {
            headers
                .get(header::IF_RANGE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| value == etag)
        })
        .and_then(|value| parse_range(value, metadata.size_bytes));
    let (status, offset, length, content_range) = match range {
        Some((start, end)) => (
            StatusCode::PARTIAL_CONTENT,
            start,
            end - start + 1,
            Some(format!("bytes {start}-{end}/{}", metadata.size_bytes)),
        ),
        None => (StatusCode::OK, 0, metadata.size_bytes, None),
    };
    let mut file = fs::File::open(&image_path)
        .await
        .map_err(|_| AppError::not_found())?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|_| AppError::internal())?;
    let body_stream = stream::try_unfold((file, length), |(mut file, remaining)| async move {
        if remaining == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        let mut buffer = vec![0_u8; remaining.min(128 * 1024) as usize];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some((Bytes::from(buffer), (file, remaining - read as u64))))
    });
    let mut response = Body::from_stream(body_stream).into_response();
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string()).map_err(|_| AppError::internal())?,
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|_| AppError::internal())?,
    );
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(content_range) = content_range {
        response.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&content_range).map_err(|_| AppError::internal())?,
        );
    }
    Ok(response)
}

fn storage_dir(state: &AppState) -> PathBuf {
    PathBuf::from(&state.config.high_iso_storage_dir)
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let (unit, value) = value.split_once('=')?;
    if unit != "bytes" || value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        size.checked_sub(1)?
    } else {
        end.parse::<u64>().ok()?.min(size.checked_sub(1)?)
    };
    (start <= end && start < size).then_some((start, end))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Drop an uploaded source after its trap registration is removed, unless another owned trap
/// still references the same immutable source URL.
pub async fn remove_unreferenced_for_trap(
    state: &AppState,
    principal: &Principal,
    trap: &crate::resources::Trap,
) {
    let Some(source_url) = trap
        .effective_config
        .get("image_source")
        .and_then(|source| source.get("url"))
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    let Ok(url) = url::Url::parse(source_url) else {
        return;
    };
    let Some(artifact_id) = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|segment| Uuid::parse_str(segment).ok())
    else {
        return;
    };
    let Some(token) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
    else {
        return;
    };
    let source_pattern = format!("%/api/v1/high-iso/{artifact_id}?token=%");
    let referenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM traps WHERE user_id=$1 AND effective_config #>> '{image_source,url}' LIKE $2)",
    )
    .bind(principal.user.id)
    .bind(source_pattern)
    .fetch_one(match state.pool() {
        Ok(pool) => pool,
        Err(_) => return,
    })
    .await
    .unwrap_or(true);
    if referenced {
        return;
    }
    let directory = storage_dir(state);
    let metadata_path = directory.join(format!("{artifact_id}.json"));
    let image_path = directory.join(format!("{artifact_id}.iso"));
    let Ok(bytes) = fs::read(&metadata_path).await else {
        return;
    };
    let Ok(metadata) = serde_json::from_slice::<ArtifactMetadata>(&bytes) else {
        return;
    };
    let presented = hex_digest(Sha256::digest(token.as_bytes()).as_slice());
    if metadata.owner_id != principal.user.id
        || !constant_time_equal(&presented, &metadata.token_sha256)
    {
        return;
    }
    let _ = fs::remove_file(image_path).await;
    let _ = fs::remove_file(metadata_path).await;
}
