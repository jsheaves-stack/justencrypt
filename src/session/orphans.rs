use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use rocket::tokio::{self, task};
use uuid::Uuid;

use crate::{
    enums::db_error::DbError,
    session::user_session::UserSession,
    util::sharded_path::{is_not_found, remove_sharded_path},
};

/// Removes stored files that no database row refers to: blobs whose file row
/// is gone, thumbnails of such blobs, and `.part` files of uploads that no
/// longer exist. They are left behind by crashes or by failed deletes.
///
/// Scanning needs the user's database, which can only be opened while the
/// user is logged in, so it runs in the background after every login. It is
/// off unless `JUSTENCRYPT_ORPHAN_SCAN_ENABLED` is true.
pub struct OrphanScanner {
    enabled: bool,
}

impl OrphanScanner {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Starts a scan of `session`'s user in the background, if scanning is
    /// enabled.
    pub fn scan_in_background(&self, session: Arc<UserSession>) {
        if !self.enabled {
            return;
        }

        tokio::spawn(async move {
            match remove_orphaned_files(&session).await {
                Ok(0) => trace!("Orphan scan for {} found nothing", session.username),
                Ok(removed) => info!(
                    "Orphan scan for {} removed {} file(s)",
                    session.username, removed
                ),

                Err(e) => error!("Orphan scan for {} failed: {}", session.username, e),
            }
        });
    }
}

#[derive(PartialEq)]
enum StoredKind {
    Blob,
    Partial,
    Thumbnail,
    /// A thumbnail cache file still being written. One that is still around
    /// when the scan runs was left behind by a crash; one that is genuinely
    /// in progress only costs that request its cache write.
    PartialThumbnail,
}

/// Deletes the user's unreferenced files and returns how many were removed.
/// Only files named like the server names them (a UUID, optionally with
/// `.part`) inside the user's sub-directories are considered; the user's
/// database files and anything else are never touched.
pub async fn remove_orphaned_files(session: &UserSession) -> Result<usize, DbError> {
    let user_path = session.get_user_path();

    // The disk is listed before the database is read, and that order is what
    // makes the scan safe while uploads are running: every upload records its
    // row before it creates its file, and a finished upload records its file
    // row before dropping its upload row. So any file seen here is still
    // referenced by some row when the database is read below, unless it really
    // is an orphan. Reading the database first would let an upload that starts
    // in between lose its new `.part` file.
    let candidates = {
        let user_path = user_path.clone();

        task::spawn_blocking(move || find_stored_files(&user_path))
            .await
            .map_err(|e| DbError::ThreadJoinError(e.to_string()))?
    };

    let (files, uploads) = session.referenced_blob_names().await?;

    let mut removed = 0;

    for (path, name, kind) in candidates {
        let referenced = match kind {
            StoredKind::Blob => files.contains(&name) || uploads.contains(&name),
            StoredKind::Partial => uploads.contains(&name),
            StoredKind::Thumbnail => files.contains(&name),
            StoredKind::PartialThumbnail => false,
        };

        if referenced {
            continue;
        }

        match remove_sharded_path(&user_path, &path).await {
            Ok(()) => removed += 1,
            Err(e) if is_not_found(e.as_ref()) => {},

            Err(e) => warn!("Failed to remove orphaned file {:?}: {}", path, e),
        }
    }

    Ok(removed)
}

// Every server-named file under the user's sub-directories.
fn find_stored_files(user_path: &Path) -> Vec<(PathBuf, String, StoredKind)> {
    let cache_path = user_path.join(".cache");
    let mut found = Vec::new();

    let mut dirs: Vec<PathBuf> = match fs::read_dir(user_path) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect(),
        Err(e) => {
            warn!("Orphan scan could not read {:?}: {}", user_path, e);

            return found;
        },
    };

    while let Some(dir) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();

            if path.is_dir() {
                dirs.push(path);

                continue;
            }

            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            let (name, is_partial) = match file_name.strip_suffix(".part") {
                Some(base) => (base, true),
                None => (file_name, false),
            };

            if Uuid::parse_str(name).is_err() {
                continue;
            }

            let kind = match (path.starts_with(&cache_path), is_partial) {
                (true, true) => StoredKind::PartialThumbnail,
                (true, false) => StoredKind::Thumbnail,
                (false, true) => StoredKind::Partial,
                (false, false) => StoredKind::Blob,
            };

            found.push((path.clone(), name.to_string(), kind));
        }
    }

    found
}
