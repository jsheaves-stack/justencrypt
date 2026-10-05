use std::{io, sync::Arc};

use rocket::tokio;

use crate::{
    enums::db_error::DbError,
    session::{user_session::UserSession, user_storage::StoredKind},
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
    /// A scanner that scans at login only when `enabled`.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether scans run at login.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Starts a scan of `session`'s user in the background, if scanning is
    /// enabled and no scan of theirs is already running.
    pub fn scan_in_background(&self, session: Arc<UserSession>) {
        if !self.enabled {
            return;
        }

        let Some(claim) = session.context.try_claim_orphan_scan() else {
            debug!("An orphan scan for {} is already running", session.username);

            return;
        };

        tokio::spawn(async move {
            let _claim = claim;

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

/// Deletes the user's unreferenced files and returns how many were removed.
/// Only files the server named are considered (see
/// [`UserContext::list_stored_files`](crate::session::user_context::UserContext::list_stored_files));
/// the user's database files and anything else are never touched.
pub async fn remove_orphaned_files(session: &UserSession) -> Result<usize, DbError> {
    let context = &session.context;

    // The disk is listed before the database is read, and that order is what
    // makes the scan safe while uploads are running: every upload records its
    // row before it creates its file, and a finished upload records its file
    // row before dropping its upload row. So any file seen here is still
    // referenced by some row when the database is read below, unless it really
    // is an orphan. Reading the database first would let an upload that starts
    // in between lose its new `.part` file.
    let candidates = context.list_stored_files().await?;

    let (files, uploads) = session.referenced_blob_names().await?;

    let mut removed = 0;

    for file in candidates {
        let referenced = match file.kind {
            StoredKind::Blob => files.contains(&file.name) || uploads.contains(&file.name),
            StoredKind::Partial => uploads.contains(&file.name),
            StoredKind::Thumbnail => files.contains(&file.name),
            StoredKind::PartialThumbnail => false,
        };

        if referenced {
            continue;
        }

        match context.remove_stored_file(&file).await {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},

            Err(e) => warn!(
                "Failed to remove orphaned {:?} file {}: {}",
                file.kind, file.name, e
            ),
        }
    }

    Ok(removed)
}
