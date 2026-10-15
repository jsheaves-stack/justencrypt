//! A user's encrypted files on disk. Every file operation runs on one of the
//! user's blocking threads through their [`UserContext`], so file access counts
//! against the user's limits just as database work does.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use uuid::Uuid;

use crate::{
    enums::blocking_error::BlockingError, storage::user_context::UserContext,
    util::sharded_path::sharded_path,
};

/// The directory, inside the user's, that holds their cached thumbnails.
const THUMBNAIL_DIR: &str = ".cache";

/// One of a user's encrypted files, open for reading and writing. Clones
/// share the open file. Reads and writes give a position, so several can run
/// at once.
#[derive(Clone)]
pub struct BlobFile {
    file: Arc<File>,
    context: UserContext,
}

/// What a file found in the user's storage is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoredKind {
    Blob,
    /// An upload's partial file.
    Partial,
    Thumbnail,
    /// A thumbnail cache file still being written. One that is still around
    /// when the orphan scan runs was left behind by a crash; one that is
    /// genuinely in progress only costs that request its cache write.
    PartialThumbnail,
}

/// A server-named file found in the user's storage by
/// [`UserContext::list_stored_files`]. `name` is the encoded name it belongs
/// to; a partial thumbnail's is its own.
pub struct StoredFile {
    path: PathBuf,
    pub name: String,
    pub kind: StoredKind,
}

/// A thumbnail being written to a temporary file next to its place in the
/// cache. Committing renames it into place in one step, so the cache only ever
/// holds complete thumbnails, even with several writers at once (the last one
/// wins).
pub struct ThumbnailTemp {
    file: BlobFile,
    temp_path: PathBuf,
    final_path: PathBuf,
}

impl UserContext {
    /// Where the encrypted file `name` is stored.
    pub fn blob_path(&self, name: &str) -> PathBuf {
        sharded_path(self.user_path().to_path_buf(), name)
    }

    /// Where the cached thumbnail of the encrypted file `name` is stored.
    pub fn thumbnail_path(&self, name: &str) -> PathBuf {
        sharded_path(self.user_path().join(THUMBNAIL_DIR), name)
    }

    /// Where an upload of `name` is written until it is committed.
    pub fn upload_part_path(&self, name: &str) -> PathBuf {
        self.blob_path(name).with_extension("part")
    }

    /// Opens the encrypted file `name`.
    pub async fn open_blob(&self, name: &str) -> io::Result<BlobFile> {
        self.open(self.blob_path(name)).await
    }

    /// Opens the cached thumbnail of the encrypted file `name`.
    pub async fn open_thumbnail(&self, name: &str) -> io::Result<BlobFile> {
        self.open(self.thumbnail_path(name)).await
    }

    /// Opens the encrypted file `name` for work already running on one of the
    /// user's blocking threads. It doesn't take another turn: one task
    /// waiting for a second while holding the first could leave the user
    /// with every turn taken and none ever freed.
    pub fn open_blob_on_this_thread(&self, name: &str) -> io::Result<File> {
        File::open(self.blob_path(name))
    }

    /// Creates, or empties, the partial file an upload of `name` is written to.
    pub async fn create_upload(&self, name: &str) -> io::Result<BlobFile> {
        self.create(self.upload_part_path(name)).await
    }

    /// Renames a finished upload of `name` into place. Follow it with
    /// [`sync_blob_dir`](Self::sync_blob_dir) to make the rename durable.
    pub async fn commit_upload(&self, name: &str) -> io::Result<()> {
        let part_path = self.upload_part_path(name);
        let final_path = self.blob_path(name);

        self.run_blocking(move || fs::rename(part_path, final_path))
            .await?
    }

    /// Waits until the directory holding the encrypted file `name` is on
    /// disk, which makes a rename or creation inside it survive a crash or
    /// power loss.
    pub async fn sync_blob_dir(&self, name: &str) -> io::Result<()> {
        let path = self.blob_path(name);

        self.run_blocking(move || sync_parent_dir(&path)).await?
    }

    /// Starts writing the thumbnail of the encrypted file `name`, to a new
    /// temporary file.
    pub async fn create_thumbnail_temp(&self, name: &str) -> io::Result<ThumbnailTemp> {
        let final_path = self.thumbnail_path(name);
        let temp_path = final_path.with_file_name(format!("{}.part", Uuid::new_v4()));
        let file = self.create(temp_path.clone()).await?;

        Ok(ThumbnailTemp {
            file,
            temp_path,
            final_path,
        })
    }

    /// Deletes the encrypted file `name`, and any directories that left empty.
    pub async fn remove_blob(&self, name: &str) -> io::Result<()> {
        self.remove(self.blob_path(name)).await
    }

    /// Deletes the partial file of an upload of `name`.
    pub async fn remove_upload_part(&self, name: &str) -> io::Result<()> {
        self.remove(self.upload_part_path(name)).await
    }

    /// Deletes the cached thumbnail of the encrypted file `name`.
    pub async fn remove_thumbnail(&self, name: &str) -> io::Result<()> {
        self.remove(self.thumbnail_path(name)).await
    }

    /// Deletes the encrypted file `name`, which no database row refers to any
    /// more, together with its cached thumbnail. Failures are only logged: the
    /// row is already gone, so as far as the user is concerned the file is too.
    pub async fn remove_blob_and_thumbnail(&self, name: &str) {
        match self.remove_blob(name).await {
            Ok(()) => {},
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                warn!("Blob {} was already missing from disk", name);
            },
            Err(e) => error!("Failed to delete blob {}: {}", name, e),
        }

        // Most files have no thumbnail, so a missing one is expected.

        if let Err(e) = self.remove_thumbnail(name).await {
            if e.kind() != io::ErrorKind::NotFound {
                warn!("Failed to delete thumbnail for {}: {}", name, e);
            }
        }
    }

    /// Every server-named file in the user's storage: named by a UUID,
    /// optionally with `.part`, inside the user's sub-directories. The user's
    /// database files and anything else are never listed.
    pub async fn list_stored_files(&self) -> Result<Vec<StoredFile>, BlockingError> {
        let user_path = self.user_path().to_path_buf();

        self.run_blocking(move || find_stored_files(&user_path))
            .await
    }

    /// Deletes a file [`list_stored_files`](Self::list_stored_files) found.
    pub async fn remove_stored_file(&self, file: &StoredFile) -> io::Result<()> {
        self.remove(file.path.clone()).await
    }

    /// Deletes the file at `path`, then any directories that left empty, up
    /// to the user's own.
    async fn remove(&self, path: PathBuf) -> io::Result<()> {
        let user_path = self.user_path().to_path_buf();

        self.run_blocking(move || remove_and_prune(&user_path, &path))
            .await?
    }

    /// Opens the file at `path`, on one of the user's blocking threads.
    async fn open(&self, path: PathBuf) -> io::Result<BlobFile> {
        let file = self.run_blocking(move || File::open(path)).await??;

        Ok(self.blob_file(file))
    }

    /// Creates, or empties, the file at `path`, and any missing directories.
    async fn create(&self, path: PathBuf) -> io::Result<BlobFile> {
        let file = self
            .run_blocking(move || {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }

                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
            })
            .await??;

        Ok(self.blob_file(file))
    }

    /// Wraps an open file so its operations run on the user's blocking threads.
    fn blob_file(&self, file: File) -> BlobFile {
        BlobFile {
            file: Arc::new(file),
            context: self.clone(),
        }
    }
}

impl BlobFile {
    /// Reads into `buf` from `position` until `buf` is full or the file ends,
    /// and gives `buf` back with the number of bytes read.
    pub async fn read_at(&self, mut buf: Vec<u8>, position: u64) -> io::Result<(Vec<u8>, usize)> {
        self.run(move |file| {
            let mut filled = 0;

            while filled < buf.len() {
                match read_once_at(file, &mut buf[filled..], position + filled as u64) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            Ok((buf, filled))
        })
        .await
    }

    /// Writes all of `bytes` at `position`.
    pub async fn write_at(&self, bytes: Vec<u8>, position: u64) -> io::Result<()> {
        self.run(move |file| write_all_at(file, &bytes, position))
            .await
    }

    /// Truncates or extends the file to `len` bytes.
    pub async fn set_len(&self, len: u64) -> io::Result<()> {
        self.run(move |file| file.set_len(len)).await
    }

    /// Waits until everything written is on disk.
    pub async fn sync(&self) -> io::Result<()> {
        self.run(|file| file.sync_all()).await
    }

    /// Runs `f` on the open file, on one of the user's blocking threads.
    async fn run<F, R>(&self, f: F) -> io::Result<R>
    where
        F: FnOnce(&File) -> io::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let file = self.file.clone();

        self.context.run_blocking(move || f(&file)).await?
    }
}

impl ThumbnailTemp {
    /// The temporary file, to write the thumbnail into.
    pub fn file(&self) -> &BlobFile {
        &self.file
    }

    /// Renames the thumbnail into place, and waits until the rename is on disk.
    pub async fn commit(&self) -> io::Result<()> {
        let temp_path = self.temp_path.clone();
        let final_path = self.final_path.clone();

        self.file
            .context
            .run_blocking(move || {
                fs::rename(&temp_path, &final_path)?;

                sync_parent_dir(&final_path)
            })
            .await?
    }

    /// Removes the temporary file, if it is still there.
    pub async fn discard(self) {
        let temp_path = self.temp_path;
        let _ = self
            .file
            .context
            .run_blocking(move || fs::remove_file(temp_path))
            .await;
    }
}

/// Reads once into `buf` from `position`, giving the number of bytes read; 0
/// means the file ends there.
#[cfg(unix)]
fn read_once_at(file: &File, buf: &mut [u8], position: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, position)
}

/// Reads once into `buf` from `position`, giving the number of bytes read; 0
/// means the file ends there. This moves the file's cursor, which nothing
/// here uses.
#[cfg(windows)]
fn read_once_at(file: &File, buf: &mut [u8], position: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, position)
}

/// Writes all of `bytes` at `position`.
#[cfg(unix)]
fn write_all_at(file: &File, bytes: &[u8], position: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, bytes, position)
}

/// Writes all of `bytes` at `position`. This moves the file's cursor, which
/// nothing here uses.
#[cfg(windows)]
fn write_all_at(file: &File, mut bytes: &[u8], mut position: u64) -> io::Result<()> {
    while !bytes.is_empty() {
        match std::os::windows::fs::FileExt::seek_write(file, bytes, position) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                bytes = &bytes[n..];
                position += n as u64;
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Waits until the directory containing `path` is on disk.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) => File::open(dir)?.sync_all(),
        None => Ok(()),
    }
}

/// Does nothing: Windows can't open a directory as a file to sync it, and
/// NTFS journals renames and creations itself.
#[cfg(windows)]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Deletes the file at `path`, then each parent directory that is left empty,
/// stopping at `user_path`. Runs on a blocking thread.
fn remove_and_prune(user_path: &Path, path: &Path) -> io::Result<()> {
    fs::remove_file(path)?;

    let mut current = path.parent();

    while let Some(dir) = current {
        if dir == user_path || !dir.starts_with(user_path) {
            break;
        }

        if fs::read_dir(dir)?.next().is_some() {
            break;
        }

        fs::remove_dir(dir)?;
        current = dir.parent();
    }

    Ok(())
}

/// Walks the user's directories and lists every server-named file in them.
/// A directory that can't be read is skipped. Runs on a blocking thread.
fn find_stored_files(user_path: &Path) -> Vec<StoredFile> {
    let cache_path = user_path.join(THUMBNAIL_DIR);
    let mut found = Vec::new();

    let mut dirs: Vec<PathBuf> = match fs::read_dir(user_path) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect(),
        Err(e) => {
            warn!("Could not list the files in {:?}: {}", user_path, e);

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

            found.push(StoredFile {
                name: name.to_string(),
                path,
                kind,
            });
        }
    }

    found
}
