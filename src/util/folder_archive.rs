//! Streams a folder, with everything below it, as a TAR archive.
//!
//! The archive is built on a blocking thread while the client downloads it.
//! It is never held in memory: the thread writes into a bounded channel and
//! waits whenever the client falls behind. The archive's exact length is
//! worked out before the first byte is sent, so the response can carry a
//! `Content-Length` and a client can tell a download that broke off from a
//! complete one.

use std::{
    io::{self, Read, Write},
    mem,
    time::Duration,
};

use rocket::tokio::{
    runtime::Handle,
    sync::{mpsc, oneshot},
    time,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::{
    db::sqlite::{self, ArchiveEntry},
    encryption::{
        sync_chunk_decryptor::SyncChunkDecryptReader, FileEncryptionMetadata, CHUNK_SIZE,
    },
    enums::{archive_error::ArchiveError, db_error::DbError},
    session::user_context::UserContext,
    util::{
        names::is_valid_relative_path,
        tar::{self, EntryKind},
    },
};

/// An archive being streamed: its bytes arrive on `rx`, and come to exactly
/// `len` bytes unless the archive fails part-way.
pub struct FolderArchive {
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub len: u64,
    pub file_name: String,
}

/// Where [`produce`] reports, before it streams anything, the archive's
/// length and file name, or why there is no archive.
type ArchiveReady = oneshot::Sender<Result<(u64, String), DbError>>;

/// What an archive holds: the folder, the directory its entries go under,
/// and the archive's total length.
struct ArchivePlan {
    folder_id: i32,
    root: String,
    len: u64,
}

/// Builds the archive of `folder_path` and writes it to `out`. It runs on one
/// of the user's blocking threads, from `context`, and returns when the
/// archive is finished, has failed, or the client has gone away or stopped
/// reading.
pub fn produce(
    context: &UserContext,
    folder_path: &str,
    username: &str,
    ready: ArchiveReady,
    mut out: ChannelWriter,
) {
    let mut db = match context.pool().get() {
        Ok(db) => db,
        Err(e) => {
            let _ = ready.send(Err(e.into()));

            return;
        },
    };

    let (snapshot, plan) = match start_archive(&mut db, folder_path, username) {
        Ok(started) => started,
        Err(e) => {
            let _ = ready.send(Err(e));

            return;
        },
    };

    let file_name = format!("{}.tar", plan.root.trim_end_matches('/'));

    // The request is gone if nobody is waiting for the length.

    if ready.send(Ok((plan.len, file_name))).is_err() {
        return;
    }

    match write_archive(&snapshot, &plan, context, &mut out) {
        Ok(()) => {},
        Err(ArchiveError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => {
            debug!("Client went away during a folder download");
        },
        Err(ArchiveError::Io(e)) if e.kind() == io::ErrorKind::TimedOut => {
            warn!(
                "Abandoned a folder download: the client read nothing for {}s",
                out.stall_timeout.as_secs()
            );
        },
        Err(e) => error!("Folder download failed part-way: {}", e),
    }
}

/// Opens the read transaction the archive is built in, and plans the archive
/// inside it.
///
/// The folder tree is read twice, once to work out the length and once to
/// write the archive. Both passes run in this transaction, so they see the
/// same entries whatever other requests change in the meantime, and the
/// length worked out here is exactly what a successful run sends.
fn start_archive<'c>(
    db: &'c mut Connection,
    folder_path: &str,
    username: &str,
) -> Result<(Transaction<'c>, ArchivePlan), DbError> {
    let snapshot = db.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let plan = plan_archive(&snapshot, folder_path, username)?;

    Ok((snapshot, plan))
}

/// Finds the folder, names the archive, and works out its exact length by
/// walking the folder tree once, without reading any file.
fn plan_archive(
    db: &Connection,
    folder_path: &str,
    username: &str,
) -> Result<ArchivePlan, DbError> {
    let folder_id = sqlite::get_folder_id(db, folder_path)?.ok_or(DbError::NotFound)?;

    // The root folder's stored name is a placeholder; its archive is named
    // after the user.
    let name = if folder_id == 1 {
        username.to_owned()
    } else {
        sqlite::get_folder_name(db, folder_id)?
    };
    let root = format!("{name}/");
    let mut len = tar::END_LEN;

    let skipped = for_each_entry(db, folder_id, &root, |entry| {
        len += match entry {
            ArchiveEntry::Folder { path, .. } => tar::entry_len(&path, 0),
            ArchiveEntry::File { path, metadata, .. } => tar::entry_len(&path, metadata.total_size),
        };

        Ok::<_, DbError>(())
    })?;

    // Only a count: file names are user data, which stays out of the logs.
    if skipped > 0 {
        warn!(
            "Leaving {} entries with invalid names out of a folder download",
            skipped
        );
    }

    Ok(ArchivePlan {
        folder_id,
        root,
        len,
    })
}

/// Writes every entry of the archive, then the end-of-archive marker.
fn write_archive(
    db: &Connection,
    plan: &ArchivePlan,
    context: &UserContext,
    out: &mut ChannelWriter,
) -> Result<(), ArchiveError> {
    for_each_entry(db, plan.folder_id, &plan.root, |entry| {
        match entry {
            ArchiveEntry::Folder { path, mtime } => {
                tar::write_header(out, &path, EntryKind::Directory, 0, mtime)?;
            },
            ArchiveEntry::File {
                path,
                encoded_name,
                metadata,
                mtime,
            } => {
                write_file(out, context, &path, &encoded_name, metadata, mtime)?;
            },
        }

        Ok::<_, ArchiveError>(())
    })?;

    tar::write_end(out)?;
    out.flush()?;

    Ok(())
}

/// Calls `f` with every entry of the archive, and returns how many entries
/// were left out.
///
/// Names are checked when they are stored, but an entry that slipped through
/// could point outside the directory the archive is extracted to, so it is
/// left out. Both passes go through here, so they leave out exactly the same
/// entries and the archive's length matches what is written.
fn for_each_entry<E: From<DbError>>(
    db: &Connection,
    folder_id: i32,
    root: &str,
    mut f: impl FnMut(ArchiveEntry) -> Result<(), E>,
) -> Result<usize, E> {
    let mut skipped = 0;

    sqlite::for_each_archive_entry(db, folder_id, root, |entry| {
        let (ArchiveEntry::Folder { path, .. } | ArchiveEntry::File { path, .. }) = &entry;

        if is_valid_relative_path(path) {
            f(entry)
        } else {
            skipped += 1;

            Ok(())
        }
    })?;

    Ok(skipped)
}

/// Writes one file's entry: its header, its decrypted content, and padding.
/// Fails with `Truncated` if the stored file holds less than its recorded size.
fn write_file(
    out: &mut ChannelWriter,
    context: &UserContext,
    path: &str,
    encoded_name: &str,
    metadata: FileEncryptionMetadata,
    mtime: u64,
) -> Result<(), ArchiveError> {
    let size = metadata.total_size;

    tar::write_header(out, path, EntryKind::File, size, mtime)?;

    if size == 0 {
        return Ok(());
    }

    let file = context.open_blob_on_this_thread(encoded_name)?;
    let reader = SyncChunkDecryptReader::new(file, metadata)?;
    let copied = io::copy(&mut reader.take(size), out)?;

    if copied != size {
        return Err(ArchiveError::Truncated {
            encoded_name: encoded_name.to_owned(),
            expected: size,
            got: copied,
        });
    }

    tar::write_padding(out, size)?;

    Ok(())
}

/// Sends what is written to it down a channel in chunks of up to
/// `CHUNK_SIZE` bytes, waiting while the channel is full. Small writes such
/// as headers are gathered into the same chunk as the data around them.
///
/// Writes fail with `BrokenPipe` once the receiving end is gone, and with
/// `TimedOut` if a chunk waits longer than `stall_timeout` for room: a
/// client that stops reading would otherwise keep the download, and the
/// database snapshot it holds, open forever.
///
/// Sending blocks the thread, so it must only be used on a blocking thread.
pub struct ChannelWriter {
    tx: mpsc::Sender<Vec<u8>>,
    buf: Vec<u8>,
    stall_timeout: Duration,
    runtime: Handle,
}

impl ChannelWriter {
    /// Must be called from within the async runtime, whose timer the writer
    /// uses.
    pub fn new(tx: mpsc::Sender<Vec<u8>>, stall_timeout: Duration) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(CHUNK_SIZE),
            stall_timeout,
            runtime: Handle::current(),
        }
    }

    /// Sends the buffered bytes as one chunk, waiting at most the stall timeout
    /// for room.
    fn send(&mut self) -> io::Result<()> {
        let chunk = mem::replace(&mut self.buf, Vec::with_capacity(CHUNK_SIZE));
        let sent = self
            .runtime
            .block_on(time::timeout(self.stall_timeout, self.tx.send(chunk)));

        match sent {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the client went away",
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the client stopped reading",
            )),
        }
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(CHUNK_SIZE - self.buf.len());

        self.buf.extend_from_slice(&data[..n]);

        if self.buf.len() == CHUNK_SIZE {
            self.send()?;
        }

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.send()?;
        }

        Ok(())
    }
}
