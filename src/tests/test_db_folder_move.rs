// Unit tests for `sqlite::move_folder`.
//
// Moving a folder underneath one of its own descendants creates a cycle in the
// folder tree, and the folder-total triggers then recurse forever, growing in
// memory until the process dies. There is deliberately no schema-level guard
// against this: `move_folder`'s own check is the only thing preventing it, so
// these tests are the safety net.
//
// Every test that could trigger the runaway arms a `Watchdog`, which
// interrupts SQLite after a few seconds. If the check is ever weakened, the
// affected test then fails quickly with a clear message instead of hanging the
// test run.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};
use tempfile::tempdir;

use super::{migrated_db, Db};
use crate::{
    db::{migrations::get_migrations, sqlite},
    enums::db_error::DbError,
};

// Interrupts whatever statement is running on the connection once `limit` has
// passed, unless it has been dropped first.
struct Watchdog(Arc<AtomicBool>);

impl Watchdog {
    fn arm(conn: &Connection, limit: Duration) -> Self {
        let handle = conn.get_interrupt_handle();
        let finished = Arc::new(AtomicBool::new(false));
        let flag = finished.clone();

        thread::spawn(move || {
            let deadline = Instant::now() + limit;

            while Instant::now() < deadline {
                if flag.load(Ordering::Relaxed) {
                    return;
                }

                thread::sleep(Duration::from_millis(50));
            }

            handle.interrupt();
        });

        Watchdog(finished)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn folder_id(db: &Db, path: &str) -> i32 {
    sqlite::get_folder_id(db, path).unwrap().unwrap()
}

// (total size, total files, total folders) as maintained by the triggers.
fn totals(db: &Db, folder_id: i32) -> (i64, i64, i64) {
    db.query_row(
        "SELECT total_folder_size, total_file_count, total_folder_count FROM folders WHERE id = ?1",
        params![folder_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

fn add_file_row(db: &Db, folder_id: i32, name: &str, size: i64) {
    db.execute(
        "INSERT INTO files (parent_folder_id, name, encoded_name, key, total_size) VALUES (?1, ?2, ?2, x'00', ?3)",
        params![folder_id, name, size],
    )
    .unwrap();
}

// Follows every folder's parent chain and fails if any of them never reaches
// the root.
fn assert_tree_is_acyclic(db: &Db) {
    let mut stmt = db
        .prepare("SELECT id, parent_folder_id FROM folders")
        .unwrap();
    let parents: HashMap<i32, Option<i32>> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();

    for &start in parents.keys() {
        let mut current = start;
        let mut steps = 0;

        while let Some(Some(parent)) = parents.get(&current) {
            current = *parent;
            steps += 1;

            assert!(steps <= parents.len(), "folder {start} is part of a cycle");
        }
    }
}

fn assert_rejected_as_cycle(result: Result<(), DbError>, context: &str) {
    assert!(
        matches!(result, Err(DbError::InvalidInput(_))),
        "{context}: expected the move to be rejected as a cycle, got {result:?}"
    );
}

#[test]
fn test_move_folder_rejects_a_move_into_its_own_subtree_for_every_path_spelling() {
    let mut db = migrated_db();
    let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));
    sqlite::add_folder(&mut db, "a/b/c").unwrap();
    let ids = [
        1,
        folder_id(&db, "a"),
        folder_id(&db, "a/b"),
        folder_id(&db, "a/b/c"),
    ];
    let before = ids.map(|id| totals(&db, id));

    // Spellings of the destination that resolve into a/b's own subtree. Some
    // only get past a plain string comparison because path resolution
    // normalizes them, and some name folders that don't exist yet.
    for destination in [
        "a/b",
        "a/./b",
        "a/b/c",
        "a/./b/c",
        "a/b/../b/c",
        "a//b/c",
        "./a/b/c",
        "/a/b/c",
        "a/b/c/",
        "a/b/c/d",
        "a//b/new",
    ] {
        let result = sqlite::move_folder(&mut db, "a/b", destination);

        assert_rejected_as_cycle(result, &format!("destination '{destination}'"));
    }

    // The same, with the source spelled differently.
    for source in ["/a/b/", "./a/b", "a//b", "a/./b"] {
        let result = sqlite::move_folder(&mut db, source, "a/b/c");

        assert_rejected_as_cycle(result, &format!("source '{source}'"));
    }

    // Nothing moved, and no destination folder was left behind.
    assert_eq!(sqlite::get_folder_id(&db, "a/b/c").unwrap(), Some(ids[3]));
    assert_eq!(sqlite::get_folder_id(&db, "a/b/c/d").unwrap(), None);
    assert_eq!(sqlite::get_folder_id(&db, "a/b/new").unwrap(), None);
    assert_eq!(ids.map(|id| totals(&db, id)), before);
}

#[test]
fn test_move_folder_rejected_move_rolls_back_the_destination_it_created() {
    let mut db = migrated_db();
    let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));
    sqlite::add_folder(&mut db, "a/b").unwrap();
    let root_before = totals(&db, 1);

    let result = sqlite::move_folder(&mut db, "a/b", "a//b/new/deeper");

    assert_rejected_as_cycle(result, "destination that has to be created first");
    assert_eq!(sqlite::get_folder_id(&db, "a/b/new").unwrap(), None);
    assert_eq!(totals(&db, 1), root_before);
}

#[test]
fn test_move_folder_rejects_the_root_and_unknown_sources() {
    let mut db = migrated_db();
    let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));
    sqlite::add_folder(&mut db, "a").unwrap();

    for root in ["", "/"] {
        let result = sqlite::move_folder(&mut db, root, "a");

        assert_rejected_as_cycle(result, &format!("moving the root as '{root}'"));
    }

    let result = sqlite::move_folder(&mut db, "nope", "a");

    assert!(matches!(result, Err(DbError::NotFound)), "got {result:?}");
}

#[test]
fn test_move_folder_allows_moves_that_are_not_cycles() {
    let mut db = migrated_db();
    let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));
    sqlite::add_folder(&mut db, "a/b/c").unwrap();
    sqlite::add_folder(&mut db, "x").unwrap();
    let c = folder_id(&db, "a/b/c");

    // Up into an ancestor, sideways into a sibling, and out to the root.
    sqlite::move_folder(&mut db, "a/b/c", "a").unwrap();
    assert_eq!(sqlite::get_folder_id(&db, "a/c").unwrap(), Some(c));

    sqlite::move_folder(&mut db, "a/c", "x").unwrap();
    assert_eq!(sqlite::get_folder_id(&db, "x/c").unwrap(), Some(c));

    sqlite::move_folder(&mut db, "x/c", "").unwrap();
    assert_eq!(sqlite::get_folder_id(&db, "c").unwrap(), Some(c));
}

#[test]
fn test_move_folder_creates_a_missing_destination() {
    let mut db = migrated_db();
    let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));
    sqlite::add_folder(&mut db, "a/b").unwrap();
    let b = folder_id(&db, "a/b");

    sqlite::move_folder(&mut db, "a/b", "x/y").unwrap();

    assert_eq!(sqlite::get_folder_id(&db, "x/y/b").unwrap(), Some(b));
    assert_eq!(sqlite::get_folder_id(&db, "a/b").unwrap(), None);
    assert_eq!(totals(&db, 1), (0, 0, 4));
}

#[test]
fn test_move_folder_moves_a_subtree_and_keeps_the_totals_correct() {
    let mut db = migrated_db();
    let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));
    sqlite::add_folder(&mut db, "a/b/c").unwrap();
    sqlite::add_folder(&mut db, "x").unwrap();
    let (a, b, c, x) = (
        folder_id(&db, "a"),
        folder_id(&db, "a/b"),
        folder_id(&db, "a/b/c"),
        folder_id(&db, "x"),
    );
    add_file_row(&db, c, "f", 10);

    sqlite::move_folder(&mut db, "a/b", "x").unwrap();

    assert_eq!(sqlite::get_folder_id(&db, "x/b/c").unwrap(), Some(c));
    assert_eq!(sqlite::get_folder_id(&db, "a/b").unwrap(), None);
    assert_eq!(totals(&db, 1), (10, 1, 4));
    assert_eq!(totals(&db, a), (0, 0, 0));
    assert_eq!(totals(&db, x), (10, 1, 2));
    assert_eq!(totals(&db, b), (10, 1, 1));
    assert_eq!(totals(&db, c), (10, 1, 0));
}

// The check has to happen under the write lock. Here one connection has moved
// z under y but not yet committed, and a second connection then asks to move
// y into z/w. Before the first move z/w is not inside y, so a check that read
// the tree before taking the write lock would allow it, and once the first move
// commits that would put y underneath its own descendant. Taking the lock
// first means the second move waits, then sees the committed tree. Whatever it
// then decides to do, it must end cleanly and leave the tree acyclic.
#[test]
fn test_move_folder_checks_for_cycles_under_the_write_lock() {
    let dir = tempdir().unwrap();
    let manager = SqliteConnectionManager::file(dir.path().join("race.db"))
        .with_init(|conn| conn.busy_timeout(Duration::from_secs(10)));
    let pool = Pool::builder().max_size(2).build(manager).unwrap();

    let mut writer = pool.get().unwrap();
    get_migrations().to_latest(&mut writer).unwrap();
    sqlite::add_folder(&mut writer, "y").unwrap();
    sqlite::add_folder(&mut writer, "z/w").unwrap();
    let (y, z) = (folder_id(&writer, "y"), folder_id(&writer, "z"));

    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    writer
        .execute(
            "UPDATE folders SET parent_folder_id = ?1 WHERE id = ?2",
            params![y, z],
        )
        .unwrap();

    let contender = {
        let pool = pool.clone();

        thread::spawn(move || {
            let mut db = pool.get().unwrap();
            let _watchdog = Watchdog::arm(&db, Duration::from_secs(5));

            sqlite::move_folder(&mut db, "y", "z/w")
        })
    };

    // Give the contender time to start and block on the write lock.
    thread::sleep(Duration::from_millis(500));
    writer.execute_batch("COMMIT").unwrap();

    let result = contender.join().unwrap();

    assert!(
        matches!(result, Ok(()) | Err(DbError::InvalidInput(_))),
        "move made while another move was in flight did not end cleanly: {result:?}"
    );
    assert_tree_is_acyclic(&writer);
}
