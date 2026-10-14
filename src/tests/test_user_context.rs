use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

use futures_util::future::join_all;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{
    config::DbConfig, enums::blocking_error::BlockingError, storage::user_context::UserContext,
};

// A context whose user may occupy at most `threads` blocking threads (no
// limit with none), and which gives up waiting for a turn after
// `max_wait_secs`. Its pool is never used.
fn context(threads: Option<usize>, max_wait_secs: u64) -> UserContext {
    let pool = Pool::builder()
        .max_size(1)
        .build_unchecked(SqliteConnectionManager::memory());

    UserContext::new(
        pool,
        PathBuf::new(),
        &DbConfig {
            max_connections: NonZeroU32::new(1).unwrap(),
            connection_timeout_seconds: NonZeroU64::new(max_wait_secs).unwrap(),
            ..DbConfig::default()
        },
        threads.map(|threads| NonZeroUsize::new(threads).unwrap()),
    )
}

// Runs 20 tasks that each sleep for 50 ms on the context's blocking threads,
// and returns the most that ran at once.
async fn peak_concurrency(context: &UserContext) -> usize {
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let tasks = (0..20).map(|_| {
        let running = running.clone();
        let peak = peak.clone();

        context.run_blocking(move || {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;

            peak.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(50));
            running.fetch_sub(1, Ordering::SeqCst);
        })
    });

    for result in join_all(tasks).await {
        result.unwrap();
    }

    peak.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_blocking_work_never_exceeds_the_users_limit() {
    // The test runtime has 32 blocking threads, so without the limit all 20
    // tasks would run at once.
    assert_eq!(peak_concurrency(&context(Some(4), 30)).await, 4);
}

// By default a single user may use every blocking thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_blocking_work_is_unlimited_by_default() {
    assert_eq!(peak_concurrency(&context(None, 30)).await, 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_waiting_for_a_turn_gives_up_after_the_timeout() {
    let context = context(Some(1), 1);
    let _taken = context.reserve_blocking().await.unwrap();
    let started = Instant::now();

    let result = context.run_blocking(|| ()).await;

    assert!(matches!(result, Err(BlockingError::Busy)), "{result:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
}

// `start_blocking` returns at once, but the thread counts against the user's
// limit until the work finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_started_work_keeps_its_thread_until_it_finishes() {
    let context = context(Some(1), 1);
    let (finish, finished) = mpsc::channel::<()>();

    let running = context
        .start_blocking(move || finished.recv().unwrap())
        .await
        .unwrap();

    assert!(matches!(
        context.run_blocking(|| ()).await,
        Err(BlockingError::Busy)
    ));

    finish.send(()).unwrap();
    running.await.unwrap();

    context.run_blocking(|| ()).await.unwrap();
}

// A scan walks all of the user's storage, so a second one (from a second
// login) waits until the first is over instead of repeating its work.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_only_one_orphan_scan_runs_per_user() {
    let context = context(Some(1), 1);
    let first = context.try_claim_orphan_scan();

    assert!(first.is_some());
    assert!(context.clone().try_claim_orphan_scan().is_none());

    drop(first);

    assert!(context.try_claim_orphan_scan().is_some());
}
