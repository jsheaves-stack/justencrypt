# JustEncrypt — Audit Report & Remediation Plan

| | |
|---|---|
| **Audited commit** | `947a1a4` (branch `user-session-overhaul`) |
| **Audit date** | 2026-09-23 |
| **Scope** | All Rust source (~4.5k LOC) + tests (~1.7k LOC), `Cargo.toml`, Dockerfiles, CI spec, `openapi.yaml`, README, perf harness |
| **Baseline** | `cargo test`: 42/42 pass · default `cargo clippy`: clean · `cargo audit`: 7 vulnerabilities (see M10) |

Line numbers in this document refer to commit `947a1a4` and will drift as fixes land — search by function name if a line no longer matches.

**Evidence tags used below**
- **[Reproduced]** — I ran it against the real code (throwaway tests, live server, load harness, `sqlite3`). Reproduction recipes are in [Appendix A](#appendix-a--reproduction-recipes).
- **[Code]** — established by reading the code; not executed.

---

## 0. How to use this document (read this first if you are an agent)

1. Pick an item from the [tracker](#1-tracker). Items are independent unless a **Depends on** line says otherwise. Suggested bundles are in [§2](#2-work-packages--suggested-order).
2. **Write the regression test first** (each item lists one) and watch it fail on the current code, then implement the fix, then watch it pass.
3. Before declaring an item done:
   - `cargo test` — all green (the suite runs in ~1 s; tests write to the system temp dir).
   - `cargo clippy --all-targets` — no new warnings.
   - `cargo +nightly fmt` — `rustfmt.toml` uses unstable options, so stable `cargo fmt` will not apply them.
   - Tick the checkbox in the tracker and fill in `Done in: <commit/PR>` under the item.
4. **Match the surrounding style.** The codebase leaves a blank line before `return`/`if`/`match` and after log macros (see the rules in `scripts/format_code.py`), uses `thiserror` enums for errors, and runs all SQLite work through `spawn_blocking`.
5. **Do not change the on-disk format** (blob layout, SQLCipher schema) without a migration. Schema changes = append a new `M::up(...)` in `src/db/migrations.rs`; never edit the existing migration (deployed DBs have already run it).
6. **API changes** (status codes, response shapes) must be mirrored in `openapi.yaml` and called out in the PR description. Items that change client-visible behavior are marked ⚠️ **API change**.
7. **When running the server binary manually, `cd` out of the project directory** (or set every env var explicitly). `dotenv` loads `./.env` from the current directory and the project's `.env` contains real secrets, including the admin key.
8. Leave changes uncommitted / on a branch unless told otherwise. One work package per branch is easiest to review.

**Effort key:** S = under ~1 h · M = half a day · L = a day or more.

---

## 1. Tracker

### High severity
- [x] **H1** — Lock-order deadlock permanently freezes all authentication · *Critical, S (minimal) / M (proper)* · [details](#h1)
- [x] **H2** — `init_upload` self-deadlocks on a stale upload (+ broken stale cleanup) · *High, M* · [details](#h2)
- [x] **H3** — Folder-move cycle → unbounded SQLite recursion → OOM · *High, M* · [details](#h3)
- [x] **H4** — `finalize_upload` loops over a client-controlled `total_size` (memory DoS) · *High, S* · [details](#h4)
- [x] **H5** — `PUT /file` silently truncates bodies over 5 GiB; configured file limit ignored · *High, M* · [details](#h5)
- [x] **H6** — Empty files cannot be downloaded (bad `Content-Length`) · *High, S* · [details](#h6)

### Medium severity
- [x] **M1** — Server trusts the client's `total_size` at finalize · *Medium, M* · [details](#m1)
- [x] **M2** — Overwrite race orphans encrypted blobs · *Medium, M* · [details](#m2)
- [ ] **M3** — Sessions never expire; logout leaks `.part` files and doesn't clear the cookie · *Medium, M* · [details](#m3)
- [ ] **M4** — Login hardening: no throttling, user-enumeration oracles, unvalidated username · *Medium, L* · [details](#m4)
- [ ] **M5** — Admin API key: empty value accepted, non-constant-time compare · *Medium, S* · [details](#m5)
- [ ] **M6** — Secrets committed to git / defaults baked into code and images · *Medium, S* · [details](#m6)
- [ ] **M7** — Non-atomic multi-step operations (folder delete, patch, finalize) · *Medium, L* · [details](#m7)
- [ ] **M8** — `PATCH` validation and semantics (nonexistent files, collisions, bad names) · *Medium, M* · [details](#m8)
- [ ] **M9** — No flush/fsync on writes; non-atomic thumbnail cache writes · *Medium, M* · [details](#m9)
- [ ] **M10** — Vulnerable/unmaintained dependencies; `Cargo.lock` is gitignored · *Medium, S* · [details](#m10)
- [ ] **M11** — HTTP/API hardening and consistency (headers, CORS, error format, statuses, ranges, dates) · *Medium, L* · [details](#m11)
- [ ] **M12** — First-login race: concurrent migrations collide; error is masked · *Medium, S* · [details](#m12)
- [ ] **M13** — Thumbnail decode has no resource limits · *Medium, S* · [details](#m13)

### Architecture / code quality
- [ ] **A1** — Typed, validated `Config` instead of 37 scattered `env::var` calls (and fix doc/code default drift) · *L* · [details](#a1)
- [ ] **A2** — Layering: db↔session cycle; business logic in route handlers · *M* · [details](#a2)
- [ ] **A3** — `UserSession` is ~18 identical wrappers; duplicated cleanup functions · *M* · [details](#a3)
- [ ] **A4** — `VirtualPath` newtype: parse/validate paths once at the boundary · *M* · [details](#a4)
- [ ] **A5** — Encryption module cleanup (duplicate loops, copies, `unwrap`s, format versioning) · *M* · [details](#a5)
- [ ] **A6** — Logging: remove Entering/Exiting boilerplate, stop logging file names · *S* · [details](#a6)
- [ ] **A7** — Secrets held in plain `String`s; tokens stored raw in the session map · *S* · [details](#a7)
- [ ] **A8** — Dead code and unused dependencies · *S* · [details](#a8)
- [ ] **A9** — Tooling: regex formatter script, nightly-only rustfmt, dead build args, CI gates · *S* · [details](#a9)

### Tests / ops / docs
- [ ] **T1** — Test infrastructure: split `lib.rs`, shared `build_rocket`, remove `env::set_var` · *M* · [details](#t1)
- [ ] **T2** — Missing regression tests (checklist) · *M* · [details](#t2)
- [ ] **O1** — Dockerfile hardening (non-root, volume, `.dockerignore`, perf image secret) · *S* · [details](#o1)
- [ ] **O2** — README/docs are inaccurate (MSRV, env file, missing provisioning docs) · *S* · [details](#o2)

---

## 2. Work packages & suggested order

Several items touch the same code; doing them together avoids merge pain.

| WP | Theme | Items | Notes |
|---|---|---|---|
| **WP0** | Quick wins (do first, independent) | H1 *(minimal patch)*, H6, M10 *(cargo update + commit lockfile)*, M6 *(rotate/placeholder)*, A8 | Under a day total; removes the worst outage risks. |
| **WP1** | Session store & lifecycle | H1 *(proper)*, M3, M12, M5, A7, M4 | H1 proper introduces `SessionStore`; M3/M4 build on it. |
| **WP2** | Upload pipeline | H2, H4, H5, M1, M9, M13 | All in `routes/file.rs`, `encryption/`, `thumbnail.rs`. Do H4+H5+M1 as one change. |
| **WP3** | DB layer | A4 → H3, M2, M7, M8, A3, A2 | Do A4 (`VirtualPath`) first; then refactor DB functions to take `&Connection`/`&Transaction` once and fix H3/M2/M7/M8 in the same pass. |
| **WP4** | HTTP/API contract | M11, plus API bits of H6/M8 | Update `openapi.yaml` in the same PR. |
| **WP5** | Config, tooling, tests, ops | A1, A6, A9, T1, T2, O1, O2 | A1 unblocks clean limits/TTLs; each item below notes an **interim** approach if A1 hasn't landed yet. |

Recommended sequence: **WP0 → WP2 (H2/H4/H5) → WP1 → WP3 → WP4 → WP5.** Items H1–H6 are the ones that can take a production instance down or lose data.

---

## 3. High severity

<a id="h1"></a>
### H1 — Lock-order deadlock permanently freezes all authentication
**Severity:** Critical (availability) · **Evidence:** [Reproduced, A/B-proven] · **Effort:** S (minimal) / M (proper) · **WP:** 0 → 1
- [x] Done in: `3b2695b` on branch `user-session-overhaul` — steps 1 and 2 together (`SessionStore` in `src/session/store.rs`). Stress harness (A.1, release build): original code deadlocked 3/3 runs; fixed code `no hang observed` 3/3 (~350k reads / ~1.6k logouts per 40 s run). Store tests live in `src/tests/test_session_store.rs`. Token keys are still raw tokens (A7 will switch them to digests).

**Where**
- `src/web/forwarding_guards.rs:95` and `:106` — `AuthenticatedSession::from_request` takes `token_to_id.read()` and keeps that guard alive while it awaits `sessions_by_id.read()`.
- `src/routes/session.rs:197-198` (`destroy_session`) and `src/routes/admin.rs:72-73` (`delete_session`) take `sessions_by_id.write()` **then** `token_to_id.write()`.

**Problem**
Classic ABBA lock ordering. Tokio's `RwLock` is write-fair: once a writer is queued, new readers block behind it. If a logout holds `sessions_by_id.write()` and waits for `token_to_id.write()` while a request holds `token_to_id.read()` and waits for `sessions_by_id.read()`, both wait forever. Every later request that needs either lock (all authenticated routes *and* `POST /session`) queues behind them. Unauthenticated routes (`GET /`) keep working, which makes it look like a partial outage.

**Evidence**
Release build, 12 threads issuing authenticated `GET /folder/` while 4 threads loop login → logout:
- Original code: **deadlocked 3/3 runs** (after 5, 669 and 798 logouts). Afterwards `POST /session` hangs, server CPU is 0.0%, `GET /` still returns 200, and an authenticated request with a valid cookie hangs.
- With only the guard change below: **0/3 deadlocks**, each run ~1,630 logouts / ~350k reads, server healthy afterwards.

**Fix — step 1, minimal (ship this immediately)**
Drop the `token_to_id` guard before touching `sessions_by_id`:
```rust
// src/web/forwarding_guards.rs  (AuthenticatedSession::from_request)
let session_id = {
    let token_to_id = state.token_to_id.read().await;
    match token_to_id.get(user_token) {
        Some(id) => id.clone(),
        None => {
            return Outcome::Error((Status::Unauthorized, RequestError::MissingActiveSession));
        },
    }
}; // token_to_id guard dropped here

let session = {
    let sessions_by_id = state.sessions_by_id.read().await;
    match sessions_by_id.get(&session_id) {
        Some(s) => s.clone(),
        None => {
            return Outcome::Error((Status::Unauthorized, RequestError::MissingActiveSession));
        },
    }
};
```
Also in `routes/session.rs:158-168` the code re-reads `sessions_by_id` and **holds that read guard across `cleanup_orphaned_uploads(...).await`** (DB + file I/O). Use the `Arc<UserSession>` you already have (clone it before inserting into the map) and call cleanup with no lock held:
```rust
let session_for_cleanup = session.clone();       // before the insert
// ... inserts ...
let active_session_ids = { state.sessions_by_id.read().await.keys().cloned().collect::<HashSet<_>>() };
if let Err(e) = session_for_cleanup.cleanup_orphaned_uploads(active_session_ids).await { error!(...); }
```

**Fix — step 2, proper (removes the bug class)**
Replace the two maps with one struct behind **one** lock so an ordering bug is impossible:
```rust
// src/session/store.rs (new)
#[derive(Default)]
pub struct SessionStore { inner: RwLock<Inner> }

#[derive(Default)]
struct Inner {
    by_token: HashMap<String, Arc<UserSession>>, // key: token digest, see A7
    token_of: HashMap<String, String>,           // session_id -> token key (admin delete-by-id)
}

impl SessionStore {
    pub async fn insert(&self, token_key: String, s: Arc<UserSession>);
    pub async fn get(&self, token_key: &str) -> Option<Arc<UserSession>>;
    pub async fn remove_by_token(&self, token_key: &str) -> Option<Arc<UserSession>>;
    pub async fn remove_by_id(&self, session_id: &str) -> Option<Arc<UserSession>>;
    pub async fn snapshot(&self) -> Vec<Arc<UserSession>>;                     // clones the Arcs, releases the lock
    pub async fn pool_for_user(&self, username: &str) -> Option<Pool<SqliteConnectionManager>>;
}
```
Rules for the store: each method takes the lock exactly once, returns owned data, and never awaits anything else while holding it. Callers that need to do slow work per session (admin listing, shutdown cleanup, reaper) call `snapshot()` first and lock each session's own state **outside** the store lock.

Sites to migrate: `AppState` and `CleanupOnShutdown` (`src/main.rs`), `routes/session.rs` (create/destroy), `routes/admin.rs` (list/delete), `web/forwarding_guards.rs`, and the test helpers (`src/tests/mod.rs::setup_rocket/create_test_session`, plus tests that read `state.sessions_by_id`: `test_file.rs`, `test_file_delete_patch.rs`, `test_folder.rs`, `test_folder_delete.rs`, `test_thumbnail.rs`, `test_admin.rs`).

**Regression tests**
- Unit test on `SessionStore`: 8 tasks × 50k `get` while another task loops `insert`/`remove_by_token`; wrap in `tokio::time::timeout(Duration::from_secs(30), ...)` and assert it completes. (Multi-thread runtime: `#[tokio::test(flavor = "multi_thread", worker_threads = 8)]`.)
- Black-box stress script in [Appendix A.1](#a1-h1--session-deadlock-stress-harness) — must show `no hang observed` 3/3 (it fails 3/3 on the original code).

**Acceptance criteria:** stress harness passes 3 consecutive 40 s runs; no code path holds one session-map lock while acquiring another or while awaiting I/O.

---

<a id="h2"></a>
### H2 — `init_upload` self-deadlocks on a stale upload (and the cleanup it attempts is wrong)
**Severity:** High · **Evidence:** [Reproduced] · **Effort:** M · **WP:** 2
- [x] Done in: `61518e3` on branch `user-session-overhaul` — fix steps 1–5 (`UserSession::abort_upload` / `sweep_stale_uploads`, atomic `last_updated`, two-phase limit check, `JUSTENCRYPT_UPLOAD_TTL_SECONDS`). Step 6 (background reaper) is left to M3. Regression tests are in `src/tests/test_chunked_upload.rs`.

**Where:** `src/routes/file.rs` `init_upload` — `:64` locks `session.active_uploads`; `:76-89` builds `stale_ids` while holding that guard; `:91-106` calls `session.active_uploads.lock().await` **again** for each stale id while the first guard (`active_uploads`, used again at `:140`) is still alive.

**Problem**
1. `tokio::sync::Mutex` is not reentrant → the handler hangs forever the first time any upload in the session has `last_updated` older than 24 h. Because sessions never expire (M3), an abandoned upload plus a later `init_upload` in the same session triggers it naturally.
2. The hung handler keeps the mutex, so every later `upload_chunk`/`finalize_upload` on that session hangs too; the admin listing (`routes/admin.rs:34-41`) takes `active_uploads.lock()` for each session **while holding `sessions_by_id.read()`**, so it hangs holding a read lock and then all logins/logouts queue behind it *[Code]*.
3. The sweep is also functionally wrong: it deletes `get_sharded_path(user, encoded_file_name)` (the *final* path) but uploads live at `<final>.part`; it never removes the `active_uploads` DB row; and the limit check (`:70-74`) runs *before* the sweep so stale uploads count against the limit.
4. `init_upload` holds the `active_uploads` mutex across DB writes and file creation (`add_active_upload_db`, `ChunkEncryptor::new`), serialising every upload operation for the session.

**Evidence:** test backdates one upload by 25 h then calls `POST /file/upload/initiate/...` under a 5 s timeout → hangs. Same request with only fresh uploads returns 200.

**Fix**
1. Add one helper on `UserSession` that owns all upload teardown and is reused by cleanup, the reaper (M3) and the stale sweep:
```rust
// session/user_session.rs
pub async fn abort_upload(&self, upload_id: &str, state: &UploadState) {
    let part = part_path(&self.user_path, &state.encoded_file_name);   // <sharded>/<uuid>.part
    if let Err(e) = remove_sharded_path(&self.user_path, &part).await { /* ignore NotFound, warn otherwise */ }
    let _ = self.remove_active_upload_db(upload_id.to_string()).await;
}
```
2. Rewrite the sweep so it removes under **one** guard, releases the guard, *then* does I/O:
```rust
let stale: Vec<(String, UploadState)> = {
    let mut uploads = session.active_uploads.lock().await;
    let now = SystemTime::now();
    let stale_ids: Vec<String> = uploads.iter()
        .filter(|(_, s)| is_stale(s, now, ttl))       // see note on last_updated below
        .map(|(id, _)| id.clone()).collect();
    stale_ids.into_iter().filter_map(|id| uploads.remove(&id).map(|s| (id, s))).collect()
}; // guard dropped
for (id, state) in &stale { session.abort_upload(id, state).await; }
// then re-lock briefly for the limit check
```
   Sweep **before** the limit check.
3. Make `UploadState.last_updated` an `AtomicU64` (unix seconds) or fold it into one `Mutex<UploadInner>` together with `written_chunks` and the encryptor (today: three separate `Arc<Mutex<..>>` per upload). This removes the nested `.lock().await` inside the sweep.
4. Do the file/DB creation for the new upload **outside** the `active_uploads` lock; take the lock only to check the limit and insert.
5. Make the TTL configurable (`JUSTENCRYPT_UPLOAD_TTL_SECONDS`, default 86400) — see A1; interim: read it once via a small helper.
6. (Best) Also run the sweep from the background reaper in M3 so abandoned uploads are reclaimed even when the user never starts another upload.

**Regression tests**
```rust
// test: stale upload must not hang init_upload and must be cleaned up
let stale_id = /* init upload A, then set its last_updated to now-25h via the session state */;
let r = timeout(Duration::from_secs(5), client.post("/file/upload/initiate/c.txt").private_cookie(cookie).dispatch()).await
    .expect("init_upload hung (deadlock)");
assert_eq!(r.status(), Status::Ok);
// A's .part file is gone from disk, A's row is gone from active_uploads (DB), A's id not in session.active_uploads
```

**Acceptance criteria:** the test above passes; no `.await` on a second lock occurs while `active_uploads` is held; stale `.part` files and DB rows are removed.

---

<a id="h3"></a>
### H3 — Folder-move cycle → unbounded SQLite recursion → OOM
**Severity:** High (any authenticated user can kill the whole process) · **Evidence:** [Reproduced] · **Effort:** M · **WP:** 3
- [x] Done in: `20a70f0` on branch `user-session-overhaul` — **layer 1 only, by decision.** `sqlite::move_folder` is one `IMMEDIATE` transaction with an id-based cycle check (a terminating `UNION` walk) and a rolled-back destination on rejection; folder creation was split into `get_or_create_folder(&Connection)` with `get_folder_id_and_create_if_missing` kept as a behavior-preserving wrapper. **Layers 2 and 3 (migration #2: the `prevent_folder_cycle` trigger and `UNION` rewrites of the six ancestor triggers) were deliberately not shipped:** a schema change makes every migrated DB unopenable by an older binary (`DatabaseTooFarAhead` → login fails), so rolling back a deployment would lock users out. The application check is therefore the only barrier, and is documented as such in a comment on `move_folder`. Tests: `src/tests/test_db_folder_move.rs` (unit tests on `move_folder` with an interrupt watchdog so a regression fails in ~5 s instead of hanging or exhausting memory; includes a concurrency test for the check-under-write-lock property) and `src/tests/test_folder_patch.rs` (route level). Verified by mutation: re-introducing the original string comparison, removing the check, or moving the check outside the transaction each fails the unit tests. Note: on the original code `a/b/../b/c` was already rejected by the string check; the real bypasses were `a/./b/c`, `a//b/c` and `./a/b/c`.

**Where**
- `src/db/sqlite.rs:773-780` `move_folder` — cycle check is a **string prefix** test on the raw request paths.
- `src/db/sqlite.rs:263-267` / `:195-199` — path lookup silently skips `.`/`..` components (`_ => continue`), so the *resolved* folder differs from the checked string.
- `src/db/migrations.rs:141-165` (`folders_after_update_parent`) and the five other triggers use `WITH RECURSIVE ParentFolders ... UNION ALL` to walk ancestors — infinite on a cycle.

**Problem**
`PATCH /folder/a/b` with `{"parent_folder_path": "a/./b/c"}` passes the prefix check (`"a/./b/c"` does not start with `"a/b/"`), but resolves to `a/b/c`, so folder `b` becomes a child of its own descendant `c`. The `UPDATE` fires `folders_after_update_parent`, whose `UNION ALL` recursion never terminates; with the app's `PRAGMA temp_store = MEMORY` the intermediate rows grow without bound.

**Evidence**
- Direct form `a/b/c` → 400 (already covered by an existing test). Bypass form `a/./b/c` → request hangs (>10 s).
- `sqlite3` with the migration SQL and the same UPDATE: RSS grows ~50 MB/s (204 → 405 → 607 → 808 MB at 4 s steps) until killed.

**Fix (do all three layers)**

*Layer 1 — application (correct by construction).* Do the cycle check by **id**, inside the same `IMMEDIATE` transaction that performs the move, and create the destination inside that transaction too (so a rejected move rolls the created folders back):
```rust
pub fn move_folder(db: &mut Connection, src: &VirtualPath, dst: &VirtualPath) -> Result<(), DbError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let folder_id = get_folder_id(&tx, src)?.ok_or(DbError::NotFound)?;
    if folder_id == ROOT_FOLDER_ID { return Err(DbError::InvalidInput("Cannot move the root folder".into())); }

    let dest_id = get_or_create_folder(&tx, dst)?;          // takes &Connection; no nested transaction
    // walk the destination's ancestors; if we meet folder_id it's a cycle
    let mut cur = Some(dest_id);
    while let Some(id) = cur {
        if id == folder_id {
            return Err(DbError::InvalidInput("Cannot move a folder into itself or its subfolders".into()));
        }
        cur = tx.query_row("SELECT parent_folder_id FROM folders WHERE id = ?1", [id], |r| r.get::<_, Option<i64>>(0))?;
    }
    // also reject a name collision in the destination (see M8) before the UPDATE
    tx.execute("UPDATE folders SET parent_folder_id = ?1 WHERE id = ?2", params![dest_id, folder_id])?;
    tx.commit()?;
    Ok(())
}
```
This requires `get_folder_id_and_create_if_missing` (currently takes `&mut PooledConnection` and opens its own transaction, `:171-250`) to be refactored into `get_or_create_folder(conn: &Connection, ..)` that does no transaction handling itself. `&Transaction` derefs to `&Connection`. Layer 1 also becomes trivial once A4 (`VirtualPath`) rejects `.`/`..` at the boundary.

*Layer 2 — schema guard (new migration #2).* Append a second `M::up(...)`. Tested against the current schema with `sqlite3` (aborts cycles, allows legit moves):
```sql
CREATE TRIGGER prevent_folder_cycle
BEFORE UPDATE OF parent_folder_id ON folders
WHEN NEW.parent_folder_id IS NOT NULL AND NEW.parent_folder_id IS NOT OLD.parent_folder_id
BEGIN
  SELECT RAISE(ABORT, 'Cannot move a folder into itself or its subfolders')
  WHERE EXISTS (
    WITH RECURSIVE anc(id) AS (
      SELECT NEW.parent_folder_id
      UNION
      SELECT f.parent_folder_id FROM folders f JOIN anc ON f.id = anc.id
      WHERE f.parent_folder_id IS NOT NULL
    )
    SELECT 1 FROM anc WHERE id = OLD.id
  );
END;
```
*Layer 3 — terminating recursion for legacy data.* In the same migration, `DROP TRIGGER` and re-`CREATE` the six triggers that contain `WITH RECURSIVE ... UNION ALL` (`files_after_insert`, `files_after_delete`, `files_after_update`, `folders_after_insert`, `folders_after_delete`, `folders_after_update_parent`) with `UNION` instead of `UNION ALL`. `UNION` de-duplicates rows, so the ancestor walk terminates even if a DB already contains a cycle (verified: on a 2↔3 cycle the `UNION` form returns `2,3` and stops). Migration text is allowed to duplicate the CTE (migrations are immutable history); if you prefer, build the six statements from one shared `const` CTE string.

Note: existing user DBs pick up migration #2 the next time the user logs in (`create_user_db_connection` runs `to_latest`); the `existing_pool` path does not re-run migrations, which is fine because the pool was created after migrating.

**Regression tests**
- Route-level: after creating `a/b`, PATCH `a/b` with `parent_folder_path` = `a/b/c`, `a/./b/c`, `a/b/../b/c`, `a//b/c` → all must return **400** promptly (wrap in a 5 s `timeout`; **do not** let a failing run wedge the test binary — run the blocking part in a separate process or `std::process::exit` as in Appendix A.3).
- DB-level: with the migrated schema, `UPDATE folders SET parent_folder_id = <descendant> WHERE id = <ancestor>` raises the ABORT; a legitimate move succeeds; a manually-built cycle plus `UPDATE folders SET name = name` terminates.
- A rejected move leaves **no** new destination folders behind (rollback).

**Acceptance criteria:** no request can create a cycle; no trigger can loop; all three test groups pass.

---

<a id="h4"></a>
### H4 — `finalize_upload` loops over a client-controlled `total_size`
**Severity:** High (authenticated memory DoS; process abort at extremes) · **Evidence:** [Reproduced] · **Effort:** S · **WP:** 2 *(implement together with H5 and M1)*
- [x] Done in: `283e3fb` on branch `user-session-overhaul`, done together as one change (H4 + H5 + M1). Limits come from Rocket's `Limits` request guard: `file` (`JUSTENCRYPT_LIMITS_FILE`, 64 GiB) and a new `file-chunk` (`JUSTENCRYPT_LIMITS_FILE_CHUNK`, 32 MiB), so tests set per-instance limits with `tests::with_upload_limits` instead of env vars. `total_size` over the file limit → 413 before any scan; the missing-chunk list is capped at 100 with `(and N more)`, keeping the `Missing chunks: [...]` format. `FinalizeErrorResponse` is still unused (no JSON body change).

**Where:** `src/routes/file.rs:219-243` — `for i in 0..expected_chunks { if !contains { missing_chunks.push(i) } }`, then `format!("Missing chunks: {:?}", missing_chunks)`; `expected_chunks = total_size.div_ceil(CHUNK_SIZE)` and `total_size` is a query parameter with no bound.

**Problem:** A single `POST /file/upload/finalize/<id>?total_size=<huge>` with no chunks uploaded builds an O(total_size / 64 KiB) `Vec<u64>` plus a giant `Debug` string that is returned to the client.

**Evidence:** `total_size = 1 TiB`, zero bytes uploaded → 627 ms, response body **149 MB**, peak RSS 27 → 326 MB. `total_size = u64::MAX` → 2⁴⁸ iterations → allocation failure → process abort.

**Fix**
1. Reject early: `if total_size > max_file_size { return Err(RequestError::PayloadTooLarge /* 413 */) }` (config from A1; interim `crate::util::limits::max_file_size()` reading `JUSTENCRYPT_LIMITS_FILE` once).
2. Cap the reported list:
```rust
const MAX_REPORTED_MISSING: usize = 100;
let missing: Vec<u64> = (0..expected_chunks).filter(|i| !written.contains_key(i)).take(MAX_REPORTED_MISSING).collect();
```
   (with `max_file_size` bounding `expected_chunks` to ≤ ~1M for 64 GiB, the scan itself is cheap). Keep the message format `Missing chunks: [0, 1, ...]` so the existing client/test contract still holds; optionally append `(and N more)`. `FinalizeErrorResponse` in `file.rs:47` is defined but unused — use it if you switch to a JSON body (⚠️ API change).
3. Prefer an O(1) first check: `written.len() as u64 != expected_chunks` before scanning.
4. The rest of the finalize validation (contiguity, per-chunk lengths, size cross-check) is specified in **M1**.

**Regression test:** initiate upload, finalize with `total_size=1099511627776` and `=18446744073709551615` → **400/413 quickly** (< 200 ms), response body < 2 KiB, and RSS does not grow (assert on elapsed time and body length; RSS via `/proc/self/status` `VmHWM` if desired).

---

<a id="h5"></a>
### H5 — `PUT /file` silently truncates bodies over 5 GiB; configured limit ignored
**Severity:** High (silent data loss) · **Evidence:** [Reproduced] · **Effort:** M · **WP:** 2
- [x] Done in: `283e3fb` on branch `user-session-overhaul`, done together as one change (H4 + H5 + M1). Limits come from Rocket's `Limits` request guard: `file` (`JUSTENCRYPT_LIMITS_FILE`, 64 GiB) and a new `file-chunk` (`JUSTENCRYPT_LIMITS_FILE_CHUNK`, 32 MiB), so tests set per-instance limits with `tests::with_upload_limits` instead of env vars. Bodies are opened at limit + 1 and `ChunkEncryptor` returns `TooLarge` before writing the chunk that crosses it → 413 (`RequestError::PayloadTooLarge`); `put_file` removes its `.part` and tracking row. Chunk requests are limited to min(chunk limit, file limit − offset); misaligned offsets are 400. Fix step 4 (per-user quota) not done.

**Where:** `src/routes/file.rs:360` (`put_file`: `data.open(5.gibibytes())`) and `:186` (`upload_chunk`: same). `JUSTENCRYPT_LIMITS_FILE` (default 64 GiB) is read only for the `offset > max` check at `:158-167`.

**Problem**
- `Data::open(limit)` returns a `DataStream` that is `Take<…>`: hitting the limit is a **silent EOF**, not an error. A 6 GiB upload is stored as a 5 GiB file and the API returns `201 Created`.
- The configured limit is not applied to `put_file` at all.
- The chunk endpoint accepts up to 5 GiB *per chunk request* although OpenAPI documents 64 KB chunks; combined with offsets up to the max file size this allows large sparse files and disk exhaustion. There is no per-user quota.

**Evidence:** in a scratch copy I shrank the `put_file` limit to 1 KiB and uploaded 5000 bytes → `201 Created`, listing shows `file_size: 1024`. Same mechanism at 5 GiB in the real code.

**Fix**
1. `put_file`: read the limit from config, open with **limit + 1** and fail if exceeded — enforce *while streaming* so an oversized upload stops early instead of writing everything first:
```rust
let max = cfg.max_file_size;                                   // u64
let mut stream = data.open(ByteUnit::Byte(max.saturating_add(1)));
// give ChunkEncryptor::encrypt_stream a `max_bytes: u64` parameter; if total_plaintext_size > max_bytes
// → Err(EncryptionError::TooLarge). Route maps it to 413 and removes the .part file + active_uploads row.
```
2. `upload_chunk`: introduce `max_chunk_request_bytes` (suggest default 32 MiB = 512 chunks, env `JUSTENCRYPT_MAX_CHUNK_BYTES`), `open(max_chunk + 1)`, error if exceeded (413), and reject `offset.checked_add(bytes) > max_file_size`. Validate `offset % CHUNK_SIZE == 0` **before** opening the file and return **400** (today it surfaces as 500 — `test_chunked_upload_invalid_offset` currently asserts 500; update it).
3. Add `RequestError::PayloadTooLarge` → `Status::PayloadTooLarge` (413) in `enums/request_error.rs` and `web/responders.rs`; document 413 in `openapi.yaml`.
4. Optional: per-user quota (`JUSTENCRYPT_USER_QUOTA_BYTES`) checked at init/finalize using the folder totals already maintained by triggers (`folders.total_folder_size` on ROOT).

**Regression tests:** PUT with `max_file_size` set small (config/test override) and body = `max + 1` → 413 and no file/DB entry/`.part` left; body = `max` → 201 and full length stored. Chunk: body larger than `max_chunk` → 413; offset not multiple of 64 KiB → 400.

⚠️ **API change:** new 413 responses; invalid offset becomes 400.

---

<a id="h6"></a>
### H6 — Empty files cannot be downloaded
**Severity:** High (functional; breaks any client that stores an empty file) · **Evidence:** [Reproduced over real HTTP] · **Effort:** S · **WP:** 0/4
- [x] Done in: `5fa0475` on branch `user-session-overhaul` — all three fix steps. `get_file` skips decryption for an empty file; `RangeResponder` sends `Content-Length: 0` for it and `Content-Range` only on 206; `RequestError::RangeNotSatisfiable { total_size }` adds `Content-Range: bytes */<total>` to 416s. Tests in `src/tests/test_file.rs` and `test_chunked_upload.rs`; verified over real HTTP with curl (original: exit 18 `1 bytes missing`; fixed: exit 0). The rest of M11f (suffix and multi-range) is not done.

**Where:** `src/routes/file.rs:439-443` (`(0, total_size.saturating_sub(1), Status::Ok)` → `end = 0` for an empty file) and `src/web/responders.rs:32-39` (`Content-Length = end - start + 1` = 1, `Content-Range: bytes 0-0/0`).

**Problem:** the response advertises 1 byte, streams 0. hyper aborts the response; curl reports `(18) end of response with 1 bytes missing`. (`test_put_file_empty_content` only tests the upload.)

**Fix**
1. In `get_file`: if `total_size == 0` and no `Range` header → return 200 with `Content-Length: 0`, do **not** spawn the decrypt task (drop `tx` so the stream ends immediately). With a `Range` header on an empty file → 416 (already produced by `parse_range` because `start >= total_size`).
2. In `RangeResponder::respond_to`: compute `body_len = if total_size == 0 { 0 } else { end - start + 1 }`, and emit `Content-Range` **only when `status == PartialContent`** (today it is also sent on 200 responses, which is non-standard).
3. For 416, add `Content-Range: bytes */<total>` (make `RequestError::RangeNotSatisfiable` carry `total: u64`).

**Regression test:** PUT empty body; GET → `200`, `Content-Length: 0`, empty body, no `Content-Range`. Over a live server: `curl -sS -o /dev/null http://…/file/empty.txt` exits 0 (see Appendix A.6).

---

## 4. Medium severity

<a id="m1"></a>
### M1 — Server trusts the client's `total_size` at finalize
**Evidence:** [Reproduced] · **Effort:** M · **WP:** 2 (with H4/H5) · **Depends on:** —
- [x] Done in: `283e3fb` on branch `user-session-overhaul`, done together as one change (H4 + H5 + M1). Limits come from Rocket's `Limits` request guard: `file` (`JUSTENCRYPT_LIMITS_FILE`, 64 GiB) and a new `file-chunk` (`JUSTENCRYPT_LIMITS_FILE_CHUNK`, 32 MiB), so tests set per-instance limits with `tests::with_upload_limits` instead of env vars. `written_chunks` is a `BTreeMap<u64, u32>` of plaintext lengths; finalize validates contiguity, full non-final chunks and the exact total, then `ChunkEncryptor::seal` truncates the `.part` file to `encrypted_len(total)`. The encryptor and chunk locks are held from validation through sealing. `add_file` uses `i64::try_from`.

**Where:** `src/routes/file.rs:249` `encryptor.finalize_metadata(total_size)`; `src/db/sqlite.rs:427` `metadata.total_size as i64`; `src/routes/file.rs:199-295` finalize logic.

**Problem:** The stored size is whatever the client says, provided the chunk *count* matches. Upload 10 bytes then finalize with `total_size=65536` → `201`; listing reports `file_size: 65536`; `GET` sends `Content-Length: 65536` but only 10 bytes are decryptable (client hangs/aborts). A `total_size > i64::MAX` wraps negative when cast for SQLite and corrupts the folder aggregates maintained by the triggers. A short chunk in the *middle* of a file (or a re-uploaded shorter last chunk leaving stale bytes) yields a file that fails authentication when read.

**Fix**
1. Track the plaintext length of each written chunk: change `UploadState.written_chunks` from `HashSet<u64>` to `BTreeMap<u64, u32>` (chunk index → plaintext bytes); `encrypt_stream_at_offset` records `bytes_read` per chunk.
2. At finalize, **derive** the size and validate everything:
```rust
fn validate_upload(chunks: &BTreeMap<u64, u32>, claimed_total: u64) -> Result<(), UploadError> {
    let n = chunks.len() as u64;
    if n == 0 { return if claimed_total == 0 { Ok(()) } else { Err(UploadError::Size) }; }
    // contiguous 0..n
    if *chunks.keys().next_back().unwrap() != n - 1 { return Err(UploadError::Missing(first_missing(chunks))); }
    // every chunk but the last must be full-size; last must be 1..=CHUNK_SIZE
    for (i, len) in chunks { if *i != n - 1 && *len as usize != CHUNK_SIZE { return Err(UploadError::ShortChunk(*i)); } }
    let last = *chunks.get(&(n - 1)).unwrap() as u64;
    let actual = (n - 1) * CHUNK_SIZE as u64 + last;
    if actual != claimed_total { return Err(UploadError::Size); }      // 400
    Ok(())
}
```
3. Truncate the `.part` file to the exact expected physical length before sealing it (drops stale bytes after a shortened retry):
```rust
fn encrypted_len(plain: u64) -> u64 {
    let full = plain / CHUNK_SIZE as u64;
    let tail = plain % CHUNK_SIZE as u64;
    full * ENCRYPTED_CHUNK_SIZE as u64 + if tail > 0 { tail + (ENCRYPTED_CHUNK_SIZE - CHUNK_SIZE) as u64 } else { 0 }
}
// file.set_len(encrypted_len(actual)).await?  then flush + sync_all (M9)
```
4. Replace `metadata.total_size as i64` with `i64::try_from(..).map_err(|_| DbError::InvalidInput(..))`.
5. Keep the `total_size` query parameter (API compatibility) but treat it as a **checksum**: mismatch → 400 `total_size does not match uploaded data`.

**Regression tests:** (a) 10 bytes uploaded, finalize `total_size=65536` → 400. (b) Chunk 0 uploaded with only 10 bytes, chunk 1 full, finalize with correct-looking total → 400 (short middle chunk). (c) Re-upload last chunk shorter → file downloads correctly after finalize. (d) `total_size = u64::MAX` → 400/413. (e) Round-trip of multi-chunk + partial-tail file still works (existing `test_chunked_upload_success`).

---

<a id="m2"></a>
### M2 — Overwrite race orphans encrypted blobs
**Evidence:** [Code] · **Effort:** M · **WP:** 3 (fold into the DB-layer refactor)
- [x] Done in: uncommitted changes on branch `user-session-overhaul`, without waiting for A4 (works on the existing `&str` paths). `sqlite::add_file` returns the replaced blob name, read in the same `IMMEDIATE` transaction as the upsert (parent folders are created in that transaction too). The same race existed in `DELETE /file` (read blob name, then delete the row separately), so `sqlite::delete_file` now returns the deleted row's blob via `DELETE ... RETURNING`. Routes no longer read the blob name up front; they remove what the DB call returns, via `remove_blob_and_thumbnail`. Tests: `src/tests/test_db_files.rs` (deterministic) and `test_concurrent_overwrites_leave_exactly_one_blob` in `test_file.rs`, which failed 5/5 on the original code. A route-level test for the delete race could not be made to reproduce (600 attempts over a sweep of timings), so it was not kept; the delete fix is covered by the DB-level tests. Step 4 (orphan GC for blobs already orphaned on deployed instances) is not done.

**Where:** `src/routes/file.rs:316-322` (`put_file` reads `old_encoded_name` *before* the upload) and `:412-418` (deletes it after); the same pattern in `finalize_upload` (`:254-257`, `:286-292`). `sqlite::add_file` (`:373-441`) upserts with `ON CONFLICT DO UPDATE`.

**Problem:** Two concurrent overwrites of the same path both read old blob `X`; both upload (A, B); `add_file(A)` then `add_file(B)`; both delete `X`. Blob `A` is now referenced by nothing and is never reclaimed. There is no GC.

**Fix**
1. Make `add_file` return the **replaced** blob name, read *inside the same `IMMEDIATE` transaction* as the upsert (writers are serialized, so whoever commits second sees the first one's blob as "old"):
```rust
pub fn add_file(db: &mut Connection, path: &VirtualPath, encoded: &str, md: &FileEncryptionMetadata) -> Result<Option<String>, DbError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let parent_id = get_or_create_folder(&tx, &path.parent())?;           // also fixes the separate-transaction issue in M7
    let old: Option<String> = tx.query_row(
        "SELECT encoded_name FROM files WHERE parent_folder_id = ?1 AND name = ?2",
        params![parent_id, path.file_name()], |r| r.get(0)).optional()?;
    tx.execute(/* existing upsert */)?;
    tx.commit()?;
    Ok(old)
}
```
2. Callers delete `old` (blob + thumbnail in `.cache`) **after** a successful `add_file`, and stop calling `get_encoded_file_name` before the upload.
3. Factor the shared "store finished blob" sequence (rename `.part` → final, `add_file`, delete replaced blob + thumbnail, clear `active_uploads` row) into one function used by `put_file` and `finalize_upload` (see A2).
4. Add an orphan GC (see M7) as a safety net.

**Regression test:** with two overlapping overwrites of the same path (spawn both requests, join), after both complete exactly **one** blob file exists on disk for that path (count files under the user's shard dirs, excluding `.cache` and the DB files).

---

<a id="m3"></a>
### M3 — Sessions never expire; logout leaks `.part` files and doesn't clear the cookie
**Evidence:** [Reproduced] · **Effort:** M · **WP:** 1 · **Depends on:** H1 (proper) recommended
- [ ] Done in: _______

**Where:** `src/session/user_session.rs:42` (`created_at` is only used for the admin listing); `src/routes/session.rs:128-136` (cookie); `:175-217` (`destroy_session`); `src/main.rs` (no reaper).

**Problem**
- Server-side sessions live until logout or process exit. The client-side cookie expires after 7 days (Rocket's default `Expires` for private cookies) but the server still honours the token. Five logins → five live sessions. A stolen cookie is valid indefinitely.
- Each live session keeps the user's SQLCipher pool (and derived key material) in memory; the pool is only dropped when the *last* session for that user goes away.
- `destroy_session` doesn't run `cleanup_own_uploads`: an in-flight `.part` file stays on disk until some later login/shutdown (confirmed: `.part` count 1 before and after logout).
- Logout doesn't send a removal cookie, so the browser keeps the (now invalid) cookie.

**Fix**
1. Config (A1): `SESSION_IDLE_TIMEOUT_SECONDS` (suggest 3600), `SESSION_MAX_LIFETIME_SECONDS` (suggest 604800, matching the cookie), `MAX_SESSIONS_PER_USER` (suggest 5; evict the oldest on overflow).
2. Add `last_seen: AtomicU64` to `UserSession`; update it in the `AuthenticatedSession` guard. In the guard, also enforce expiry (defence in depth): expired → remove from the store, 401.
3. Background reaper (Rocket `Fairing` with `Kind::Liftoff` spawning `rocket::tokio::spawn(async move { let mut t = interval(Duration::from_secs(60)); loop { t.tick().await; ... } })`): `store.snapshot()`, for each expired session `store.remove_by_id(..)`, `session.cleanup_own_uploads().await`, and reap stale uploads (H2 helper). Manage `Arc<SessionStore>` so the fairing can clone it.
4. `destroy_session`: call `session.cleanup_own_uploads().await` before removing, then `cookies.remove_private(Cookie::build("sid").path("/"))`.
5. Set an explicit cookie lifetime that matches config: `cookie.set_max_age(time::Duration::seconds(max_lifetime))` (don't rely on Rocket's implicit 1-week `Expires`).
6. Generate the token with 256 bits of OS randomness instead of a UUIDv4 (122 bits): `orion::util::secure_rand_bytes(&mut [0u8; 32])` → base64url (the `base64` crate is already a dependency, currently unused). Optional but cheap.
7. Cookie `Secure` handling is fine (defaults to true via `JUSTENCRYPT_SECURE_COOKIES`).

**Regression tests:** with idle timeout = 1 s (test config), request succeeds, sleep 2 s, request → 401 and session absent from store; logout with an in-flight chunked upload → no `.part` files remain and DB row gone; `Set-Cookie` on logout contains an expired `sid`; 6th login for a user evicts the oldest (`MAX_SESSIONS_PER_USER=5`).

---

<a id="m4"></a>
### M4 — Login hardening: no throttling, enumeration oracles, unvalidated username
**Evidence:** [Reproduced] · **Effort:** L · **WP:** 1
- [ ] Done in: _______

**Where:** `src/routes/session.rs:32-173` (`create_session`); `src/session/user_session.rs:56` (username validation, too late); `src/main.rs` (Rocket config).

**Problems (all reproduced against a live server)**
1. **No rate limiting / lockout.** 25 sequential wrong-password attempts took 2.2 s (~85 ms of SQLCipher KDF CPU each in a debug build); no delay, no 429. Trivially parallelisable brute force, and each attempt burns CPU (DoS lever).
2. **User-enumeration oracle.** With password `a`: initialised user → **401**; non-existent *or* provisioned-but-uninitialised user → **400** (weak-password message). With a strong wrong password: existing user takes ~84 ms, non-existent ~4.5 ms (no KDF runs).
3. **Username used before validation.** The pre-check closure (`:43-88`) builds `PathBuf::from(user_data_path).join(&username).join("<username>.db")` and calls `.exists()` **before** `UserSession::open` validates the name. `PathBuf::join` with an absolute path *replaces* the base, so username `/some/abs/path/x` probes for `/some/abs/path/x.db`: **401 if it exists, 400 if not** — an existence oracle for any `*.db` file the process can stat.
4. **First-login-wins provisioning.** A user "exists" when `user_data/<name>/` exists; whoever logs in first with a strong password sets that account's DB password. Provisioning isn't documented anywhere (see O2).
5. No maximum password/username length (2,000,000-char passwords are accepted, 0.85 s).
6. Rocket's default `ip_header` is `X-Real-IP` (visible in the startup config dump), i.e. `request.client_ip()` trusts a client-supplied header unless a proxy overwrites it — relevant to any IP-based limiter.

**Fix**
1. **Validate at the boundary, first.** Move the username check out of `UserSession::open` into `fn validate_username(&str) -> Result<(), RequestError>` and call it as the very first thing in `create_session`, before any filesystem access. Minimum: keep the existing rule (non-empty, ≤ 64 bytes, none of `/ \ .`, plus reject `\0`); preferred: allow-list `[A-Za-z0-9_-]{1,64}` (check what usernames exist in production first). Also cap password length (e.g. 1–4 KiB → 400) and shrink the JSON body limit for this route (M11).
2. **Uniform failure + equal cost.** Return the same `401` for unknown user, wrong password, and uninitialised user. For unknown users run a *decoy* verification so timing matches: create once at startup an encrypted DB file (e.g. `<user_data>/.decoy.db` — dot-prefixed so it can never collide with a username since `.` is rejected) and call `verify_user_db_password(decoy_path, password)` ignoring the result. **Do not** rely on an in-memory SQLCipher DB — key derivation may not happen for an empty in-memory DB. Verify timing parity with the curl timing loop in Appendix A.7 (existing vs non-existing should be within a few ms).
3. **Provisioning (recommended design).** Add an admin-only `POST /admin/users` `{username, password}` that validates the name, applies the zxcvbn policy, creates `user_data/<name>/` and the DB (running migrations) and returns 201 (409 if it exists). Then `POST /session` never creates anything, the weak-password 400 disappears from the login path (closing oracle #2), and first-login-wins is gone. ⚠️ **API/ops change**: update `perf-test/entrypoint.sh`, README, `openapi.yaml`, and the test helper `create_test_session` (currently relies on `UserSession::open` creating the DB). *If you do not want this change*, at minimum keep first-login init but document it loudly and accept that oracle #2 remains.
4. **Throttling.** Add per-IP and per-username limiters (e.g. the `governor` crate keyed by `IpAddr` and by username) checked *before* the KDF; on limit return `429` with `Retry-After`. Add a global `Semaphore` (≈ number of CPUs) around the blocking KDF so a flood can't exhaust the blocking pool. Add `RequestError::RateLimited { retry_after }`.
5. **`ip_header`.** Set `ip_header: false` in the Rocket config unless deployed behind a trusted reverse proxy that overwrites the header; document the choice (A1/O2).
6. Serialise concurrent logins per username (also fixes M12) with a per-user async mutex map in `AppState`.

**Regression tests:** unknown/uninitialised/wrong-password all return identical status+body; login timing for existing vs unknown user within an agreed tolerance (assert ratio, not absolute); username `/abs/path`, `../x`, `a/b`, `a.b`, NUL, 65 chars → 400 with **no** filesystem `exists()` call (unit-test `validate_username`); 11th attempt in a minute from one IP → 429; password > cap → 400.

---

<a id="m5"></a>
### M5 — Admin API key: empty value accepted, non-constant-time compare
**Evidence:** [Reproduced] · **Effort:** S · **WP:** 1
- [ ] Done in: _______

**Where:** `src/main.rs:322` (`env::var("JUSTENCRYPT_ADMIN_API_KEY").is_ok()` mounts admin routes — true for an **empty** value); `src/web/forwarding_guards.rs:37-46` (`key == api_key`, env re-read on every request).

**Problem:** `JUSTENCRYPT_ADMIN_API_KEY=` (set but empty) mounts the admin API and an empty `X-Admin-Api-Key:` header authenticates: `GET /admin/session` returned `200` with usernames, session ids and the file paths of in-flight uploads. `==` on strings is not constant-time. No minimum key strength, no failed-attempt throttling, and if the env var is somehow missing the guard returns 500.

**Fix**
1. At startup: `let admin_key = env::var(..).ok().filter(|k| !k.is_empty())`; if `Some(k)` and `k.len() < 32` → **refuse to start** with a clear message; if `None` → don't mount admin routes (as today, but also for empty).
2. Store it in managed state (`AdminConfig { key: SecretString }`) — no per-request `env::var`.
3. Compare in constant time with `orion::util::secure_cmp(provided.as_bytes(), expected.as_bytes()).is_ok()` (already a dependency; returns `Err` on mismatch/length mismatch).
4. Missing config → `404`/`401`, not `500`. Feed failed attempts into the login limiter from M4.
5. Consider redacting `file_path` in the admin session listing (it exposes user file names).

**Regression tests:** empty key → admin routes 404 and startup with a 10-char key fails; correct key succeeds; wrong/empty header → 401; (unit) `secure_cmp` path used.

---

<a id="m6"></a>
### M6 — Secrets committed to git / defaults baked into code and images
**Evidence:** [Code] + git history · **Effort:** S · **WP:** 0
- [ ] Done in: _______

**Where / what**
- `env/justencrypt.env` is **tracked** and has `JUSTENCRYPT_ROCKET_SECRET_KEY=cEf+JLu6…` **uncommented**.
- `src/main.rs:94-98` hard-codes a fallback key (`ept8SXw6…`) for debug builds; the same key is baked into `Dockerfile.perf`.
- Git history contains at least three different secret-key values (`frTlv9S0…`, `cEf+JLu6…`, `ept8SXw6…`).
- README step 2 says `cp env/justencrypt.env.example env/justencrypt.env` — the `.example` file does not exist, so users will run with the committed file as-is.

**Impact note:** session tokens are random and looked up server-side, so the key alone cannot forge a session; it does defeat cookie confidentiality and integrity if used in production.

**Fix**
1. **Rotate**: treat any key that ever ran on a real deployment as compromised; generate new ones (`openssl rand -base64 32`) and restart (all sessions are invalidated — acceptable).
2. Replace the value in `env/justencrypt.env` with a placeholder and comment it out; create `env/justencrypt.env.example` (or fix the README to say copy `justencrypt.env`).
3. Remove the hard-coded fallback in `get_required_env_var`. **Rocket already generates a random secret key in the debug profile** when the `secrets` feature is on and none is configured (verified in `rocket-0.5.1/src/config/secret_key.rs` docs), so the fallback is unnecessary. Keep the release-mode "must be set" panic.
4. `Dockerfile.perf`: delete the baked `ENV JUSTENCRYPT_ROCKET_SECRET_KEY`; generate one in `perf-test/entrypoint.sh` (`export JUSTENCRYPT_ROCKET_SECRET_KEY=$(head -c32 /dev/urandom | base64)`).
5. Optional: refuse to start if the configured key equals a known-leaked value (compare SHA-256 digests so the raw keys aren't re-committed); add secret scanning (gitleaks/trufflehog) to CI. Rewriting git history is optional — rotation is what matters.

**Acceptance criteria:** no live secret in the working tree or Dockerfiles; app starts in debug without any key; release start without a key fails with a clear error.

---

<a id="m7"></a>
### M7 — Non-atomic multi-step operations
**Evidence:** [Reproduced for root-delete; rest Code] · **Effort:** L · **WP:** 3 · **Depends on:** A4 (recommended)
- [ ] Done in: _______
- **Partial progress (M2 change, uncommitted):** item 4 is fixed (`add_file` creates parent folders in the same transaction as the upsert), and item 6 is fixed (`DELETE /file` returns 204 when the row is deleted even if the blob was already missing; a missing file, including one in a missing folder, returns 404 instead of the previous 404/400 split).

**Problems**
1. `DELETE /folder/` (root): the handler walks the tree, deletes every file/blob and child folder, and only then fails on the root row (trigger `prevent_root_folder_delete`) → user data wiped **and** `500` returned. *(Reproduced.)*
2. `routes/folder.rs:56-169` `delete_folder`: iterative traversal in the route; two `spawn_blocking` round-trips per folder and **one transaction per file** (`delete_file_by_id`); every failure is only `warn!`-ed and processing continues; blobs are deleted *before* their DB rows, so a failure leaves rows pointing at missing blobs. The final `session.delete_folder(path)` re-resolves the path (TOCTOU with a concurrent rename).
3. `patch_file` / `patch_folder` do rename then move as two independent operations; if the move fails the rename is not rolled back.
4. `sqlite::add_file` creates parent folders in its own committed transaction, then upserts in another.
5. `finalize_upload`: on `add_file` failure or rename failure the `active_uploads` DB row isn't removed; rename-before-commit is the right order (crash → orphan blob, not dangling row) but there is no GC for orphans.
6. `delete_file` deletes the DB row first (good) then returns `500 FailedToRemoveFile` if the blob is already missing, making DELETE non-idempotent.

**Fix**
1. One DB function does the whole folder delete in **one** transaction and returns the blob names to remove:
```rust
pub fn delete_folder_tree(db: &mut Connection, path: &VirtualPath) -> Result<Vec<String>, DbError> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let id = get_folder_id(&tx, path)?.ok_or(DbError::NotFound)?;
    if id == ROOT_FOLDER_ID { return Err(DbError::InvalidInput("Cannot delete the root folder".into())); }   // reject up front → 400
    // subtree, deepest first so FK (no ON DELETE CASCADE) is satisfied
    let ids: Vec<i64> = /* WITH RECURSIVE sub(id, depth) AS (SELECT ?1, 0 UNION SELECT f.id, sub.depth+1 FROM folders f JOIN sub ON f.parent_folder_id = sub.id)
                           SELECT id FROM sub ORDER BY depth DESC */;
    let mut blobs = Vec::new();
    for fid in &ids {
        /* collect SELECT encoded_name FROM files WHERE parent_folder_id = fid → blobs */
        /* DELETE FROM files WHERE parent_folder_id = fid; DELETE FROM folders WHERE id = fid; */
    }
    tx.commit()?;
    Ok(blobs)
}
```
   The route then removes blobs and cached thumbnails **after commit**, best-effort (log failures; the GC below reclaims leftovers) and returns 204. Decide the root semantics explicitly: recommended is `DELETE /folder/` → 400 "Cannot delete the root folder" (document it).
2. Single DB function for `PATCH` that applies rename + move atomically (see M8).
3. `add_file` creates parents inside its own single transaction (see M2).
4. Ensure every early-return path in `put_file`/`finalize_upload` clears the `active_uploads` row (a small `struct UploadGuard` with `Drop`-less explicit `abort()`/`complete()` methods makes this hard to forget).
5. `delete_file`: treat `ErrorKind::NotFound` on blob/thumbnail removal as success; after the DB row is gone return 204 even if the blob removal fails (log it).
6. **Orphan GC** (new): `UserSession::gc_orphans()` lists blobs under the shard directories (`xx/yy/<uuid>` and `.cache`) that are not in `files.encoded_name` and not in `active_uploads`, older than a safety window (e.g. 1 h, by mtime, to avoid racing an in-flight finalize), and deletes them. Run at login and from the reaper (M3). Also removes stale `.part` files.

**Regression tests:** delete a tree with N files → exactly one transaction (assert via a counter or by checking atomicity: inject a failure and verify nothing was deleted); `DELETE /folder/` → 400 and data intact; DELETE of a file whose blob was manually removed → 204; GC removes a manually-created orphan blob older than the window and keeps one newer than it.

---

<a id="m8"></a>
### M8 — `PATCH` validation and semantics
**Evidence:** [Reproduced] · **Effort:** M · **WP:** 3
- [ ] Done in: _______

**Where:** `src/db/sqlite.rs:812-860` (`rename_file`), `:862-909` (`move_file`), `:726-760` (`rename_folder`); `src/routes/file.rs:512-539`; `src/routes/folder.rs:171-198`.

**Observed behavior**
| Request | Actual | Should be |
|---|---|---|
| Rename nonexistent file | `204` (0 rows updated, ignored) | `404` |
| Move nonexistent file to `auto/created/dir` | `204` **and the destination folders are created** | `404`, nothing created |
| Rename file onto an existing name | `500` (UNIQUE violation) | `409` |
| Rename file to `evil/name.txt` | `204`; entry appears in listing but `GET /file/evil/name.txt` and `GET /file/x.txt` are both `404` (unreachable) | `400` |
| Rename file to `""` | `204` | `400` |
| Rename folder to `..` / `.` | accepted (`rename_folder` only rejects empty and `/`); path resolution skips `..`, so it's unreachable | `400` |

**Fix**
1. One shared validator, used by DB functions **and** JSON deserialization of `file_name`/`folder_name`:
```rust
pub fn validate_name(name: &str) -> Result<(), DbError> {
    // non-empty, ≤255 bytes, not "." or "..", no '/', '\\', NUL or other control characters
}
```
2. Check rows affected: `let n = tx.execute(...)?; if n == 0 { return Err(DbError::NotFound) }`.
3. Add `DbError::Conflict` / `RequestError::Conflict` (409). Map `rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation` on the rename/move/add paths to it. Also check sibling collisions for folder rename/move explicitly (UNIQUE `(parent_folder_id, name)` on `folders`).
4. Combine rename+move into one transaction: `update_file(path, new_name: Option<&str>, dest: Option<&VirtualPath>)` — verify the source exists **first**, then create the destination, then update.
5. `#[serde(deny_unknown_fields)]` on `PatchFileData`/`PatchFolderData`; `{}` (no fields) → 400.
6. Update `openapi.yaml` (add 409; PATCH on a missing file really returns 404).

**Regression tests:** one per row in the table above (assert status *and* that nothing was created/renamed).

⚠️ **API change:** 404/409/400 where 204/500 were returned.

---

<a id="m9"></a>
### M9 — No flush/fsync on writes; non-atomic thumbnail cache writes
**Evidence:** [Code] (+ tokio docs) · **Effort:** M · **WP:** 2
- [ ] Done in: _______
- **Partial progress (`61518e3`, `user-session-overhaul`):** `ChunkEncryptor::encrypt_stream_at_offset` and `encrypt_stream` now call `self.file.flush().await?` before returning. This fixed the intermittent `test_encrypt_stream_at_offset` failure (it was failing ~3/30 runs on the original code, more under load; 0/40 after). Still open: `sync_all` before sealing the `.part` file, and the atomic thumbnail-cache writes.

**Where:** `src/encryption/chunk_encryptor.rs:106,165` (`write_all` with no flush/sync); `src/routes/thumbnail.rs:86` (`exists()` check) and `:124-140` (writes at the final path via `ChunkEncryptor::new_with_metadata`, which opens with `truncate(true)`).

**Problems**
1. `tokio::fs::File` buffers writes; the tokio docs say to call `flush` before dropping, and errors of the last write are otherwise lost (returned on the *next* write/flush that never comes). The file is then renamed, recorded in the DB and `201` is returned — with no durability guarantee (`sync_all` never called).
2. Thumbnails: two concurrent requests for the same thumbnail both see `!exists()` and both open the final path with `truncate(true)` → interleaved writes/corruption. A crash or an encryption error mid-write leaves a partial file at the final path that later passes the `exists()` check, so that thumbnail returns 500 forever (until the source file is replaced).

**Fix**
1. Add `ChunkEncryptor::finish(self) -> io::Result<()>` that does `file.flush().await?; file.sync_all().await?;` and call it at the end of `encrypt_stream`/before the rename in `put_file`; in the chunked path `flush()` after each chunk request and `sync_all()` at finalize (after `set_len`, see M1). Optionally fsync the parent directory after rename.
2. Thumbnails: write to a unique temp name in the same directory (`<final>.tmp.<uuid>`), `finish()`, then `fs::rename` to the final path (atomic on the same filesystem). Concurrent generators each produce a valid file; the last rename wins. Clean up the temp file on error.
3. Self-heal: if decrypting a cached thumbnail fails, delete the cache entry and regenerate once instead of returning 500.
4. Drop the `if !cache_path.exists()` check — `create_dir_all` is idempotent (and `exists()` is a blocking call inside async code, as are the other `path.exists()` calls in `delete_file`, `delete_folder`, `cleanup_*`; use `tokio::fs::try_exists`).

**Regression tests:** simulate a failing writer (e.g. a reader that errors midway) and assert no file appears at the final thumbnail path; concurrent thumbnail requests (spawn 8) all return identical valid bodies; corrupt a cached thumbnail on disk → next request regenerates and returns 200.

---

<a id="m10"></a>
### M10 — Vulnerable/unmaintained dependencies; `Cargo.lock` is gitignored
**Evidence:** [Reproduced with `cargo audit` 0.22.2, advisory DB fetched 2026-09-23, against the local `Cargo.lock` dated Jul 30] · **Effort:** S · **WP:** 0
- [ ] Done in: _______

**Findings (7 vulnerabilities)**
| Crate | Advisory | Origin | Action |
|---|---|---|---|
| `time 0.3.44` | RUSTSEC-2026-0009 (DoS, stack exhaustion; CVSS 6.8) | `cookie` ← Rocket | `cargo update -p time` (→ 0.3.55 in dry run) |
| `bytes 1.10.1` | RUSTSEC-2026-0007 (integer overflow in `BytesMut::reserve`) | `h2`/`http`/… | `cargo update -p bytes` (→ ≥ 1.11.1) |
| `crossbeam-epoch 0.9.18` | RUSTSEC-2026-0204 (invalid pointer deref) | `rayon-core` ← `image` | `cargo update -p crossbeam-epoch` (→ ≥ 0.9.20) |
| `h2 0.3.27` | RUSTSEC-2026-0258 (unbounded empty DATA frames — HTTP/2 DoS); **no patch on the 0.3 line** | `hyper 0.14` ← Rocket 0.5.1 | Drop the `http2` feature (see below) or track Rocket 0.6 |
| `rustls-webpki 0.101.7` | RUSTSEC-2026-0104, -0099, -0098 (CRL parsing panic; name-constraint bugs) | `rustls 0.21` ← Rocket `tls` feature | Certificate *verification* paths — likely unreachable for server-only TLS; can't be bumped without Rocket 0.6. Terminate TLS at a reverse proxy and drop `tls`, or accept and document |

Unmaintained/unsound warnings: `dotenv 0.15.0` (RUSTSEC-2021-0141), `paste`, `rustls-pemfile`, `anyhow` (unsound `downcast_mut`), `rand 0.8.5/0.9.2` (unsound with custom logger), `spin` (yanked).

**Fix**
1. `cargo update -p time -p bytes -p crossbeam-epoch`; run tests.
2. **Commit `Cargo.lock`** (remove it from `.gitignore`, `git add Cargo.lock`). This is a binary crate; without the lockfile the Docker/CI build (`COPY . .` from a clean checkout) resolves fresh versions each time — unpinned and unauditable — and `Dockerfile.perf` (`COPY Cargo.toml Cargo.lock ./`) fails on a clean checkout.
3. Rocket features: `rocket = { version = "0.5.1", default-features = false, features = ["json", "secrets", "tls"] }` removes the default `http2` feature and therefore `h2`. After the change verify `cargo tree -i h2` no longer lists it and that HTTP/1.1 serving still works (the app normally sits behind a proxy). If you terminate TLS at the proxy, also drop `"tls"` to remove `rustls`/`rustls-webpki`.
4. Replace `dotenv` with `dotenvy` (drop-in: `dotenvy::dotenv().ok()`), and update `src/tests/mod.rs`.
5. Remove unused direct dependencies `base64` and `serde_json` (or use `base64` for the M3 token encoding), and `extern crate serde;`.
6. Add to CI (`.onedev-buildspec.yml` currently only builds the Docker image): `cargo audit` (fail on vulnerabilities), optionally `cargo deny`.

**Acceptance criteria:** `cargo audit` reports 0 vulnerabilities from crates you can fix; lockfile committed; CI runs audit.

---

<a id="m11"></a>
### M11 — HTTP/API hardening and consistency
**Evidence:** [Reproduced against a live server] · **Effort:** L · **WP:** 4 · ⚠️ some **API changes**
- [ ] Done in: _______

Split into independent sub-tasks; tick as you go.

- [ ] **M11a — Response headers.** Add a fairing (or extend `Cors`) that sets `Cache-Control: no-store` on all authenticated responses (currently decrypted downloads and thumbnails have none), `Referrer-Policy: no-referrer`, and set Rocket `ident = false` to drop `Server: Rocket`. HSTS is already emitted by Shield.
- [ ] **M11b — CORS (`src/web/fairings.rs`).** Currently: `Access-Control-Allow-Credentials: true` is always sent (even with no origin configured); `Access-Control-Request-Methods` is a *request* header and is bogus in a response; `Allow` is added to every response; every `OPTIONS` response is rewritten to `200` (even for unknown paths such as `OPTIONS /does/not/exist`); `Access-Control-Expose-Headers` is missing so browser JS can't read `Content-Range`/`Content-Length`/`Accept-Ranges`; no `Access-Control-Max-Age`; no `Vary: Origin`. Fix: only emit ACAO/ACAC when `ALLOW_ORIGIN` is configured **and** the request `Origin` matches exactly (echo it and add `Vary: Origin`); never combine `*` with credentials (reject that config at startup); add `Access-Control-Expose-Headers: Content-Range, Content-Length, Accept-Ranges`, `Access-Control-Max-Age: 600`; don't override the status of non-preflight `OPTIONS`. (`rocket_cors` is an alternative.) Note the admin header `X-Admin-Api-Key` is intentionally not CORS-allowed.
- [ ] **M11c — Uniform JSON error contract.** Today: guard/framework errors (401, 404, 400 malformed JSON, 422 missing field) return **HTML** (Rocket default catchers); route errors return plain text with **no `Content-Type`**; a wrong `Content-Type` on `POST /session` yields **404** (route `format = "json"` mismatch). Implement `Responder for RequestError` returning `Content-Type: application/json` with `{"error":{"code":"not_found","message":"..."}}`, and register catchers for 400/401/404/405/413/415/422/429/500 that produce the same shape. Prefer 415 for wrong content type (drop `format = "json"` and validate in the handler, or add a small guard). Document in `openapi.yaml`.
- [ ] **M11d — Request limits.** The global `json` limit is 10 MiB (login/PATCH bodies should be ≤ 16–64 KiB); `form`, `data-form`, `bytes`, `string`, `msgpack` limits are irrelevant to this API — lower or remove them. No per-request read timeouts exist for slow-body clients (consider a `tokio::time::timeout` around body reads, or rely on the reverse proxy and document it).
- [ ] **M11e — Status semantics** ⚠️. `PUT /file/<path>` returns `201` even when replacing an existing file → `201` if created, `204` (or `200`) if replaced; `PUT /folder/<path>` on an existing folder returns `201` → `200/204`. Needs `add_file` (M2) and `get_or_create_folder` to report whether they created something.
- [ ] **M11f — Ranges (`src/util/range.rs`).** `Range: bytes=-N` (suffix) → currently `400 Invalid range start`; implement (`start = total.saturating_sub(N)`, `N == 0` → 416). Multi-range (`bytes=0-1,5-6`) → currently `400`; RFC 9110 lets a server ignore `Range` and send `200` full content (do that). `Content-Range` only on `206`; 416 carries `Content-Range: bytes */total`.
- [ ] **M11g — Timestamps.** SQLite `CURRENT_TIMESTAMP` values are emitted as `2026-09-23 17:58:05` (UTC, no zone marker) while `openapi.yaml` declares `format: date-time`. Convert at read time in `get_folder` (`replace(' ', "T") + "Z"`) — no schema change needed. `ActiveFileUpload.last_updated` serialises a Rust `SystemTime` as `{"secs_since_epoch":…,"nanos_since_epoch":…}` while `created_at` is epoch seconds — make it consistent (epoch seconds or RFC 3339).
- [ ] **M11h — `openapi.yaml` drift.** Fix: chunk size description ("64KB chunk" vs. actual limit), PATCH "404 File not found" (currently 204 — fixed by M8), `OPTIONS` documented as 204 but currently 200 (fixed by M11b), add 409/413/415/429 where applicable, document error body schema, document the `total_size` validation (M1).
- [ ] **M11i — CSRF defence in depth (optional).** `SameSite=Strict` is the only CSRF control (adequate for same-site deployments). Optionally reject state-changing requests whose `Origin` (if present) doesn't match the configured origin.
- [ ] **M11j — Reserved namespace.** Files under `upload/initiate/…`, `upload/chunk/<id>` and `upload/finalize/<id>` collide with the upload routes because they share `/file/<path..>` *[Code, reasoned]*. Either document the reserved prefix or move upload routes to `/upload/...`. ⚠️ API change if moved.
- [ ] **M11k — Listing.** `GET /folder/<path>` returns everything with no `ORDER BY` and no pagination; add a deterministic order (folders first, then name) and `limit`/`cursor` query parameters. ⚠️ API addition.

---

<a id="m12"></a>
### M12 — First-login race: concurrent migrations collide; error is masked
**Evidence:** [Reproduced in server log] · **Effort:** S · **WP:** 1
- [ ] Done in: _______

**Where:** `src/db/sqlite.rs:83-106` (`create_user_db_connection`): opens the DB, verifies the key, runs `migrations::get_migrations().to_latest(&mut conn)`; on failure returns `DbError::Rusqlite(rusqlite::Error::QueryReturnedNoRows)` (`:99-103`).

**Problem:** four simultaneous first logins for the same new user each read `user_version = 0`, and later ones re-run the migration after the first committed → `trigger files_after_insert already exists`. The real error is replaced by a fake `QueryReturnedNoRows`, `create_session` turns it into `401`, and the log gets an `error!` containing the entire ~8 KB migration SQL. A legitimate user (e.g. a client that fires parallel requests at first login) gets a spurious 401.

**Fix**
1. Serialise per-username initialisation: `AppState.login_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>` (or a `DashMap`); hold the user's async mutex around `UserSession::open`. (Shared with M4 item 6.)
2. Add `DbError::Migration(String)` and return it instead of `QueryReturnedNoRows`; log a short message (`error!("Migration failed for user {}", …)`) and put the detail at `debug!`; never log the SQL text.
3. Optionally make migration idempotent-safe by wrapping in `BEGIN IMMEDIATE` — but the lock in (1) is sufficient in-process.

**Regression test:** spawn 8 concurrent `UserSession::open` calls for a brand-new user directory; all must succeed (or all return the same clean result) and none may log a migration error.

---

<a id="m13"></a>
### M13 — Thumbnail decode has no resource limits
**Evidence:** [Code] · **Effort:** S · **WP:** 2
- [ ] Done in: _______

**Where:** `src/routes/thumbnail.rs:97-113` (`image::load(buf_reader, image_format)`); `src/main.rs:265` (`semaphore_tickets = workers * 7 / 10` ≈ 11).

**Problem:** the `image` crate's default `Limits` are `max_alloc = 512 MiB` and no dimension limits (`image` 0.25.x, `src/io/limits.rs`; your lockfile resolves 0.25.8). Up to ~11 concurrent decodes ⇒ up to ~5.6 GiB from decompression-bomb images. The format is chosen from the **file name extension**, not the content.

**Fix**
```rust
let mut reader = image::ImageReader::with_format(buf_reader, image_format);
let mut limits = image::Limits::default();
limits.max_image_width = Some(16_384);
limits.max_image_height = Some(16_384);
limits.max_alloc = Some(128 * 1024 * 1024);        // tune
reader.limits(limits);                             // NB: takes &mut self in 0.25
let img = reader.decode()?;
```
Also: verify the content with `image::guess_format` against the extension (mismatch → 415); return the proper `Content-Type` for the thumbnail (currently `application/octet-stream` because the handler returns `Vec<u8>`); make the semaphore size configurable independently from `workers`.

**Regression test:** a PNG with huge declared dimensions (e.g. 60000×60000, tiny compressed size) → 415/422, not an OOM; a normal image still yields a thumbnail.

---

## 5. Architecture / code quality

<a id="a1"></a>
### A1 — Typed, validated `Config`
**Effort:** L · **WP:** 5 · **Unblocks:** limits/TTLs in H2, H4, H5, M3, M4, M5
- [ ] Done in: _______

**Problem**
- 37 `env::var` call sites reading 32 variables, spread over `main.rs`, `routes/*`, `session/user_session.rs`, `db/sqlite.rs`, `web/*` (some re-read **per request**, e.g. `AdminGuard`, `Cors`, `init_upload`, `upload_chunk`; `JUSTENCRYPT_USER_DATA_PATH` and `..._DB_BUSY_TIMEOUT_MS` are read in two places each).
- Values are parsed ad hoc with silent fallbacks (`.parse().unwrap_or(default)`) or `.unwrap()` panics without a message (8 in `main.rs`, the `LIMITS_*` group).
- **Defaults disagree between code, README and `env/justencrypt.env`:**

| Variable | Code default | README / env file |
|---|---|---|
| `JUSTENCRYPT_MAX_DB_CONNECTIONS_PER_USER` | **16** (`sqlite.rs:148-151`) | 2 |
| `JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE` | **4** (`routes/session.rs:53-55`; invalid → 4, >4 → 3) | 3 |
| `JUSTENCRYPT_MAX_ACTIVE_UPLOADS` | unlimited if unset; **per session**, not global | README "(none)", env file "100" |

  (Each pooled connection uses `cache_size = 16000 KB`, so 16 connections/user is up to ~256 MB per active user.)
- PRAGMA values are `format!`-ed into SQL (`sqlite.rs:135-138`): `synchronous`, `temp_store` are arbitrary strings; `cache_size = -{}` with a negative input becomes `--…` (a SQL comment). Operator-controlled, but fragile.

**Fix**
1. New `src/config.rs`:
```rust
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default = "d_user_data")] pub user_data_path: PathBuf,
    #[serde(default = "d_3")]        pub minimum_password_security_score: u8,   // validate 0..=4 at startup
    #[serde(default)]                pub db: DbConfig,          // busy_timeout_ms, cache_size_kb: u32, synchronous: SyncMode, temp_store: TempStore, ...
    #[serde(default = "d_64gib")]    pub limits_file: ByteUnitStr,             // or parse into u64 bytes
    #[serde(default)]                pub session_idle_timeout_seconds: u64,     // M3
    pub max_active_uploads: Option<usize>,
    pub allow_origin: Option<String>,
    pub secure_cookies: bool,
    pub admin_api_key: Option<SecretString>,                                      // M5
    // ...
}
```
   Build it with Rocket's re-exported figment: `Figment::from(Serialized::defaults(AppConfig::default())).merge(Env::prefixed("JUSTENCRYPT_"))` and `extract()`; **fail fast at startup with a readable error** on any invalid value (no silent fallback).
2. `enum SyncMode {Off, Normal, Full, Extra}` and `enum TempStore {Default, File, Memory}` with `fn as_sql(&self) -> &'static str`; `cache_size_kb: u32` (rendered as `-{n}` by code, never from user text).
3. Store as `Arc<AppConfig>` in managed state and in `AppState`; pass `&AppConfig`/`&DbConfig` into `UserSession::open`, `create_user_db_connection`, guards. Only `main` calls `dotenv`.
4. **Decide the canonical default for each drifted variable** (suggestion: pool max 4, password score 3 unless 4 was intentional) and make code, `README.md` and `env/justencrypt.env` agree.
5. Tests build `AppConfig::for_tests(user_data_dir)` — removes all 6 `env::set_var` calls (process-global and racy across parallel tests).
6. **Interim (if A1 isn't done yet):** add `src/util/limits.rs` with `fn max_file_size() -> u64` reading the env var once via `OnceLock`, so H4/H5 don't need to wait.

**Acceptance criteria:** `grep -rn "env::var" src/` finds only `config.rs`/`main.rs` startup code; an invalid value stops the server with a clear message; README table generated from (or checked against) the struct defaults.

---

<a id="a2"></a>
### A2 — Layering: db↔session cycle; business logic in routes
**Effort:** M · **WP:** 3
- [ ] Done in: _______

**Problems**
- `src/db/sqlite.rs:13` imports `session::user_session::EncodedFile` while `session` imports `db` — a module cycle. Move `EncodedFile` (and `FolderContent`/`File`/`Folder`) into `db/models.rs`.
- Multi-step business logic lives in handlers: `delete_folder` traversal (`routes/folder.rs`), the "finish an upload" sequence (rename `.part` → final, `add_file`, delete replaced blob + thumbnail, clear active-upload row) copy-pasted in `put_file` and `finalize_upload`, and the blob+thumbnail deletion in `delete_file`/`delete_folder`.

**Fix:** introduce `src/services/` (`files.rs`, `folders.rs`, `uploads.rs`) that own these sequences and are called by thin routes (parse → call service → map error). Suggested layout (do it incrementally, no big-bang):
```
src/config.rs                    (A1)
src/lib.rs + src/main.rs         (T1)
src/db/{mod,migrations,models,connection,files,folders,uploads}.rs   (split the 1,082-line sqlite.rs)
src/services/{files,folders,uploads}.rs
src/session/{store,user_session}.rs
src/http/{guards,responders,fairings,errors}.rs                       (today: web/)
src/util/virtual_path.rs         (A4)
```
Also: `get_sharded_path` is `async` with no `.await` and takes `&String` (clippy `unused_async`/`ptr_arg`) — make it a sync `fn(&Path, &str) -> PathBuf` and drop `.await` at ~15 call sites; same for `ChunkDecryptor::new`.

---

<a id="a3"></a>
### A3 — `UserSession` is ~18 identical wrappers; duplicated cleanup functions
**Effort:** M · **WP:** 3
- [ ] Done in: _______

**Problem:** `src/session/user_session.rs` (586 lines) has 22 `pub async fn`s of which ~18 are the same shape — clone args, `with_db(move |db| sqlite::foo(&db, path.to_str().ok_or(InvalidPath)?))`, plus `trace!` boilerplate. `rename_file` (`:534-560`) bypasses `with_db`. `cleanup_orphaned_uploads` (`:175-207`) and `cleanup_own_uploads` (`:209-238`) are copy-pastes differing by one predicate. `to_str().ok_or(DbError::InvalidPath)` appears 11×.

**Fix**
1. Make the helper public and delete the wrappers:
```rust
impl UserSession {
    pub async fn db<F, R>(&self, f: F) -> Result<R, DbError>
    where F: FnOnce(&mut Connection) -> Result<R, DbError> + Send + 'static, R: Send + 'static { /* spawn_blocking + pool.get() */ }
}
// call sites: session.db(move |c| sqlite::get_folder(c, &path)).await?
```
2. One `async fn cleanup_uploads(&self, should_clean: impl Fn(&str /*session_id*/) -> bool)`; `cleanup_orphaned_uploads`/`cleanup_own_uploads` become one-line callers. Use `part_path()` helper (also used in H2) and `tokio::fs::try_exists`.
3. Take `&VirtualPath` (A4) instead of `PathBuf` so the `to_str()` conversions disappear.

---

<a id="a4"></a>
### A4 — `VirtualPath`: parse and validate once at the boundary
**Effort:** M · **WP:** 3 (do **first** in the package) · **Enables:** H3 (layer 1 becomes trivial), M8
- [ ] Done in: _______

**Problem:** paths travel as `PathBuf` and each DB function re-parses `Path::new(x.trim_matches('/'))` + `Component` matching (11 repeats; `file_name().ok_or(MissingFileName)` 11×). `UnrestrictedPath` (`util/unrestricted_path.rs`) claims to "sanitize" but only joins segments; `.`/`..`/empty components are silently *skipped* deep inside `get_folder_id`, which is exactly what made H3 possible. There are no length or depth limits (a 30k-deep path makes every trigger and lookup O(depth)).

**Fix**
```rust
// src/util/virtual_path.rs
pub struct VirtualPath(Vec<String>);          // normalised components, no empties
impl VirtualPath {
    pub const MAX_DEPTH: usize = 32;
    pub const MAX_COMPONENT_BYTES: usize = 255;
    pub fn parse(raw: &str) -> Result<Self, PathError>;   // split '/', skip empty segments, REJECT "." and "..", NUL/control chars, over-long components, depth > MAX_DEPTH
    pub fn components(&self) -> &[String];
    pub fn file_name(&self) -> Option<&str>;
    pub fn parent(&self) -> VirtualPath;
    pub fn is_root(&self) -> bool;
}
impl<'r> FromSegments<'r> for VirtualPath { /* replaces UnrestrictedPath; keeps dotfiles like ".gitignore" legal; errors → 400 */ }
impl<'de> Deserialize<'de> for VirtualPath { /* for parent_folder_path etc., same rules */ }
impl Display for VirtualPath { /* "a/b/c" */ }
```
Replace `PathBuf`/`&str` path parameters in `db::*`, `UserSession`, routes. Delete the `Path::new/trim_matches/Component` blocks. Property-test it (T2): random strings never produce a path containing `.`/`..`/empty components; `parse(display(p)) == p`.

⚠️ **Behavior change:** requests containing `.`/`..` segments now fail with 400 instead of being silently normalised.

---

<a id="a5"></a>
### A5 — Encryption module cleanup
**Effort:** M · **WP:** 2/3
- [ ] Done in: _______

- **Duplicate loops.** `encrypt_stream` and `encrypt_stream_at_offset` (`chunk_encryptor.rs:51-182`) duplicate ~40 lines. Extract one `write_chunks(source, start_index, max_bytes, on_chunk)`; `encrypt_stream` = start at 0.
- **Extra copy on upload.** Read directly into `indexed_plaintext[8..]` instead of `plaintext_buffer` then `copy_from_slice`.
- **Three copies per 64 KiB chunk on download** (`chunk_decryptor.rs:80,145`: `decrypted_payload[8..].to_vec()` then `final_slice.to_vec()` for the mpsc channel). Strip the index in place (`payload.drain(..8)` / `split_off`) and send the same `Vec`; consider `bytes::Bytes` slices.
- **Silent truncation on read.** `decrypt_range` `break`s on EOF and returns `Ok(())` (`:117`); if fewer bytes were sent than promised, log an error and make the stream fail so the connection aborts visibly (today hyper aborts only because `Content-Length` was already sent).
- **`unwrap`s that panic on corrupt data:** `SecretKey::from_slice(&key_blob).unwrap()` at `sqlite.rs:529` and `:583` → map to `rusqlite::Error::FromSqlConversionFailure`. `FileEncryptionMetadata::clone` (`encryption/mod.rs:26-34`) re-creates the key with `unwrap()`; hold the key in `Arc<SecretKey>` instead of cloning key material per request.
- **Serialised chunk uploads.** `upload_chunk` holds `encryptor.lock()` **and** `written_chunks.lock()` for the whole request body read (`file.rs:183-188`), so chunks of one upload are strictly sequential and a slow client blocks `finalize`. Optional improvement: keep the file as `Arc<std::fs::File>` and write each encrypted chunk with `FileExt::write_all_at` inside `spawn_blocking`, locking only the chunk map briefly.
- **Format versioning.** `encryption_version` is stored per file but never checked on read; reject unknown versions explicitly (500 + log) instead of attempting to decrypt. If you ever change the on-disk format (e.g. add a header/final-chunk marker to detect truncation at chunk boundaries), bump the version and keep the v1 reader — do **not** silently change v1.
- **Naming.** `pub use orion::kex::SecretKey` is the same type as `orion::aead::SecretKey`; import it from `aead` for clarity.
- **Defence in depth (optional).** `PRAGMA secure_delete = ON` so deleted key rows are overwritten in the DB file.

---

<a id="a6"></a>
### A6 — Logging
**Effort:** S · **WP:** 5
- [ ] Done in: _______

**Problems:** 223 `trace!` lines in non-test code (~5% of LOC), 60 of them pure `"Entering …"/"Exiting …"` and ~18 `"Inside spawn_blocking for …"`; trace logs include user file/folder names and paths (metadata leak if someone enables `Trace`); migration errors dump the full SQL (M12); `error!` on expected conditions like wrong password (`sqlite.rs:35,92`).

**Fix:** delete the Entering/Exiting/Inside-spawn_blocking lines (they add no information); if you want flow tracing, use `tracing` with `#[tracing::instrument(skip_all, fields(user = %session.username))]` (+ `tracing-log` to keep Rocket's `log` output) — never record file/folder names or paths above `debug`, and prefer ids. Wrong-password should be `debug!`/`info!`, not `error!`.

---

<a id="a7"></a>
### A7 — Secrets held in plain `String`s; raw tokens in the session map
**Effort:** S · **WP:** 1
- [ ] Done in: _______

**Where:** `routes/session.rs:40-41,90,121` (password cloned into several `String`s; `expose_secret().clone()` copies the token into a plain `String`); `AppState.token_to_id: HashMap<String, String>` keys are raw tokens; `CreateSession { password: String }`.

**Fix:** enable `secrecy`'s `serde` feature and make `CreateSession.password: SecretString` (deserialises directly, zeroised on drop); pass `SecretString` clones only. Key the session store by a **digest** of the token (`orion::hash::digest(token.as_bytes())` → hex) so raw tokens never sit in the map. Keep `UserSession.user_token` only long enough to build the cookie, or drop the field. (`zeroize` is already a transitive dependency.)

---

<a id="a8"></a>
### A8 — Dead code and unused dependencies
**Effort:** S · **WP:** 0
- [ ] Done in: _______

- Unused items: `sqlite::get_folder_id_strict` (`sqlite.rs:318`), `encryption::STREAM_LIMIT` (`encryption/mod.rs:17`), `ChunkDecryptor::get_file_path` (`chunk_decryptor.rs:31`), `FinalizeErrorResponse` (`file.rs:47`, unless used for H4), `extern crate serde;` (`main.rs:39`).
- Unused `RequestError` variants: `FailedToAddFile`, `FailedToMoveFile`, `FailedToRenameFile` (defined and mapped in `responders.rs` but never constructed).
- Unused dependencies: `base64`, `serde_json` (both declared in `Cargo.toml`, no `use`).
- `UserSession.created_at` is only used for display — becomes useful with M3.
- Clippy pedantic also reports ~84 `uninlined_format_args`; optional: `cargo clippy --fix -- -W clippy::uninlined_format_args`.

---

<a id="a9"></a>
### A9 — Tooling
**Effort:** S · **WP:** 5
- [ ] Done in: _______

- `scripts/format_code.py` is a regex-based reformatter that isn't string- or comment-aware (it could insert blank lines inside raw strings such as the SQL in `migrations.rs`) and rewrites files in place. Remove it; encode the blank-line preferences in review or clippy instead.
- `rustfmt.toml` uses `unstable_features`/`imports_granularity`/`group_imports` ⇒ requires nightly rustfmt. Document `cargo +nightly fmt` in the README and add `cargo +nightly fmt --check` to CI (or drop the unstable options).
- `build.sh` (`MODE` is parsed and echoed but unused) and the `ARG BUILD_MODE=static` in both Dockerfiles do nothing — remove.
- CI (`.onedev-buildspec.yml`) only builds the image (the `release` stage depends on `test_and_build`, so tests do run there). Add explicit steps: `cargo clippy --all-targets -- -D warnings`, `cargo +nightly fmt --check`, `cargo audit` (M10).
- Set `rust-version` in `Cargo.toml` (find the real MSRV with `cargo msrv find`); the README claims 1.70 but the code uses `u64::is_multiple_of` (much newer).

---

## 6. Tests, ops, docs

<a id="t1"></a>
### T1 — Test infrastructure
**Effort:** M · **WP:** 5
- [ ] Done in: _______

**Problems:** the crate is binary-only, so there is no `tests/` integration directory; the route list is copy-pasted 47 times in tests (`routes![put_file, get_file, …]`), so tests never exercise the real `main()` wiring — the `Cors` and `Shield` fairings, `CleanupOnShutdown`, admin mounting — and can drift from it; 6 `env::set_var` calls mutate process-global state across parallel tests (unsafe in Rust 2024 and racy already); `create_test_session` bypasses the real login path.

**Fix:** add `src/lib.rs` exposing the modules and `pub fn build_rocket(cfg: AppConfig) -> Rocket<Build>` that mounts everything (main = `#[launch] fn rocket() -> _ { build_rocket(AppConfig::from_env().expect(..)) }`). Tests call `build_rocket(AppConfig::for_tests(tmp))`. Add a shared `tests/common` (or `src/tests/common.rs`) helper with `login(client, user, pw)` that goes through `POST /session`. Keep `create_test_session` for speed but add real-login tests.

---

<a id="t2"></a>
### T2 — Missing regression tests (checklist)
**Effort:** M · **WP:** 5 (each is also listed under its finding)
- [ ] Done in: _______

Currently untested: concurrency/deadlock (H1, H2), folder cycle (H3), huge `total_size` (H4), oversize PUT (H5), empty-file download (H6), size validation (M1), overwrite race (M2), session expiry/logout cleanup (M3), login oracles/throttling/username validation (M4), admin key edge cases (M5), PATCH edge cases (M8), durability/thumbnail concurrency (M9), first-login race (M12), thumbnail limits (M13), range edge cases (suffix, multi-range, 416 header), tamper detection.

Add also:
- **Tamper detection:** flip one byte in a stored blob → `GET` fails (stream aborts, logged); swap two chunk records within a blob → index mismatch error.
- **Property tests** (`proptest`) for `VirtualPath::parse` and for chunk/offset arithmetic (`encrypted_len` ↔ plaintext length round-trip).
- **Crypto round-trips** at boundaries: sizes 0, 1, `CHUNK_SIZE-1`, `CHUNK_SIZE`, `CHUNK_SIZE+1`, `2*CHUNK_SIZE`.
- An `#[ignore]`d **stress test** (Appendix A.1) runnable in CI nightly.

---

<a id="o1"></a>
### O1 — Dockerfile hardening
**Effort:** S · **WP:** 5
- [ ] Done in: _______

- Runs as **root** in `scratch`: create a data dir in the build stage, `COPY --from=… --chown=10001:10001 /data /data`, `USER 10001:10001`, `ENV JUSTENCRYPT_USER_DATA_PATH=/data`, `VOLUME /data`. (`scratch` has no `mkdir`, so the directory must be created in an earlier stage.)
- README `docker run` has no volume, so `user_data` lives in the container filesystem (`/user_data` doesn't even exist in `scratch`) — document `-v justencrypt_data:/data`, and recommend `--read-only --cap-drop ALL --security-opt no-new-privileges`.
- `.dockerignore` only lists `target` and `user_data`; add `.env`, `.git`, `perf-test`, `perf-results`, `*.md`, `.vscode`. `COPY . .` currently puts a developer `.env` (with real secrets) into build-stage layers.
- No `HEALTHCHECK` (no curl in `scratch`): either add a `--healthcheck` mode to the binary or rely on the orchestrator probing `GET /`.
- Pin base images by digest (`rust:alpine3.20`, `alpine:3.20`, `grafana/k6:latest` in `Dockerfile.perf` is unpinned).
- `Dockerfile.perf`: remove the baked secret key (M6); the `COPY Cargo.lock` line requires M10's committed lockfile.
- Remove dead `ARG BUILD_MODE` (A9).

---

<a id="o2"></a>
### O2 — README/docs are inaccurate
**Effort:** S · **WP:** 5
- [ ] Done in: _______

- MSRV "1.70" is wrong (A9). Badge and prerequisites need the real version.
- "Configuration … loaded from the `env/justencrypt.env` file" is false for `cargo run`: `dotenv::dotenv()` loads **`.env` from the current working directory** (`env/justencrypt.env` is only used via Docker `--env-file`). Fix the wording or load the documented file explicitly.
- `cp env/justencrypt.env.example env/justencrypt.env` → the `.example` file doesn't exist (M6).
- **No documentation of how users are created** (a `user_data/<name>/` directory must exist and the first successful login sets the password — or the admin endpoint from M4 once added). This is the biggest gap for a new operator.
- Config table defaults must match code (A1: `MAX_DB_CONNECTIONS_PER_USER`, `MINIMUM_PASSWORD_SECURITY_SCORE`, `MAX_ACTIVE_UPLOADS`). Document the new variables from this report.
- Add a "Deployment / security notes" section: run behind TLS (or set TLS paths), keep `SECURE_COOKIES=true`, admin key ≥ 32 chars, `ip_header` behavior behind a proxy, back up `user_data/` (encrypted DBs hold the file keys — losing a DB loses the files), set request-body limits at the proxy too.
- README's endpoint list omits response codes and the upload flow order; link `openapi.yaml`.

---

## Appendix A — Reproduction recipes

All were run against an isolated copy of `HEAD` (never against your working tree or `user_data/`). Tests below use the repo's existing helpers (`setup_rocket`, `create_test_session` from `src/tests/mod.rs`); register a new file in `src/tests/mod.rs` (`mod test_regression;`). Rocket prints a lot at test time — run with `ROCKET_LOG_LEVEL=off cargo test <name> -- --nocapture`.

### A.1 H1 — session deadlock stress harness
Start a **release** server from a scratch directory (not the project dir), pre-initialise two users, then run the script. On the original code it reports a hang (3/3); after the H1 fix, `no hang observed`.
```bash
TMP=$(mktemp -d); mkdir -p $TMP/data/reader $TMP/data/churn; cd $TMP        # cd away from the project's .env!
cargo build --release --manifest-path /path/to/justencrypt/Cargo.toml
env JUSTENCRYPT_ADDRESS=127.0.0.1 JUSTENCRYPT_PORT=18124 JUSTENCRYPT_USER_DATA_PATH=$TMP/data \
    JUSTENCRYPT_SECURE_COOKIES=false JUSTENCRYPT_ROCKET_SECRET_KEY="$(openssl rand -base64 32)" \
    JUSTENCRYPT_LOG_LEVEL=error JUSTENCRYPT_ROCKET_LOG_LEVEL=Off  /path/to/target/release/justencrypt &
for u in reader churn; do   # pre-initialise (avoids the M12 first-login race confounding the test)
  curl -s -o /dev/null -X POST localhost:18124/session -H 'Content-Type: application/json' \
       -d "{\"username\":\"$u\",\"password\":\"correct-horse-battery-staple-9!\"}"; done
python3 stress.py 40 18124
```
```python
# stress.py — usage: stress.py <seconds> <port>
import http.client, json, threading, time, sys
DUR, PORT = int(sys.argv[1]), int(sys.argv[2]); PW = "correct-horse-battery-staple-9!"
def login(user):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    c.request("POST", "/session", json.dumps({"username": user, "password": PW}), {"Content-Type": "application/json"})
    r = c.getresponse(); r.read(); c.close()
    ck = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
    return r.status, (ck[0].split(";")[0] if ck else None)
st, reader_cookie = login("reader"); assert st == 201, st
stop = time.time() + DUR; stats = {"reads": 0, "logouts": 0, "timeouts": 0}
lock = threading.Lock(); dead = threading.Event()
def reader():                      # hammer an authenticated route (takes token_to_id.read -> sessions_by_id.read)
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=4)
    while time.time() < stop and not dead.is_set():
        try:
            c.request("GET", "/folder/", headers={"Cookie": reader_cookie}); c.getresponse().read()
            with lock: stats["reads"] += 1
        except Exception:
            with lock: stats["timeouts"] += 1
            dead.set(); return
def churn():                       # login -> logout (takes sessions_by_id.write -> token_to_id.write)
    while time.time() < stop and not dead.is_set():
        try:
            st, ck = login("churn")
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=4)
            c.request("DELETE", "/session", headers={"Cookie": ck}); c.getresponse().read(); c.close()
            with lock: stats["logouts"] += 1
        except Exception:
            with lock: stats["timeouts"] += 1
            dead.set(); return
ts = [threading.Thread(target=reader) for _ in range(12)] + [threading.Thread(target=churn) for _ in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
print(stats)
if dead.is_set():
    print("!! request timed out -> DEADLOCK suspected; probing:")
    for path, ck in (("/", None), ("/folder/", reader_cookie)):
        try:
            c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=4)
            c.request("GET", path, headers={"Cookie": ck} if ck else {}); r = c.getresponse(); r.read(); print("  ", path, "->", r.status)
        except Exception as e: print("  ", path, "-> TIMEOUT", type(e).__name__)
else: print("no hang observed")
```
Signature of the bug: `GET /` → 200, `GET /folder/` with a valid cookie → timeout, `POST /session` → timeout, server CPU ≈ 0%.

### A.2 H2 — stale-upload deadlock (Rust test)
```rust
#[async_test]
async fn init_upload_with_stale_upload_does_not_hang() {
    let (client, _u, sid, cookie) = full_client().await;             // mount init_upload/upload_chunk/finalize_upload/put_file/get_file/... and create_test_session
    for name in ["a.txt", "b.txt"] {
        assert_eq!(client.post(format!("/file/upload/initiate/{name}")).private_cookie(cookie.clone()).dispatch().await.status(), Status::Ok);
    }
    { // backdate one upload by 25h
        let state = client.rocket().state::<AppState>().unwrap();
        let session = state.sessions_by_id.read().await.get(&sid).unwrap().clone();
        let uploads = session.active_uploads.lock().await;
        let (_, up) = uploads.iter().next().unwrap();
        *up.last_updated.lock().await = SystemTime::now() - Duration::from_secs(25 * 3600);
    }
    let fut = client.post("/file/upload/initiate/c.txt").private_cookie(cookie).dispatch();
    let r = timeout(Duration::from_secs(5), fut).await.expect("init_upload hung (deadlock)");
    assert_eq!(r.status(), Status::Ok);
    // then assert: stale .part file gone, stale row gone from active_uploads
}
```
### A.3 H3 — folder cycle
Route-level (run as its own process with a hard timeout; a failing run leaves a stuck blocking thread, hence `process::exit`):
```rust
#[async_test] #[ignore]
async fn folder_cycle_bypass() {
    let (client, _u, _sid, cookie) = full_client().await;
    client.put("/folder/a/b").private_cookie(cookie.clone()).dispatch().await;
    for dest in ["a/b/c", "a/./b/c", "a/b/../b/c"] {           // all must be 400
        let fut = client.patch("/folder/a/b").private_cookie(cookie.clone()).header(ContentType::JSON)
                        .body(format!(r#"{{"parent_folder_path":"{dest}"}}"#)).dispatch();
        match timeout(Duration::from_secs(10), fut).await {
            Ok(r) => assert_eq!(r.status(), Status::BadRequest, "dest {dest}"),
            Err(_) => { eprintln!("HUNG on {dest}"); std::process::exit(1); }
        }
    }
}
// run: timeout 60 cargo test folder_cycle_bypass -- --ignored --nocapture
```
SQL-level (works on plain `sqlite3`; extract the migration SQL from `migrations.rs` into `schema.sql`):
```sql
PRAGMA temp_store = MEMORY; PRAGMA foreign_keys = ON;
.read schema.sql
INSERT INTO folders (parent_folder_id,name) VALUES (1,'a'),(2,'b'),(3,'c');   -- ids 2,3,4  (a/b/c)
UPDATE folders SET parent_folder_id = 4 WHERE id = 3;     -- ORIGINAL: never returns, RSS grows ~50 MB/s.   FIXED: "Cannot move a folder into itself or its subfolders"
```
(Run under `timeout 20` and watch RSS: `grep VmRSS /proc/$(pgrep -n sqlite3)/status`.)

### A.4 H4 — huge `total_size`
```rust
let up: InitUploadResponse = client.post("/file/upload/initiate/big.bin").private_cookie(cookie.clone()).dispatch().await.into_json().await.unwrap();
let t = Instant::now();
let r = client.post(format!("/file/upload/finalize/{}?total_size={}", up.upload_id, 1u64 << 40)).private_cookie(cookie).dispatch().await;
let body = r.into_string().await.unwrap();
// ORIGINAL: 400 after ~630 ms with a ~149 MB body and +300 MB RSS.  EXPECTED: fast 400/413, body < 2 KiB.
```
### A.5 H5 — silent truncation
Temporarily change `data.open(5.gibibytes())` in `put_file` to `1.kibibytes()`, PUT 5000 bytes → `201`, listing shows `file_size: 1024`. After the fix (limit from config + `limit+1` check) the same PUT must return 413 and leave nothing behind.
### A.6 H6 — empty file over real HTTP
```bash
curl -s -b jar -X PUT localhost:8000/file/empty.txt --data-binary ''      # 201
curl -sS -i -b jar localhost:8000/file/empty.txt                          # ORIGINAL: Content-Length: 1, Content-Range: bytes 0-0/0, then "curl: (18) end of response with 1 bytes missing"
```
### A.7 M4 — login oracles and timing
```bash
login(){ curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" -X POST $B/session -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}"; }
login alice a                       # initialised user, weak pw      -> ORIGINAL 401
login nobody a                      # no such user, weak pw          -> ORIGINAL 400   (oracle)
login alice 'another-strong-Wrong-pass-77!'   # ~84 ms
login nobody 'another-strong-Wrong-pass-77!'  # ~4.5 ms            (timing oracle)
login "/tmp/somewhere/probe" a      # absolute-path username: 401 if /tmp/somewhere/probe.db exists, else 400
for i in $(seq 25); do login alice "guess-$i"; done   # no throttle, ~85 ms each
```
### A.8 M5 — empty admin key
Start with `JUSTENCRYPT_ADMIN_API_KEY=` and run `curl -H 'X-Admin-Api-Key;' localhost:8000/admin/session` (curl sends an empty header for `name;`) → ORIGINAL: `200` with session list.
### A.9 M8 — PATCH semantics
Upload `x.txt`, `y.txt`; then PATCH `/file/ghost.txt {"file_name":"z"}` (204), PATCH `/file/ghost.txt {"parent_folder_path":"auto/created/dir"}` (204 + folders created), PATCH `/file/x.txt {"file_name":"y.txt"}` (500), PATCH `/file/x.txt {"file_name":"evil/name.txt"}` (204, then both names 404), PATCH `/file/y.txt {"file_name":""}` (204).
### A.10 M7 — root delete
Create a file and `docs/sub/a.txt`; `DELETE /folder/` → `500`, and `GET /folder/` afterwards returns `[]` (everything deleted).
### A.11 M10 — dependency audit
```bash
cargo install cargo-audit --locked          # or: cargo install cargo-audit --locked --root /some/dir
cargo audit                                 # needs Cargo.lock
cargo tree -i h2@0.3.27                     # shows hyper 0.14 <- rocket_http 0.5.1
```

## Appendix B — Suspected but disproved (don't spend time here)
- **`zxcvbn` DoS on huge passwords:** flat ~0.4–0.5 s for 2 k–32 k characters and 0.85 s for 2,000,000 characters (zxcvbn 3.x caps the analysed length). Only a length cap for hygiene (M4).
- **Percent-encoded names stored raw:** `PUT /file/my%20file%20%C3%A9.txt` is stored and listed as `my file é.txt` (decoded correctly).
- **Filesystem path traversal:** not exploitable — user paths are virtual (rows in SQLite) and blobs are named by server-generated UUIDs; the only user-derived filesystem path is the *username* (see M4 for the unvalidated-username issue).
- **SQL injection:** all data-dependent SQL is parameterised; only PRAGMA values from operator config are `format!`-ed (A1).
- **Cookie replay after logout:** correctly rejected with 401.
- **`decrypt_all` OOM:** `Vec::with_capacity(total_size)` looked risky but it is only used for thumbnails whose derived metadata has `total_size = 0`.

## Appendix C — What is solid (don't regress it)
- Per-file random 256-bit keys; per-chunk XChaCha20-Poly1305 via `orion::aead::seal` with a fresh random 24-byte nonce per chunk (no nonce-reuse risk); the chunk index is authenticated inside the plaintext, defeating chunk reordering/substitution; thumbnails use a key derived by HMAC from the file key.
- Per-user SQLCipher databases give real tenant isolation; upload ids are session-scoped; `AuthenticatedSession` always resolves to the caller's own DB pool.
- Virtual filesystem design: no user-supplied path reaches the disk; blob names are UUIDs sharded into `xx/yy/`.
- Private (encrypted) cookies with `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` by default (`JUSTENCRYPT_SECURE_COOKIES`); 7-day client expiry.
- Errors returned to clients from DB failures are generic (`DbError` → 500 without details).
- Admin routes are only mounted when a key is configured (tighten per M5).
- Shield headers (`nosniff`, `X-Frame-Options`, `Permissions-Policy`, HSTS) are enabled.
- Password policy uses zxcvbn at account creation.
- Good test coverage of the happy paths (42 tests, ~1 s) and range/chunk arithmetic.
