# JustEncrypt

**A secure file encryption service.**

[![Rust Version][rust-badge]][rust-link]
[![License: MIT][license-badge]][license-link]

[rust-badge]: https://img.shields.io/badge/Rust-1.87%2B-orange.svg
[rust-link]: https://www.rust-lang.org/
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[license-link]: https://opensource.org/licenses/MIT

JustEncrypt is a self-hostable, high-performance file encryption service accessible via a RESTful API. It's built with Rust and the axum web framework, with a strong emphasis on security and privacy.

## Features

- **Encryption at Rest:** Every file is encrypted on the server with its own key as it is uploaded, and decrypted as it is downloaded. Each user's file keys and metadata live in a database encrypted with that user's password (SQLCipher). The server handles plaintext while a request is in progress, so this is not end-to-end encryption.
- **Chunked and Ranged Transfers:** Large files can be uploaded in chunks, in any order and in parallel, and downloads support single byte ranges.
- **Folder Downloads:** A folder, with all its subfolders, downloads as one TAR archive. The archive is built as it streams, so its size doesn't affect the server's memory use.
- **Thumbnails:** Generates and caches (encrypted) thumbnails for JPEG, PNG, GIF, WebP and AVIF images.
- **Multi-User Sessions:** Cookie-based sessions with idle and absolute timeouts and a per-user session limit.
- **Detailed Configuration:** Configured through environment variables, validated at startup.
- **Docker Support:** Ready to be deployed as a Docker container.

## Technologies

- **Language:** [Rust](https://www.rust-lang.org/)
- **Web Framework:** [axum](https://github.com/tokio-rs/axum), on [Tokio](https://tokio.rs/)
- **Database:** [SQLite](https://www.sqlite.org/index.html) with [SQLCipher](https://www.zetetic.net/sqlcipher/) for database encryption.
- **Encryption:** [Orion](https://docs.rs/orion/latest/orion/) for cryptographic operations.
- **Serialization:** [Serde](https://serde.rs/)

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.87 or later, with Cargo. (The code uses APIs stabilised in 1.87; older versions are not tested.)
- A C compiler, `make` and `perl`: SQLCipher and OpenSSL are compiled from source as part of the build, so neither needs to be installed.
- Linux or another Unix: the server writes file chunks with Unix positional writes and does not build on Windows.
- For static builds: the `x86_64-unknown-linux-musl` Rust target and the musl C toolchain.

## Getting Started

### 1. Clone the Repository

```sh
git clone <repository-url>
cd justencrypt
```

### 2. Set Up Environment Variables

`env/justencrypt.env` is an example configuration listing every variable. When run with `cargo run`, the server loads a `.env` file from the current directory, so copy the example there and uncomment the variables you need to change:

```sh
cp env/justencrypt.env .env
```

Generate your own secret key with `openssl rand -base64 32` and set it as `JUSTENCRYPT_SECRET_KEY`; release builds refuse to start without one. Set `JUSTENCRYPT_ADMIN_API_KEY` too, since accounts are created through the admin API. For development over plain HTTP, set `JUSTENCRYPT_SECURE_COOKIES=false` so the session cookie isn't marked HTTPS-only.

### 3. Build and Run

You can run the application using `cargo`:

```sh
cargo run --release
```

The server will start on the address and port specified in your configuration (default: `http://0.0.0.0:8000`). It speaks plain HTTP (HTTP/1.1, and HTTP/2 for clients that ask for it directly); see [Running Behind a Reverse Proxy](#running-behind-a-reverse-proxy) for HTTPS.

### 4. Create a User

Accounts are created by an administrator; logging in never creates one. Set `JUSTENCRYPT_ADMIN_API_KEY`, then:

```sh
curl -X POST http://localhost:8000/admin/users \
  -H 'Content-Type: application/json' \
  -H "X-Admin-Api-Key: $JUSTENCRYPT_ADMIN_API_KEY" \
  -d '{"username": "alice", "password": "<a strong password>"}'
```

This returns `201` and creates `user_data/alice/` with the user's encrypted database. With the default `JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE` of `4`, the password must be very strong by [zxcvbn](https://github.com/dropbox/zxcvbn)'s measure; a weak one gets `400`. Usernames are 1-64 bytes with no `/`, `\`, `.` or control characters; passwords are 1-1024 bytes and must meet `JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE`. The user can then log in with `POST /session`.

## Configuration

The application is configured through environment variables. When run directly, the server also loads a `.env` file from its working directory; variables already set in the environment take precedence over it. With Docker, pass the file with `--env-file`. The following table details the available variables and their default values.

All variables are read once at startup (`src/config/mod.rs`). An empty value counts as unset. A value that can't be parsed or is out of range stops the server with an error that names the variable. `JUSTENCRYPT_*` variables the server doesn't recognize are ignored.

| Variable Name                                 | Description | Default |
|-----------------------------------------------|-------------|---------|
| `JUSTENCRYPT_ADDRESS`                         | The IP address the server listens on. | `0.0.0.0` |
| `JUSTENCRYPT_PORT`                            | The port the server listens on. | `8000` |
| `JUSTENCRYPT_WORKERS`                         | Number of worker threads for handling requests. | `16` |
| `JUSTENCRYPT_MAX_BLOCKING_THREADS`            | Number of threads for work that blocks: database queries, file reads and writes, and image decoding. Shared by every user. | `512` |
| `JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE` | The minimum zxcvbn password score (`0`-`4`) required when creating an account. | `4` |
| `JUSTENCRYPT_HTTP_LOG_LEVEL`                  | Logging level for the HTTP server and its libraries, including one line per request at `Info` (`Off`, `Trace`, `Debug`, `Info`, `Warn`, `Error`). | `Error` |
| `JUSTENCRYPT_LOG_LEVEL`                       | Logging level for the application (`Off`, `Trace`, `Debug`, `Info`, `Warn`, `Error`). | `Warn` |
| `JUSTENCRYPT_USER_DATA_PATH`                  | The path to store user data. | `./user_data` |
| `JUSTENCRYPT_MIN_DB_CONNECTIONS_PER_USER`     | Minimum number of idle SQLite connections per user. | `0` |
| `JUSTENCRYPT_MAX_DB_CONNECTIONS_PER_USER`     | Maximum number of SQLite connections per user. A user's database work waits for one of their own connections without holding a server thread, so a user who runs out slows down only themselves. Folder downloads may use at most half of them, leaving the rest for the user's other requests. | `16` |
| `JUSTENCRYPT_DB_IDLE_TIMEOUT_SECONDS`         | Seconds a connection can be idle before being closed. | `600` |
| `JUSTENCRYPT_DB_BUSY_TIMEOUT_MS`              | Milliseconds to wait when the database is locked. | `60000` |
| `JUSTENCRYPT_DB_SYNCHRONOUS_MODE`             | SQLite PRAGMA synchronous setting (`OFF`, `NORMAL`, `FULL`, `EXTRA`). | `NORMAL` |
| `JUSTENCRYPT_DB_CACHE_SIZE_KB`                | SQLite PRAGMA cache_size in kilobytes. | `16000` |
| `JUSTENCRYPT_DB_TEMP_STORE`                   | SQLite PRAGMA temp_store setting (`DEFAULT`, `FILE`, `MEMORY`). | `MEMORY` |
| `JUSTENCRYPT_DB_JOURNAL_SIZE_LIMIT_BYTES`     | Max size in bytes for the WAL file. | `67108864` |
| `JUSTENCRYPT_DB_CONNECTION_TIMEOUT_SECONDS`   | Seconds a request waits for one of its user's connections, folder download slots or (with `JUSTENCRYPT_MAX_BLOCKING_THREADS_PER_USER` set) blocking threads before giving up with `429`. | `30` |
| `JUSTENCRYPT_MAX_ACTIVE_UPLOADS`              | Maximum number of uploads a session may have in progress at once. | (no limit) |
| `JUSTENCRYPT_MAX_ACTIVE_DOWNLOADS`            | Maximum number of folder downloads that may run at once, across all users. Each one holds a thread and one of its user's database connections until it finishes; further downloads get `429`. | (no limit) |
| `JUSTENCRYPT_MAX_BLOCKING_THREADS_PER_USER`   | Maximum number of blocking threads one user's requests may occupy at once. With no limit, a single busy user can take every one and slow down everyone else; set this to keep users from affecting each other. Requests over the limit wait without holding a thread. | (no limit) |
| `JUSTENCRYPT_DOWNLOAD_STALL_TIMEOUT_SECONDS`  | Seconds a file or folder download waits for the client to read more before it is abandoned, freeing what it holds (for a folder download, its slot and database connection). | `60` |
| `JUSTENCRYPT_UPLOAD_TTL_SECONDS`              | Seconds an upload can sit idle before it is considered abandoned and removed (checked when a new upload starts, and by the session reaper if enabled). | `86400` |
| `JUSTENCRYPT_SESSION_IDLE_TIMEOUT_SECONDS`    | A session with no requests for this long expires. | `3600` |
| `JUSTENCRYPT_SESSION_MAX_LIFETIME_SECONDS`    | A session expires this long after login, however active it is. Also the session cookie's `Max-Age`. | `604800` |
| `JUSTENCRYPT_MAX_SESSIONS_PER_USER`           | Logging in beyond this many sessions ends the user's oldest session. | `5` |
| `JUSTENCRYPT_ORPHAN_SCAN_ENABLED`             | When `true`, every login starts a background job that removes that user's stored files that no database row refers to: blobs, thumbnails and `.part` files left behind by crashes or failed deletes. | `false` |
| `JUSTENCRYPT_THUMBNAIL_CONCURRENCY`           | Maximum number of thumbnails generated at once. | 70% of `JUSTENCRYPT_WORKERS` |
| `JUSTENCRYPT_THUMBNAIL_MAX_DECODE_MEMORY`     | Maximum memory one image may need to decode for a thumbnail (e.g. `256MiB`); larger images, or ones wider or taller than 16384 pixels, get a `422`. Decoding uses at most this times `JUSTENCRYPT_THUMBNAIL_CONCURRENCY`. | `256MiB` |
| `JUSTENCRYPT_SESSION_REAPER_INTERVAL_SECONDS` | How often a background job removes expired sessions and stale uploads. `0` disables it; expired sessions are then still rejected on their next request and cleared out on every login. | `0` |
| `JUSTENCRYPT_SECRET_KEY`                      | **Required in release builds.** The key the session cookies are encrypted with: 256 or 512 bits, as base64 or hex. Generate one with `openssl rand -base64 32`. Debug builds without one use a random key for each launch. | (none) |
| `JUSTENCRYPT_ALLOW_ORIGIN`                    | The one origin (e.g. `https://app.example.com`, no trailing slash) whose pages may call the API from a browser, with cookies. Other origins get no CORS headers. `*` is rejected. | (none) |
| `JUSTENCRYPT_SECURE_COOKIES`                  | Whether session cookies require HTTPS. Set to false for local dev. | `true` |
| `JUSTENCRYPT_ADMIN_API_KEY`                   | API key to enable and access administrative routes, including creating user accounts. | (none) |
| `JUSTENCRYPT_LIMITS_FILE`                     | Maximum file size, for both single and chunked uploads. Larger uploads are rejected with `413`. | `64GiB` |
| `JUSTENCRYPT_LIMITS_FILE_CHUNK`               | Maximum body size of a single chunked-upload request (`PUT /upload/chunk/...`). | `32MiB` |
| `JUSTENCRYPT_LIMITS_JSON`                     | Maximum JSON body size (login, account creation and `PATCH` requests). | `10MiB` |

## API Endpoints

The full API, including request and response formats and every status code, is described in [`openapi.yaml`](openapi.yaml). Requests with a JSON body must send `Content-Type: application/json`; others get `415`. Every error response has an [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) body (`application/problem+json`) whose `detail` says what went wrong. Apart from `GET /`, `POST /session`, preflight `OPTIONS` requests and the admin routes, every route needs the `sid` session cookie set by `POST /session`. Any of those routes can answer `429` when the user's own requests in progress kept it waiting for longer than `JUSTENCRYPT_DB_CONNECTION_TIMEOUT_SECONDS`; it can be retried later.

### Info (`/`)
- `GET /`: Get server information.

### Session (`/session`)
- `POST /`: Create a new session (login).
- `DELETE /`: Destroy the current session (logout).

### File (`/file`)
- `GET /<file_path..>`: Download a file.
- `PUT /<file_path..>`: Upload a file (simple upload).
- `DELETE /<file_path..>`: Delete a file.
- `PATCH /<file_path..>`: Rename or move a file.

### Chunked Upload (`/upload`)
- `POST /initiate/<file_path..>`: Initiate a chunked upload.
- `PUT /chunk/<upload_id>?offset=<offset>`: Upload a chunk of a file.
- `POST /finalize/<upload_id>?total_size=<total_size>`: Finalize a chunked upload.

A chunked upload starts with `initiate`, which returns an `upload_id`. The file is then sent in 64 KiB chunks: each `chunk` request carries one or more consecutive chunks starting at `offset` (a multiple of 65536), and requests may be sent in any order or in parallel. `finalize` checks that the chunks add up to exactly `total_size` bytes and stores the file.

### Folder (`/folder`)
- `GET /<folder_path..>`: List the contents of a folder.
- `GET /<folder_path..>?download`: Download a folder and everything in it as an uncompressed TAR archive, streamed as it is built. Any `download` parameter selects the archive, with or without a value.
- `PUT /<folder_path..>`: Create a new folder.
- `DELETE /<folder_path..>`: Delete a folder.
- `PATCH /<folder_path..>`: Rename or move a folder.

### Thumbnail (`/thumbnail`)
- `GET /<file_path..>`: Get a thumbnail for a file.

### Admin (`/admin`)
These routes exist only when `JUSTENCRYPT_ADMIN_API_KEY` is set, and every request must send the key in the `X-Admin-Api-Key` header.
- `POST /users`: Create a user account.
- `GET /session`: List all active sessions, with their unfinished uploads.
- `DELETE /session/<session_id>`: End a session.

## Building and Running

### Standard Build

```sh
# Build for development
cargo build

# Build for release
cargo build --release
```

### Static Build

To create a statically linked binary for Linux:

```sh
cargo build --release --target x86_64-unknown-linux-musl
```

### Docker

The repository includes a `Dockerfile` for building and running the application in a container.

```sh
# Build the Docker image
docker build -t justencrypt .

# Run the container
docker run -d -p 8000:8000 \
  --env-file env/justencrypt.env \
  --cap-drop ALL --security-opt no-new-privileges \
  --name justencrypt justencrypt
```

The image only contains the server binary, so it runs without any capabilities. User data is written to `/user_data` inside the container, so it is lost when the container is removed. The container serves plain HTTP; put a reverse proxy in front of it for HTTPS.

Building the image runs the test suite in release mode before building the binary.

### Running Behind a Reverse Proxy

The server doesn't handle TLS itself; a reverse proxy in front of it terminates HTTPS and renews the certificate. With [Caddy](https://caddyserver.com/), which gets a certificate from Let's Encrypt automatically, the whole configuration is:

```
files.example.com {
    reverse_proxy localhost:8000
}
```

Keep the server's port reachable only by the proxy (bind it with `JUSTENCRYPT_ADDRESS=127.0.0.1`, or keep it on a private Docker network), so requests can't bypass HTTPS. Keep `JUSTENCRYPT_SECURE_COOKIES=true`: browsers talk to the proxy over HTTPS, so the session cookie is still sent.

## Testing

Run the test suite using `cargo`:

```sh
cargo test
```

The tests write temporary files to the system temp directory and need no running server. Code is formatted with nightly rustfmt (`rustfmt.toml` uses unstable options):

```sh
cargo +nightly fmt
```

## Deployment and Security Notes

- **A forgotten password can't be recovered.** A user's file keys live in their database, which is encrypted with their password. Without the password, their files can't be decrypted by anyone, including an administrator.
- **Back up the user data directory** (`JUSTENCRYPT_USER_DATA_PATH`). Losing a user's `.db` file loses the keys to all of their files, even if the encrypted files themselves survive.
- **Use HTTPS.** Run behind a reverse proxy that terminates TLS (see [Running Behind a Reverse Proxy](#running-behind-a-reverse-proxy)), and keep `JUSTENCRYPT_SECURE_COOKIES=true`. Passwords and files travel in the requests.
- **Keep the secret key and the admin key secret.** The secret key protects the session cookies. Anyone with the admin key can create accounts and end sessions, so use a long random value.
- **Sessions live in memory.** Restarting the server logs everyone out and discards unfinished chunked uploads.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
