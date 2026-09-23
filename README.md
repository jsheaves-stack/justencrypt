# JustEncrypt

**A secure file encryption service.**

[![Rust Version][rust-badge]][rust-link]
[![License: MIT][license-badge]][license-link]

[rust-badge]: https://img.shields.io/badge/Rust-1.70%2B-orange.svg
[rust-link]: https://www.rust-lang.org/
[license-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[license-link]: https://opensource.org/licenses/MIT

JustEncrypt is a self-hostable, high-performance file encryption service accessible via a RESTful API. It's built with Rust and the Rocket web framework, with a strong emphasis on security and privacy.

## Features

- **End-to-End Encryption:** Files are encrypted and decrypted on the fly.
- **Chunked Uploads:** Supports uploading large files in chunks.
- **Thumbnail Generation:** Automatically generates thumbnails for image files.
- **User-Based Sessions:** Secure session management for multi-user environments.
- **Detailed Configuration:** Highly configurable through environment variables.
- **Docker Support:** Ready to be deployed as a Docker container.

## Technologies

- **Language:** [Rust](https://www.rust-lang.org/)
- **Web Framework:** [Rocket](https://rocket.rs/)
- **Database:** [SQLite](https://www.sqlite.org/index.html) with [SQLCipher](https://www.zetetic.net/sqlcipher/) for database encryption.
- **Encryption:** [Orion](https://docs.rs/orion/latest/orion/) for cryptographic operations.
- **Serialization:** [Serde](https://serde.rs/)

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (1.70 or later)
- [Cargo](https://doc.rust-lang.org/cargo/)
- [SQLCipher](https://www.zetetic.net/sqlcipher/open-source/)
- For static builds:
    - `x86_64-unknown-linux-musl` toolchain
    - `musl`

## Getting Started

### 1. Clone the Repository

```sh
git clone <repository-url>
cd justencrypt
```

### 2. Set Up Environment Variables

Create an `env/justencrypt.env` file. You can start with the provided example and uncomment the variables you need to change.

```sh
mkdir -p env
cp env/justencrypt.env.example env/justencrypt.env
```

### 3. Build and Run

You can run the application using `cargo`:

```sh
cargo run --release
```

The server will start on the address and port specified in your configuration (default: `http://0.0.0.0:8000`).

## Configuration

The application is configured through environment variables, which are loaded from the `env/justencrypt.env` file. The following table details the available variables and their default values.

| Variable Name                                 | Description | Default |
|-----------------------------------------------|-------------|---------|
| `JUSTENCRYPT_ADDRESS`                         | The IP address Rocket will bind to. | `0.0.0.0` |
| `JUSTENCRYPT_PORT`                            | The port Rocket will listen on. | `8000` |
| `JUSTENCRYPT_WORKERS`                         | Number of worker threads for handling requests. | `16` |
| `JUSTENCRYPT_KEEP_ALIVE`                      | Keep-alive timeout in seconds. | `5` |
| `JUSTENCRYPT_MINIMUM_PASSWORD_SECURITY_SCORE` | The minimum password security score (`0`-`4`). | `3` |
| `JUSTENCRYPT_ROCKET_LOG_LEVEL`                | Logging level for Rocket (`Off`, `Debug`, `Normal`, `Critical`). | `Critical` |
| `JUSTENCRYPT_LOG_LEVEL`                       | Logging level for the application (`Off`, `Trace`, `Debug`, `Info`, `Warn`, `Error`). | `Warn` |
| `JUSTENCRYPT_USER_DATA_PATH`                  | The path to store user data. | `./user_data` |
| `JUSTENCRYPT_MIN_DB_CONNECTIONS_PER_USER`     | Minimum number of idle SQLite connections per user. | `0` |
| `JUSTENCRYPT_MAX_DB_CONNECTIONS_PER_USER`     | Maximum number of concurrent SQLite connections per user. | `2` |
| `JUSTENCRYPT_DB_IDLE_TIMEOUT_SECONDS`         | Seconds a connection can be idle before being closed. | `600` |
| `JUSTENCRYPT_DB_BUSY_TIMEOUT_MS`              | Milliseconds to wait when the database is locked. | `60000` |
| `JUSTENCRYPT_DB_SYNCHRONOUS_MODE`             | SQLite PRAGMA synchronous setting (`NORMAL`, `FULL`, `OFF`). | `NORMAL` |
| `JUSTENCRYPT_DB_CACHE_SIZE_KB`                | SQLite PRAGMA cache_size in kilobytes. | `16000` |
| `JUSTENCRYPT_DB_TEMP_STORE`                   | SQLite PRAGMA temp_store setting (`MEMORY`, `FILE`). | `MEMORY` |
| `JUSTENCRYPT_DB_JOURNAL_SIZE_LIMIT_BYTES`     | Max size in bytes for the WAL file. | `67108864` |
| `JUSTENCRYPT_DB_CONNECTION_TIMEOUT_SECONDS`   | Seconds to wait for an available DB connection. | `30` |
| `JUSTENCRYPT_MAX_ACTIVE_UPLOADS`              | Maximum number of concurrent active uploads allowed. | (none) |
| `JUSTENCRYPT_UPLOAD_TTL_SECONDS`              | Seconds an upload can sit idle before it is considered abandoned and removed (checked when a new upload starts). | `86400` |
| `JUSTENCRYPT_ROCKET_SECRET_KEY`               | **Required.** A 256-bit base64 key for securing cookies. Generate one with `openssl rand -base64 32`. | (none) |
| `JUSTENCRYPT_TLS_KEY_PATH`                    | Path to the TLS key file for HTTPS. | (none) |
| `JUSTENCRYPT_TLS_CERT_PATH`                   | Path to the TLS cert file for HTTPS. | (none) |
| `JUSTENCRYPT_ALLOW_ORIGIN`                    | Access-Control-Allow-Origin domain for CORS. | (none) |
| `JUSTENCRYPT_SECURE_COOKIES`                  | Whether session cookies require HTTPS. Set to false for local dev. | `true` |
| `JUSTENCRYPT_ADMIN_API_KEY`                   | API key to enable and access administrative routes. | (none) |
| `JUSTENCRYPT_LIMITS_FORM`                     | Maximum size for form submissions. | `10MiB` |
| `JUSTENCRYPT_LIMITS_DATA_FORM`                | Maximum size for data-form submissions. | `10MiB` |
| `JUSTENCRYPT_LIMITS_FILE`                     | Maximum file upload size. | `64GiB` |
| `JUSTENCRYPT_LIMITS_JSON`                     | Maximum JSON payload size. | `10MiB` |
| `JUSTENCRYPT_LIMITS_MSGPACK`                  | Maximum MessagePack payload size. | `1MiB` |
| `JUSTENCRYPT_LIMITS_FILE_JPG`                 | Maximum size for JPG files. | `10GiB` |
| `JUSTENCRYPT_LIMITS_BYTES`                    | Maximum size for raw byte payloads. | `10MiB` |
| `JUSTENCRYPT_LIMITS_STRING`                   | Maximum size for string payloads. | `10MiB` |

## API Endpoints

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
- `POST /upload/initiate/<file_path..>`: Initiate a chunked upload.
- `PUT /upload/chunk/<upload_id>?<offset>`: Upload a chunk of a file.
- `POST /upload/finalize/<upload_id>?<total_size>`: Finalize a chunked upload.

### Folder (`/folder`)
- `GET /<folder_path..>`: List the contents of a folder.
- `PUT /<folder_path..>`: Create a new folder.
- `DELETE /<folder_path..>`: Delete a folder.
- `PATCH /<folder_path..>`: Rename or move a folder.

### Thumbnail (`/thumbnail`)
- `GET /<file_path..>`: Get a thumbnail for a file.

### Admin (`/admin`)
- `GET /session`: Get information about the current session.
- `DELETE /session/<session_id>`: Delete a specific session.

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
docker run -d -p 8000:8000 --env-file env/justencrypt.env --name justencrypt justencrypt
```

## Testing

Run the test suite using `cargo`:

```sh
cargo test
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
