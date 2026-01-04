# Gemini Guidelines for JustEncrypt

This document provides guidelines for interacting with the JustEncrypt codebase using Gemini.

## Project Overview

JustEncrypt is a file encryption service written in Rust. It provides a web API for encrypting and decrypting files, with a focus on security and performance. The backend is built using the [Rocket](https://rocket.rs/) web framework, and it uses SQLCipher for database encryption.

## Technologies

- **Language:** Rust
- **Web Framework:** Rocket
- **Database:** SQLite with SQLCipher for encryption
- **Encryption:** `orion` for cryptographic operations
- **Serialization:** Serde

## Project Structure

The project follows a standard Rust project layout:

- `src/`: Contains all the source code.
  - `main.rs`: The entry point of the application.
  - `db/`: Database-related modules, including migrations and SQLite connection handling.
  - `encryption/`: Modules for stream encryption and decryption.
  - `enums/`: Custom error and success enums.
  - `routes/`: Rocket route handlers for different API endpoints.
  - `session/`: User session management.
  - `util/`: Utility modules.
  - `web/`: Web-related components like fairings and guards.
- `Cargo.toml`: The package manifest, containing metadata and dependencies.
- `README.md`: General information about the project, including setup instructions.
- `Dockerfile`: For building a Docker image of the application.
- `build.sh`: A script for building the project.

## Development Workflow

### Build

To build the project, run:

```sh
cargo build
```

For a release build:

```sh
cargo build --release
```

### Run

To run the server:

```sh
cargo run
```

Make sure to set up the environment variables as described in `README.md`.

### Test

The project does not currently have a dedicated test suite. When adding new features, please add corresponding tests.

## Coding Conventions

- Follow the official [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- Use `cargo fmt` to format the code before committing.
- Write clear and concise commit messages.
- Add comments to explain complex logic.
