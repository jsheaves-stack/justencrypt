# JustEncrypt

## Requirements

- Rust
- Cargo
- Sqlcipher

For static builds:
- x86_64-unknown-linux-musl toolchain
- Musl

## Installation & Setup

1. Clone the repository:

   ```sh
   git clone https://github.com/jsheaves-stack/justencrypt.git
   cd justencrypt
   ```

2. Install dependencies:

   Regular Build:
   ```sh
   cargo build --release
   ```

   Static build:
   ```sh
   cargo build --release --target x86_64-unknown-linux-musl
   ```

3. Set up environment variables:

   - Create a `.env` file in the project root and define the required environment variables (see below for details).

4. Run the server:

   ```sh
   cargo run --release
   ```

## Environment Variables

The API uses environment variables for configuration. Below are the required variables and their descriptions:

| Variable Name                          | Description |
|----------------------------------------|-------------|
| `JUSTENCRYPT_USER_DATA_PATH`           | The path to store the user data. Default: `./user_data`. |
| `JUSTENCRYPT_ADDRESS`                  | The IP address Rocket will bind to. Default: `0.0.0.0`. |
| `JUSTENCRYPT_PORT`                     | The port Rocket will listen on. Default: `8000`. |
| `JUSTENCRYPT_WORKERS`                  | Number of worker threads for handling requests. Default: `16`. |
| `JUSTENCRYPT_KEEP_ALIVE`               | Keep-alive timeout in seconds. Default: `5`. |
| `JUSTENCRYPT_LOG_LEVEL`                | Logging level for Rocket. Options: `normal`, `critical`, etc. Default: `critical`. |
| `JUSTENCRYPT_ROCKET_SECRET_KEY`        | Required for securing private cookies. A suitable 256-bit base64 key can be generated using OpenSSL: `openssl rand -base64 32`. Required in release mode. |
| `JUSTENCRYPT_TLS_KEY_PATH`             | The path to the tls key file. Required in release mode. |
| `JUSTENCRYPT_TLS_CERT_PATH`            | The path to the tls cert file. Required in release mode. |
| `JUSTENCRYPT_ALLOW_ORIGIN`             | The Access-Control-Allow-Origin domain value. Default: `http://localhost:8000`. |
| `JUSTENCRYPT_LIMITS_FORM`              | Maximum size allowed for form submissions. Default: `10 MiB`. |
| `JUSTENCRYPT_LIMITS_DATA_FORM`         | Maximum size allowed for data-form submissions. Default: `10 MiB`. |
| `JUSTENCRYPT_LIMITS_FILE`              | Maximum file upload size. Default: `64 GiB`. |
| `JUSTENCRYPT_LIMITS_JSON`              | Maximum JSON request payload size. Default: `10 MiB`. |
| `JUSTENCRYPT_LIMITS_MSGPACK`           | Maximum MessagePack request payload size. Default: `1 MiB`. |
| `JUSTENCRYPT_LIMITS_FILE_JPG`          | Maximum size allowed for JPG files. Default: `10 GiB`. |
| `JUSTENCRYPT_LIMITS_BYTES`             | Maximum size for raw byte payloads. Default: `10 MiB`. |
| `JUSTENCRYPT_LIMITS_STRING`            | Maximum size for string payloads. Default: `10 MiB`. |

Example `.env` file:
```ini
JUSTENCRYPT_USER_DATA_PATH=./user_data
JUSTENCRYPT_ADDRESS=0.0.0.0
JUSTENCRYPT_PORT=8000
JUSTENCRYPT_WORKERS=16
JUSTENCRYPT_KEEP_ALIVE=5
JUSTENCRYPT_LOG_LEVEL=critical
JUSTENCRYPT_ROCKET_SECRET_KEY=your_generated_secret_key
JUSTENCRYPT_TLS_KEY_PATH=./default.key
JUSTENCRYPT_TLS_CERT_PATH=./default.crt
JUSTENCRYPT_ALLOW_ORIGIN=https://example.com
JUSTENCRYPT_LIMITS_FORM=10MiB
JUSTENCRYPT_LIMITS_DATA_FORM=10MiB
JUSTENCRYPT_LIMITS_FILE=64GiB
JUSTENCRYPT_LIMITS_JSON=10MiB
JUSTENCRYPT_LIMITS_MSGPACK=1MiB
JUSTENCRYPT_LIMITS_FILE_JPG=10GiB
JUSTENCRYPT_LIMITS_BYTES=10MiB
JUSTENCRYPT_LIMITS_STRING=10MiB
```

## License

This project is open-source and licensed under the MIT License.
