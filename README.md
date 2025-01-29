# JustEncrypt

## Installation & Setup

1. Clone the repository:
   ```sh
   git clone https://github.com/jsheaves-stack/justencrypt.git
   cd justencrypt
   ```

2. Install dependencies:
   ```sh
   cargo build --release
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
| `JUSTENCRYPT_ROCKET_SECRET_KEY`        | The cryptographic key used for encrypting application values. This is required for securing private cookies when the Rocket `secrets` feature is enabled. A suitable 256-bit base64 key can be generated using OpenSSL: `openssl rand -base64 32`. |
| `JUSTENCRYPT_ROCKET_ALLOW_ORIGIN`      | The CORS configuration allowing frontend applications to interact with the API. Example: `http://localhost:8080`. |
| `JUSTENCRYPT_USER_DATA_PATH`           | The file system path where uploaded and processed files are stored. Default: `./user_data`. |

Example `.env` file:
```ini
JUSTENCRYPT_ROCKET_SECRET_KEY=frTlv9S0PhCWxd3sWnT+CHKGmHUWZLIVr9iR8zqMnw0=
JUSTENCRYPT_ROCKET_SERVER_DOMAIN="http://localhost:8080"
JUSTENCRYPT_ROCKET_ALLOW_ORIGIN="http://localhost:8080"
JUSTENCRYPT_USER_DATA_PATH="./user_data"
```

## Security Considerations
- Always use a strong `JUSTENCRYPT_ROCKET_SECRET_KEY` in production.
- Ensure the `JUSTENCRYPT_USER_DATA_PATH` is properly secured to prevent unauthorized access.

## License
This project is open-source and licensed under the MIT License.