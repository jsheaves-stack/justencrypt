# Start with a Rust base image
FROM rust:1.82.0-slim-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/justencrypt

# Copy the entire project
COPY . .

# Build the project
RUN cargo build --release

# Start a new stage with a minimal image
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/local/bin

# Copy the built executable from the builder stage
COPY --from=builder /usr/src/justencrypt/target/release/justencrypt .

# Copy the Rocket.toml configuration file
COPY --from=builder /usr/src/justencrypt/Rocket.toml .

# Create a directory for user data
RUN mkdir -p /usr/local/bin/user_data

# Set the environment variable for the Rocket configuration file
ENV ROCKET_CONFIG=/usr/local/bin/Rocket.toml

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD ["./justencrypt"]
