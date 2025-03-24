# syntax=docker/dockerfile:1.4

FROM rust:alpine3.20 AS builder

ARG BUILD_MODE

RUN apk add --no-cache \
    build-base \
    openssl-dev \
    pkgconfig \
    musl-dev \
    linux-headers \
    cmake \
    perl

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/justencrypt
COPY . .

RUN if [ "$BUILD_MODE" = "static" ]; then \
    export RUSTFLAGS="-C target-feature=-crt-static" && \
    export OPENSSL_STATIC=1 && \
    cargo build --release --target x86_64-unknown-linux-musl; \
    else \
    cargo build --release; \
    fi

FROM alpine:3.20 AS dynamic
RUN mkdir /app
RUN mkdir /app/user_data
RUN mkdir /app/tls
RUN apk add --no-cache openssl
COPY --from=builder /usr/src/justencrypt/target/release/justencrypt /app/justencrypt
EXPOSE 8000
CMD ["/app/justencrypt"]

FROM scratch AS static
COPY --from=builder /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt /justencrypt
EXPOSE 8000
CMD ["/justencrypt"]


