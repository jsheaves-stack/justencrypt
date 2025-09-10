FROM rust:alpine3.20 AS builder

ARG BUILD_MODE=static
ENV OPENSSL_STATIC=1

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
    cargo build --release --target x86_64-unknown-linux-musl; \
    else \
    cargo build --release; \
    fi

RUN chmod +x /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt

FROM scratch
COPY --from=builder /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt /justencrypt
EXPOSE 8000
CMD ["/justencrypt"]

FROM rust:alpine3.20 AS test
RUN cargo test
