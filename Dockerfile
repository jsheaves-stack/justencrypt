FROM rust:alpine3.20 AS builder

RUN apk add --no-cache \
    build-base \
    openssl-dev \
    pkgconfig

# ENV RUSTFLAGS="-C target-feature=-crt-static"
# ENV OPENSSL_STATIC=1
# ENV LIBSQLITE3_SYS_BINDING=sqlcipher
# ENV LIBSQLITE3_SYS_STATIC=1

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/justencrypt

COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

EXPOSE 8000

COPY --from=builder \
    /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt \
    /justencrypt

CMD ["/justencrypt"]
