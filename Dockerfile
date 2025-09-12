FROM rust:alpine3.20 AS prepare
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

FROM prepare AS test
WORKDIR /usr/src/justencrypt
RUN cargo test --target x86_64-unknown-linux-musl --release

FROM prepare AS build
WORKDIR /usr/src/justencrypt
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN chmod +x /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt

FROM prepare AS test_and_build
WORKDIR /usr/src/justencrypt
RUN cargo test --target x86_64-unknown-linux-musl --release
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN chmod +x /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt

FROM scratch AS release
COPY --from=test_and_build /usr/src/justencrypt/target/x86_64-unknown-linux-musl/release/justencrypt /justencrypt
EXPOSE 8000
CMD ["/justencrypt"]