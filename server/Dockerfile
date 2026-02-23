FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY server/Cargo.toml ./Cargo.toml
COPY server/Cargo.lock ./Cargo.lock
COPY server/build.rs ./build.rs
COPY ml/ml_service.proto ./ml/ml_service.proto
COPY server/src ./src
COPY server/migration ./migration

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/server /app/server

COPY --from=builder /app/migration /app/migration

ENV RUST_LOG=orazen_api=info,tower_http=info

EXPOSE 8080

CMD ["/app/server"]
