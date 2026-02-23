FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY server/Cargo.toml ./Cargo.toml

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release && rm -rf src

COPY server/src ./src
COPY server/migration ./migration

RUN find src -type f -exec touch {} + && cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/server /app/server

COPY --from=builder /app/migration /app/migration

ENV RUST_LOG=orafinite_api=info,tower_http=info

EXPOSE 8080

CMD ["/app/server"]
