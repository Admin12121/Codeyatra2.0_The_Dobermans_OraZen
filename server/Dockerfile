FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY server/Cargo.toml ./

COPY proto /proto

COPY server/build.rs ./

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release && rm -rf src

COPY server/src ./src
COPY server/migrations ./migrations

RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/orafinite-api /app/orafinite-api

COPY --from=builder /app/migrations /app/migrations

ENV RUST_LOG=orafinite_api=info,tower_http=info

EXPOSE 8080

CMD ["/app/orafinite-api"]
