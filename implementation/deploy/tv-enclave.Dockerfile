FROM rust:1.94 AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p tv-enclave --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/tv-enclave /usr/local/bin/tv-enclave
ENV TV_STATE_PK=""
ENV TV_ISSUANCE_PK=""
ENTRYPOINT ["/usr/local/bin/tv-enclave"]
