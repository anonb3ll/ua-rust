FROM rust:1.88-bookworm AS builder

ARG UA_FEATURES=embeddings
WORKDIR /src
COPY . .

RUN cargo build --release --locked -p ua-cli --features "${UA_FEATURES}"

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ua \
    && useradd --system --uid 10001 --gid ua --home-dir /var/lib/ua-rust --create-home ua \
    && chmod 0700 /var/lib/ua-rust \
    && install -d -m 0700 -o ua -g ua /var/lib/ua-rust/models

COPY --from=builder /src/target/release/ua /usr/local/bin/ua

ENV UA_HOME=/var/lib/ua-rust \
    UA_BIND=0.0.0.0:8765 \
    FASTEMBED_CACHE_DIR=/var/lib/ua-rust/models \
    HF_HOME=/var/lib/ua-rust/models

VOLUME ["/var/lib/ua-rust"]
EXPOSE 8765

USER ua
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8765/healthz"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ua"]
CMD ["serve"]
