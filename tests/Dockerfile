ARG RUST_VERSION=1.97.1
FROM rust:${RUST_VERSION}-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    bird2 iproute2 python3 util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
COPY tests ./tests
RUN cargo build --release --locked && cargo test --no-run --locked
ENV RUST_BACKTRACE=1
ENTRYPOINT ["bash", "/work/tests/container.sh"]
CMD ["unit"]
