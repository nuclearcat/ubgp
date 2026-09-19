# syntax=docker/dockerfile:1
ARG BASE_IMAGE=debian:12-slim
ARG RUST_VERSION=1.97.1
FROM rust:${RUST_VERSION}-slim-bookworm AS rust

# Compile on each target distribution, so dpkg-shlibdeps uses its actual ABI.
FROM ${BASE_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates debhelper python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo/bin /usr/local/cargo/bin
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
WORKDIR /work
COPY Cargo.toml Cargo.lock README.md LICENSE ./
COPY src ./src
COPY examples ./examples
COPY packaging/build-deb.sh packaging/ubgp.service packaging/90-ubgp.conf ./packaging/
COPY packaging/debian ./packaging/debian
ARG SOURCE_DATE_EPOCH
ARG RELEASE_TAG
RUN UBGP_PACKAGE_CONTAINER=1 ./packaging/build-deb.sh

# Installation tests run on a clean target image without build dependencies.
FROM ${BASE_IMAGE} AS test
RUN apt-get update
COPY --from=build /out /out
COPY packaging/test-deb.sh /test-deb.sh
RUN UBGP_PACKAGE_CONTAINER=1 bash -x /test-deb.sh \
    && rm -rf /var/lib/apt/lists/*

# Export only packages that passed the installation tests, plus checksums.
FROM scratch AS artifacts
COPY --from=test /out/ /
