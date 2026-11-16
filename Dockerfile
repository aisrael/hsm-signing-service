# syntax=docker/dockerfile:1

# The image of the HSM signing service.
#
# Targets:
#   runtime (default)  The service and the SoftHSM PKCS#11 library. Nothing else.
#   setup              The runtime image plus the tools that create the token
#                      and the keys (`setup.sh`). Run it once, on the same
#                      volume as the service. Do not run it in production.
#
# The token lives in the volume /var/lib/softhsm/tokens. The image holds no
# token, no key and no PIN.

ARG DEBIAN_RELEASE=bookworm
ARG RUST_VERSION=1.99

################################################################################
# Build SoftHSM 2.7.0. The Debian and Ubuntu packages are 2.6.1. That version
# does not support the mechanism CKM_ECDSA_SHA256, which the service uses.
FROM debian:${DEBIAN_RELEASE}-slim AS softhsm

ARG SOFTHSM_VERSION=2.7.0
ARG SOFTHSM_SHA256=be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf automake build-essential ca-certificates curl libssl-dev libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSL -o softhsm.tar.gz \
        "https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz" \
    && echo "${SOFTHSM_SHA256}  softhsm.tar.gz" | sha256sum -c - \
    && tar -xzf softhsm.tar.gz --strip-components=1 \
    && sh autogen.sh \
    && ./configure \
        --prefix=/opt/softhsm \
        --sysconfdir=/etc/softhsm \
        --with-crypto-backend=openssl \
        --disable-gost \
        --disable-static \
    && make -j"$(nproc)" \
    && make install

################################################################################
# Build the service.
FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS build

WORKDIR /app
# The manifest lists the benchmarks, so the files must exist. `cargo build`
# does not build them.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp target/release/hsm-signing-service /usr/local/bin/hsm-signing-service

################################################################################
# The runtime image.
FROM debian:${DEBIAN_RELEASE}-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/lib/softhsm/tokens /etc/softhsm \
    && chown app:app /var/lib/softhsm/tokens

# SoftHSM reads /etc/softhsm/softhsm2.conf (the `--sysconfdir` of the build).
RUN printf '%s\n' \
        'directories.tokendir = /var/lib/softhsm/tokens' \
        'objectstore.backend = file' \
        'log.level = ERROR' \
        'slots.removable = false' \
        > /etc/softhsm/softhsm2.conf

COPY --from=softhsm /opt/softhsm/lib/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so
COPY --from=build /usr/local/bin/hsm-signing-service /usr/local/bin/hsm-signing-service

# The service must listen on all addresses to be reachable from outside the
# container. It has no authentication. Publish the port only on a trusted
# interface (see the README).
ENV PKCS11_MODULE=/usr/local/lib/softhsm/libsofthsm2.so \
    HSM_SIGNING_SERVICE_HOST=0.0.0.0 \
    HSM_SIGNING_SERVICE_PORT=8080

VOLUME /var/lib/softhsm/tokens
EXPOSE 8080
USER app

ENTRYPOINT ["/usr/local/bin/hsm-signing-service"]
CMD ["server"]

################################################################################
# The setup image: it creates the token and the keys (see `setup.sh`).
FROM runtime AS setup

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends opensc \
    && rm -rf /var/lib/apt/lists/*
COPY --from=softhsm /opt/softhsm /opt/softhsm
COPY setup.sh /usr/local/bin/setup.sh

ENV PATH="/opt/softhsm/bin:${PATH}"
USER app
ENTRYPOINT ["sh", "/usr/local/bin/setup.sh"]
CMD []

# Keep the runtime image as the default target.
FROM runtime
