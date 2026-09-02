# syntax=docker/dockerfile:1

# Static musl binaries, compiled natively for the target architecture.
#
# rust:*-alpine targets *-unknown-linux-musl by default, so rustc links musl's
# libc.a self-contained and the runtime stage needs no libc at all. musl-dev
# supplies the C toolchain the bundled SQLite and ring build scripts invoke.
#
# Keep this at or above the workspace MSRV (`rust-version` in Cargo.toml).
FROM rust:1.98-alpine3.22 AS build

RUN apk add --no-cache musl-dev git

WORKDIR /src
COPY . .

# `crates/version/build.rs` derives the reported version from
# `git describe --match 'v*'`, so the build context must carry `.git` *with
# tags*. A shallow clone, a plain source tarball, or a `.dockerignore` that
# excludes `.git` all fall back to the Cargo version (0.0.1) silently — the
# binaries build fine and report the wrong version. `safe.directory` matters for
# the same reason: git refusing the repo as dubiously-owned is indistinguishable
# from "no tag reachable" to build.rs, and takes the same silent fallback.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    git config --global --add safe.directory /src; \
    cargo build --release --locked -p lotusd -p lotusctl -p lotusweb; \
    mkdir -p /out /state; \
    cp target/release/lotusd target/release/lotusctl target/release/lotusweb /out/

# distroless/static carries the CA bundle the n0 relay's HTTPS needs and an
# /etc/passwd with `nonroot` (65532), and nothing else — the binaries are static,
# so there is no libc, shell or package manager to keep patched.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/lotusd /out/lotusctl /out/lotusweb /usr/local/bin/
# Owned by nonroot so a plain `docker run -v` works; under Kubernetes the
# volume's own ownership wins, hence `fsGroup: 65532` in the pod spec.
COPY --from=build --chown=65532:65532 /state /var/lib/lotus

# lotusd, lotusctl and lotusweb all read LOTUS_STATE_DIR, so one setting keeps
# the daemon and a `kubectl exec ... lotusctl status` agreeing on where the
# control socket lives.
ENV LOTUS_STATE_DIR=/var/lib/lotus
VOLUME ["/var/lib/lotus"]

# lotusweb only, and only once told to bind somewhere reachable: its default is
# 127.0.0.1:8080, which nothing outside the container can reach. That default is
# deliberately left alone here rather than widened to 0.0.0.0 in the image — pass
# `--listen`/LOTUS_WEB_LISTEN when you actually want it served.
EXPOSE 8080

USER nonroot
CMD ["lotusd", "run"]
