FROM rust:1.95-bookworm AS build
ARG RUN_BUILD_TESTS=true
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libssh2-1-dev && rm -rf /var/lib/apt/lists/*
ENV CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=8
WORKDIR /src
COPY . .
RUN if [ "$RUN_BUILD_TESTS" = "true" ]; then cargo test --locked --workspace; fi \
    && cargo build --release --locked --workspace
RUN if [ "$RUN_BUILD_TESTS" = "true" ]; then cargo test --locked --manifest-path backend/Cargo.toml; fi \
    && cargo build --release --locked --manifest-path backend/Cargo.toml
RUN if [ "$RUN_BUILD_TESTS" = "true" ]; then cargo test --locked --manifest-path honeypots/kozyavka/Cargo.toml; fi \
    && cargo build --release --locked --manifest-path honeypots/kozyavka/Cargo.toml
RUN mkdir -p /artifacts/bin && cp target/release/hf-center target/release/hf-agent \
    target/release/hf-dispatcher /artifacts/bin/ \
    && cp backend/target/release/honeyforge-backend /artifacts/bin/ \
    && sh honeypots/high-ubuntu-ssh/scripts/package-recipe.sh /artifacts/hf-high-ubuntu-ssh.tar.gz

FROM debian:bookworm-slim AS low
COPY --from=build /src/honeypots/kozyavka/target/release/honeyforge-low /usr/local/bin/honeyforge-low
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/honeyforge-low"]

FROM debian:bookworm-slim AS middle
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/pritvoryashka /usr/local/bin/pritvoryashka
COPY honeypots/pritvoryashka/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 0755 /usr/local/bin/pritvoryashka /usr/local/bin/docker-entrypoint \
    && output="$(/usr/local/bin/pritvoryashka /__hf_missing_config_probe__.json 2>&1 || true)" \
    && printf '%s\n' "$output" | grep -Fq 'Error: Read(Os {' \
    && printf '%s\n' "$output" | grep -Fq 'No such file or directory' || \
       { printf 'Middle binary cannot start in its runtime image:\n%s\n' "$output" >&2; exit 1; }
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["/etc/honeyforge/pritvoryashka.json"]

FROM debian:bookworm-slim AS artifacts
COPY --from=build /artifacts /artifacts
CMD ["true"]
