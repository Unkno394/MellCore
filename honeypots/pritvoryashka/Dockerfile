# Build this image on the Center CI, export it with `docker save`, and pass the archive as
# HF_PRITVORYASHKA_IMAGE_ARCHIVE during agent bootstrap. VPS hosts never need Rust toolchains.
FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p pritvoryashka

FROM scratch AS binary-artifact
COPY --from=build /src/target/release/pritvoryashka /pritvoryashka

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates wget \
    && wget -q https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb \
    && dpkg -i /tmp/packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends powershell \
    && rm -f /tmp/packages-microsoft-prod.deb \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/pritvoryashka /usr/local/bin/pritvoryashka
COPY honeypots/pritvoryashka/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
COPY honeypots/pritvoryashka/config-schema-probe.json /tmp/hf-middle-config-schema-probe.json
RUN chmod 0755 /usr/local/bin/pritvoryashka /usr/local/bin/docker-entrypoint \
    && output="$(/usr/local/bin/pritvoryashka /__hf_missing_config_probe__.json 2>&1 || true)" \
    && printf '%s\n' "$output" | grep -Fq 'Error: Read(Os {' \
    && printf '%s\n' "$output" | grep -Fq 'No such file or directory' || \
       { printf 'Middle binary cannot start in its runtime image:\n%s\n' "$output" >&2; exit 1; }
RUN /usr/local/bin/pritvoryashka --check-config /tmp/hf-middle-config-schema-probe.json \
    && /usr/local/bin/pritvoryashka --check-windows-parser \
    && rm -f /tmp/hf-middle-config-schema-probe.json
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["/etc/honeyforge/pritvoryashka.json"]
