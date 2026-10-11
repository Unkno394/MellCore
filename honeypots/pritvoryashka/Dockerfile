# Build this image on the Center CI, export it with `docker save`, and pass the archive as
# HF_PRITVORYASHKA_IMAGE_ARCHIVE during agent bootstrap. VPS hosts never need Rust toolchains.
FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p pritvoryashka

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/pritvoryashka /usr/local/bin/pritvoryashka
COPY honeypots/pritvoryashka/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 0755 /usr/local/bin/pritvoryashka /usr/local/bin/docker-entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["/etc/honeyforge/pritvoryashka.json"]
