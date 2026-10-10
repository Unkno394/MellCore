FROM rust:1.95-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/honeyforge-low /usr/local/bin/honeyforge-low
COPY config/docker.json /etc/honeyforge/config.json
USER 65532:65532
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/honeyforge-low"]
CMD ["--config", "/etc/honeyforge/config.json"]
