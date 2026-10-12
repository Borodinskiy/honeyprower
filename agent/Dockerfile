# --- сборка агента ---
FROM docker.io/library/rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# --- рантайм ---
FROM docker.io/library/debian:bookworm-slim
RUN useradd -r -u 10001 agent
COPY --from=build /src/target/release/honeyforge-agent /usr/local/bin/honeyforge-agent
USER agent
ENTRYPOINT ["honeyforge-agent"]
CMD ["/config/config.json"]
