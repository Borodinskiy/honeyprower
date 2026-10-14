# --- сборка ---
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/honeyforge .

# --- агент для деплоя по SSH (glibc bookworm — запускается на Debian 12+/Ubuntu 22.04+) ---
FROM docker.io/library/rust:1-slim-bookworm AS agent
WORKDIR /src
COPY agent/Cargo.toml agent/Cargo.lock ./
COPY agent/src ./src
RUN cargo build --release

# --- рантайм ---
FROM docker.io/library/alpine:3.22
RUN adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/honeyforge /app/honeyforge
COPY Web /app/Web
COPY --from=agent /src/target/release/honeyforge-agent /app/agent/honeyforge-agent
COPY agent/honeyforge-agent.service /app/agent/honeyforge-agent.service
ENV WEB_ADDR=:8080 \
    API_ADDR=127.0.0.1:8081 \
    STATIC_DIR=/app/Web \
    HF_AGENT_BIN=/app/agent/honeyforge-agent \
    HF_AGENT_SERVICE=/app/agent/honeyforge-agent.service
USER app
EXPOSE 8080
ENTRYPOINT ["/app/honeyforge"]
