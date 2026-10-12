# --- сборка ---
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/honeyforge .

# --- рантайм ---
FROM docker.io/library/alpine:3.22
RUN adduser -D -H -u 10001 app
WORKDIR /app
COPY --from=build /out/honeyforge /app/honeyforge
COPY Web /app/Web
ENV WEB_ADDR=:8080 \
    API_ADDR=127.0.0.1:8081 \
    STATIC_DIR=/app/Web
USER app
EXPOSE 8080
ENTRYPOINT ["/app/honeyforge"]
