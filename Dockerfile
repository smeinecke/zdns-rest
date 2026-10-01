# Build stage
FROM golang:1.27-alpine AS builder

# Version is injected via ldflags (release builds pass --build-arg VERSION=x.y.z)
ARG VERSION=dev

WORKDIR /app

# Copy go mod files and download dependencies (cached layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code (.dockerignore keeps the context lean)
COPY . .

# Build a static binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.buildVersion=${VERSION}" -o zdns-rest ./cmd/zdns-rest

# Final stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates && \
    addgroup -S zdns && adduser -S -G zdns -H zdns

WORKDIR /home/zdns

# Copy binary from builder
COPY --from=builder /app/zdns-rest .

USER zdns

# Expose default port
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/ping || exit 1

# Run the binary
ENTRYPOINT ["./zdns-rest"]
CMD ["--bind-port", "8080", "--bind-ip", "0.0.0.0"]
