# syntax=docker/dockerfile:1

# Build stage (fallback when no prebuilt binary)
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for fetching dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o zdns-rest .

# Final stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /root/

ARG TARGETARCH

# Copy builder binary as fallback
COPY --from=builder /app/zdns-rest /root/zdns-rest-builder

# Copy prebuilt binary if available (from CI)
COPY prebuilt/zdns-rest-linux-${TARGETARCH} /root/zdns-rest-prebuilt 2>/dev/null || true

# Use prebuilt if available, otherwise builder output
RUN if [ -f /root/zdns-rest-prebuilt ]; then \
        mv /root/zdns-rest-prebuilt /root/zdns-rest; \
    else \
        mv /root/zdns-rest-builder /root/zdns-rest; \
    fi && \
    chmod +x /root/zdns-rest && \
    rm -f /root/zdns-rest-builder /root/zdns-rest-prebuilt

# Expose default port
EXPOSE 8080

# Run the binary
ENTRYPOINT ["./zdns-rest"]
CMD ["--bind-port", "8080"]
