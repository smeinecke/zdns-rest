# Build stage
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
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o zdns-rest ./cmd/zdns-rest

# Final stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/zdns-rest .

# Expose default port
EXPOSE 8080

# Run the binary
ENTRYPOINT ["./zdns-rest"]
CMD ["--bind-port", "8080"]
