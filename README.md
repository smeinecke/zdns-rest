# zdns-rest

A REST API wrapper for [zmap/zdns](https://github.com/zmap/zdns), providing HTTP endpoints for high-speed DNS lookups.

## Build

```bash
go build -o zdns-rest .
```

## Run

```bash
./zdns-rest --bind-ip 127.0.0.1 --bind-port 8080
```

### Configuration

All flags can be provided via command line, environment variables, or a config file (`~/.zdns.yaml`).

| Flag | Description | Default |
|------|-------------|---------|
| `--bind-ip` | IP to bind API to | `` (all interfaces) |
| `--bind-port` | Port to bind API to | `8080` |
| `--iterative` | Perform own iteration instead of using recursive resolver | `false` |
| `--name-servers` | Comma-separated list or `@/path/to/file` | System default |
| `--timeout` | Timeout for resolving a name (seconds) | `15` |
| `--threads` | Number of lightweight go threads | `1000` |
| `--verbosity` | Log verbosity (1-5) | `4` |
| `--tcp-only` | Only perform lookups over TCP | `false` |
| `--udp-only` | Only perform lookups over UDP | `false` |
| `--class` | DNS class (INET, CSNET, CHAOS, HESIOD, NONE, ANY) | `INET` |
| `--cache-enabled` | Enable DNS result caching | `true` |
| `--cache-ttl` | Cache TTL in seconds | `300` |
| `--cache-max-size` | Maximum cache entries | `10000` |
| `--cache-stale-ttl` | Stale entry TTL on error | `150` |
| `--circuit-breaker` | Enable circuit breaker | `false` |
| `--circuit-breaker-failures` | Circuit breaker threshold | `5` |
| `--circuit-breaker-timeout` | Circuit breaker timeout (seconds) | `60` |

Environment variables use `ZDNS_` prefix with uppercase and underscores, e.g. `ZDNS_BIND_PORT=9090`.

## Features

- **REST API** for high-speed DNS lookups
- **DNS Result Cache** with TTL and stale-on-error support
- **Async/Batch Job Processing** via background workers
- **Prometheus metrics** (`/metrics`)
- **Rate limiting** per IP address
- **API key authentication** (optional)
- **TLS/HTTPS** support
- **CORS** support for browser clients
- **Circuit breaker** for DNS failure protection
- **Structured logging** with request IDs
- **Health/readiness probes** (`/health`, `/ready`)
- **pprof profiling** endpoints (optional)

## API Documentation

See [API.md](API.md) for full API documentation including:
- All endpoints (`/job`, `/job/{lookup}`, `/jobs`, `/ping`, `/health`, `/ready`, `/metrics`)
- Async batch job processing
- DNS result caching
- Authentication methods
- Rate limiting headers
- Error codes and response formats
- Request/response examples
- CORS configuration
- Circuit breaker behavior

## Quick Examples

### Simple A record lookup

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"module": "A", "queries": ["example.com"]}' \
  http://localhost:8080/job
```

### Health check

```bash
curl http://localhost:8080/ping
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```

---

## Development

### Run tests

```bash
# Unit tests
go test -v -race ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Integration tests
go test -v -race -tags=integration ./...
```

### Install pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

### Format and lint

```bash
gofmt -w .
go vet ./...
go mod tidy
```

---

## License

See [LICENSE](LICENSE) file.
