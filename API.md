# API Documentation

This document describes the REST API endpoints for zdns-rest, a high-speed DNS lookup service.

## Base URL

```
http://localhost:8080
```

For HTTPS deployments, use:

```
https://your-host:8080
```

## Authentication

When API key authentication is enabled (`--api-key` flag), all endpoints (except `/ping`, `/health`, `/ready`, `/metrics`) require authentication.

### Authentication Methods

**Bearer Token:**
```bash
curl -H "Authorization: Bearer your-api-key" http://localhost:8080/job
```

**Header:**
```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/job
```

**Response on authentication failure (401):**
```json
{
  "code": 4001,
  "message": "Unauthorized: valid API key required"
}
```

## Rate Limiting

When rate limiting is enabled (`--rate-limit`), the API tracks requests per IP address. Rate limit headers are included in responses:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed per window |
| `X-RateLimit-Window` | Duration of the rate limit window (seconds) |
| `X-Request-ID` | Unique request ID for tracing |

**Rate limit response (429):**
```json
{
  "code": 3000,
  "message": "Rate limit exceeded. Please try again later."
}
```

---

## Endpoints

### GET /ping

Simple health check endpoint.

- **Auth Required**: No
- **Rate Limited**: No
- **Content-Type**: `application/json`

**Response:**
```json
{
  "code": 1000,
  "message": "Command completed successfully"
}
```

---

### GET /health

Detailed health check with build information.

- **Auth Required**: No
- **Rate Limited**: No
- **Content-Type**: `application/json`

**Response:**
```json
{
  "code": 1000,
  "message": "Healthy",
  "status": "up",
  "build_info": {
    "version": "dev",
    "go_version": "go1.24.0",
    "commit": "abc123",
    "build_date": "2026-01-01T00:00:00Z"
  }
}
```

---

### GET /ready

Readiness probe for load balancers and orchestrators.

- **Auth Required**: No
- **Rate Limited**: No
- **Content-Type**: `application/json`

**Response:**
```json
{
  "code": 1000,
  "message": "Ready",
  "ready": true
}
```

---

### GET /metrics

Prometheus metrics endpoint for monitoring.

- **Auth Required**: No
- **Rate Limited**: No
- **Content-Type**: `text/plain; version=0.0.4`

**Metrics exposed:**

| Metric | Type | Description |
|--------|------|-------------|
| `zdns_requests_total` | Counter | Total HTTP requests (labels: method, path, status) |
| `zdns_request_duration_seconds` | Histogram | HTTP request latency |
| `zdns_dns_lookups_total` | Counter | Total DNS lookups (labels: module, status) |
| `zdns_dns_lookup_duration_seconds` | Histogram | DNS lookup latency |
| `zdns_rate_limit_hits_total` | Counter | Rate limit violations |
| `zdns_auth_failures_total` | Counter | Authentication failures |
| `zdns_active_connections` | Gauge | Current active connections |

---

### POST /job

Run a DNS lookup job with JSON body.

- **Auth Required**: Yes (if enabled)
- **Rate Limited**: Yes (if enabled)
- **Content-Type**: `application/json`
- **Response**: `application/x-ndjson` (newline-delimited JSON)

**Request Body:**
```json
{
  "module": "A",
  "queries": ["example.com", "example.org"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `module` | string | No | Lookup module. Default: `A` |
| `queries` | string[] | Yes | Array of domain names (1-1000 items) |

**Supported Modules:**

| Module | Description |
|--------|-------------|
| `A` | IPv4 address lookup |
| `AAAA` | IPv6 address lookup |
| `MX` | Mail exchange records |
| `MXLOOKUP` | MX with A/AAAA resolution |
| `NS` | Name server records |
| `NSLOOKUP` | NS with A/AAAA resolution |
| `SOA` | Start of authority |
| `TXT` | Text records |
| `SPF` | SPF records |
| `DMARC` | DMARC records |
| `CNAME` | CNAME records |
| `PTR` | Pointer records |
| `SRV` | Service records |
| `BINDVERSION` | BIND version query |
| `AXFR` | Zone transfer attempt |

**Response** (one JSON object per line):
```ndjson
{"data":{"answers":[{"answer":"93.184.216.34","class":"IN","name":"example.com","ttl":300,"type":"A"}]},"name":"example.com","status":"NOERROR","timestamp":"2026-01-01T00:00:00+00:00"}
{"data":{"answers":[{"answer":"93.184.216.34","class":"IN","name":"example.org","ttl":300,"type":"A"}]},"name":"example.org","status":"NOERROR","timestamp":"2026-01-01T00:00:00+00:00"}
```

**Error Responses:**

| HTTP | Code | Description |
|------|------|-------------|
| 400 | 2001 | Failed to decode/read request |
| 400 | 2005 | Queries array empty |
| 400 | 2006 | Too many queries (exceeds limit) |
| 400 | 2007 | Invalid lookup module |
| 400 | 2008 | Invalid domain name |
| 413 | 2009 | Request entity too large |
| 429 | 3000 | Rate limit exceeded |
| 401 | 4001 | Unauthorized (invalid/missing API key) |
| 503 | 5001 | Circuit breaker open (upstream DNS issues) |

---

### POST /job/{lookup}

Run a DNS lookup with the module specified in the URL.

- **Auth Required**: Yes (if enabled)
- **Rate Limited**: Yes (if enabled)
- **Content-Type**: `application/x-www-form-urlencoded` or `text/plain`
- **Response**: `application/x-ndjson`

**URL Parameters:**

| Parameter | Description |
|-----------|-------------|
| `lookup` | Lookup module (see table above) |

**Body:** Plain text with one domain per line

```
example.com
example.org
```

**Response:** Same NDJSON format as `POST /job`.

---

## Error Response Format

All error responses follow this JSON structure:

```json
{
  "code": 3000,
  "message": "Rate limit exceeded. Please try again later."
}
```

**Common Error Codes:**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| 1000 | 200 OK | Success |
| 2000 | 400 Bad Request | Unknown command |
| 2001 | 400 Bad Request | Failed to decode/read request |
| 2002 | 400 Bad Request | Failed to read request body |
| 2005 | 400 Bad Request | Queries array empty |
| 2006 | 400 Bad Request | Too many queries |
| 2007 | 400 Bad Request | Invalid lookup module |
| 2008 | 400 Bad Request | Invalid domain name |
| 2009 | 413 Request Entity Too Large | Request body too large |
| 3000 | 429 Too Many Requests | Rate limit exceeded |
| 4001 | 401 Unauthorized | Invalid/missing API key |
| 5001 | 503 Service Unavailable | Circuit breaker open |
| 2400 | 500 Internal Server Error | Configuration/copy error |
| 2401 | 500 Internal Server Error | Factory initialization error |
| 2402 | 500 Internal Server Error | Lookup execution error |
| 2403 | 500 Internal Server Error | Factory finalization error |
| 5000 | 500 Internal Server Error | Internal server error |

---

## CORS Support

When CORS is enabled (`--cors-origins`), the API supports cross-origin requests from specified origins.

**CORS Headers:**

| Header | Description |
|--------|-------------|
| `Access-Control-Allow-Origin` | Allowed origin |
| `Access-Control-Allow-Methods` | Allowed HTTP methods |
| `Access-Control-Allow-Headers` | Allowed request headers |
| `Access-Control-Allow-Credentials` | Credentials support |

**Preflight request:**
```bash
curl -X OPTIONS \
  -H "Origin: https://your-frontend.com" \
  -H "Access-Control-Request-Method: POST" \
  http://localhost:8080/job
```

---

## Examples

### Basic A record lookup

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"module": "A", "queries": ["example.com"]}' \
  http://localhost:8080/job
```

### Multiple queries with MX

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"module": "MX", "queries": ["gmail.com", "yahoo.com", "outlook.com"]}' \
  http://localhost:8080/job
```

### With API key authentication

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer my-secret-key" \
  -d '{"module": "A", "queries": ["example.com"]}' \
  http://localhost:8080/job
```

### Plain text input

```bash
curl -X POST \
  -H "Content-Type: text/plain" \
  --data-binary $'google.com\nbing.com\nyahoo.com' \
  http://localhost:8080/job/A
```

### Check health with metrics

```bash
# Simple health check
curl http://localhost:8080/ping

# Detailed health
curl http://localhost:8080/health

# Prometheus metrics
curl http://localhost:8080/metrics
```

---

## Circuit Breaker

When enabled (`--circuit-breaker`), the API protects against cascading failures when upstream DNS becomes unresponsive.

**Circuit States:**

| State | Description |
|-------|-------------|
| **Closed** | Normal operation, requests proceed |
| **Open** | Failing fast after threshold reached, returns 503 |
| **Half-Open** | Testing recovery with limited requests |

**Configuration:**
- `--circuit-breaker-failures`: Failures before opening (default: 5)
- `--circuit-breaker-timeout`: Seconds before trying again (default: 60)

---

## Profiling

When pprof is enabled (`--enable-pprof`), profiling endpoints are available on a separate port (default: 6060):

| Endpoint | Description |
|----------|-------------|
| `/debug/pprof/` | Index with all profiles |
| `/debug/pprof/heap` | Memory heap profile |
| `/debug/pprof/goroutine` | Goroutine profile |
| `/debug/pprof/profile` | CPU profile (30s) |
| `/debug/pprof/trace` | Execution trace |
| `/debug/pprof/allocs` | Allocation profile |

**Example:**
```bash
curl http://localhost:6060/debug/pprof/heap > heap.pprof
go tool pprof heap.pprof
```
