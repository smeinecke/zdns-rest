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

---

## Async/Batch Job Processing

The API supports asynchronous DNS lookups via the `/jobs` endpoints. Jobs are processed by a background worker pool, allowing clients to submit large batches without blocking.

### POST /jobs

Create a new async DNS lookup job.

- **Auth Required**: Yes (if enabled)
- **Rate Limited**: Yes (if enabled)
- **Content-Type**: `application/json`

**Request Body:**
```json
{
  "module": "A",
  "queries": ["example.com", "example.org", "example.net"]
}
```

**Response (202 Accepted):**
```json
{
  "job_id": "job-1640995200-1",
  "status": "pending",
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

### GET /jobs/{job_id}

Get the status of a job.

- **Auth Required**: Yes (if enabled)
- **Rate Limited**: Yes (if enabled)

**Response:**
```json
{
  "id": "job-1640995200-1",
  "status": "running",
  "module": "A",
  "total": 3,
  "progress": 2,
  "created_at": "2026-01-01T00:00:00Z",
  "started_at": "2026-01-01T00:00:01Z"
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `pending` | Job is queued, waiting for a worker |
| `running` | Job is being processed |
| `completed` | All lookups finished successfully |
| `failed` | Job failed due to error |
| `cancelled` | Job was cancelled |

---

### GET /jobs/{job_id}/results

Get the results of a completed job (NDJSON format).

- **Auth Required**: Yes (if enabled)
- **Rate Limited**: Yes (if enabled)
- **Content-Type**: `application/x-ndjson`

**Response (if completed):**
```ndjson
{"name":"example.com","status":"NOERROR","data":{"answers":[{"answer":"93.184.216.34","type":"A"}]}}
{"name":"example.org","status":"NOERROR","data":{"answers":[{"answer":"93.184.216.34","type":"A"}]}}
{"name":"example.net","status":"NOERROR","data":{"answers":[{"answer":"93.184.216.34","type":"A"}]}}
```

**Response (if still processing - 202 Accepted):**
```json
{
  "status": "running",
  "progress": 2,
  "total": 3,
  "message": "Job is still processing"
}
```

---

### DELETE /jobs/{job_id}

Cancel a pending or running job.

- **Auth Required**: Yes (if enabled)
- **Rate Limited**: Yes (if enabled)

**Response:**
```json
{
  "code": 1000,
  "message": "Job cancelled"
}
```

---

## DNS Result Cache

The API includes an in-memory cache for DNS lookup results to improve performance and reduce load on upstream DNS servers.

**Cache Features:**
- **TTL-based expiration**: Cached entries expire after configured TTL (default: 5 minutes)
- **Stale-on-error**: If upstream DNS fails, stale cached results may be served
- **LRU eviction**: When cache reaches max size, least recently used entries are evicted
- **Per-key caching**: Cache keys include (module, query, nameserver) for precise invalidation

**Configuration:**
- `--cache-enabled`: Enable/disable caching (default: true)
- `--cache-ttl`: Cache TTL in seconds (default: 300)
- `--cache-max-size`: Maximum number of cached entries (default: 10000)
- `--cache-stale-ttl`: How long to serve stale entries on error (default: 150)

**Cache Metrics:**
| Metric | Description |
|--------|-------------|
| `zdns_cache_hits_total` | Total cache hits |
| `zdns_cache_misses_total` | Total cache misses |
| `zdns_cache_evictions_total` | Total LRU evictions |
| `zdns_cache_size` | Current number of cached entries |

---

## Job Metrics

When async job processing is enabled, the following Prometheus metrics are available:

| Metric | Type | Description |
|--------|------|-------------|
| `zdns_jobs_total` | Counter | Total jobs created (label: status) |
| `zdns_job_duration_seconds` | Histogram | Job processing duration |
| `zdns_jobs_active` | Gauge | Currently running jobs |

---

## Example: Async Job Workflow

```bash
# 1. Submit a job
JOB_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"module": "A", "queries": ["google.com", "cloudflare.com", "github.com"]}' \
  http://localhost:8080/jobs)

JOB_ID=$(echo $JOB_RESPONSE | jq -r '.job_id')
echo "Job ID: $JOB_ID"

# 2. Poll for completion
while true; do
  STATUS=$(curl -s http://localhost:8080/jobs/$JOB_ID | jq -r '.status')
  echo "Status: $STATUS"
  if [ "$STATUS" = "completed" ]; then
    break
  fi
  sleep 1
done

# 3. Get results
curl http://localhost:8080/jobs/$JOB_ID/results
```
