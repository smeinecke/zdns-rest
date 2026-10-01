# Quickstart

Get zdns-rest answering DNS queries over HTTP in a few minutes.

## Run

### From source

```bash
git clone <repo> && cd zdns-rest
go build -o zdns-rest ./cmd/zdns-rest
./zdns-rest --bind-ip 127.0.0.1 --bind-port 8080
```

### Docker

```bash
docker build -t zdns-rest .
docker run --rm -p 8080:8080 zdns-rest
```

Or pull the published image (release pipeline pushes to GHCR):

```bash
docker run --rm -p 8080:8080 ghcr.io/<owner>/zdns-rest:latest
```

### Verify it's up

```bash
curl http://localhost:8080/ping
# {"code":1000,"message":"Command completed successfully"}
```

## Your first lookup

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"module": "A", "queries": ["example.com", "example.org"]}' \
  http://localhost:8080/job
```

Response is [NDJSON](https://ndjson.org/) — one JSON object per line, one per
query, in query order:

```json
{"name":"example.com","results":{"A":{"status":"NOERROR","duration":0.012,"data":{"answers":[...]}}}}
{"name":"example.org","results":{"A":{"status":"NOERROR","duration":0.010,"data":{"answers":[...]}}}}
```

### Modules

`module` selects the lookup type: `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`,
`CNAME`, `PTR`, `SRV`, `CAA`, `ANY`, plus the compound modules `ALOOKUP`,
`MXLOOKUP`, `NSLOOKUP`, `DMARC`, `SPF`, `BINDVERSION`, `AXFR`.

You can also put the module in the URL instead of the body:

```bash
curl -X POST -d 'example.com' http://localhost:8080/job/MX
```

Plain-text bodies work too — one domain per line:

```bash
printf 'example.com\nexample.org\n' | curl -X POST --data-binary @- http://localhost:8080/job/A
```

### Output formats

The default `v2` envelope nests results per module and includes per-lookup
`duration`/`trace`. For the legacy flat envelope (matching zdns v1 output),
start with:

```bash
./zdns-rest --output-format=v1
```

## Async jobs

For large batches, use the job API instead of blocking on `/job`:

```bash
# Submit — returns immediately with a job ID
curl -X POST -H "Content-Type: application/json" \
  -d '{"module": "MX", "queries": ["example.com", "example.org"]}' \
  http://localhost:8080/jobs
# {"job_id":"job-...","status":"pending", ...}

# Poll status
curl http://localhost:8080/jobs/job-...

# Fetch results (NDJSON) once status is "completed"
curl http://localhost:8080/jobs/job-.../results

# Cancel a pending/running job
curl -X DELETE http://localhost:8080/jobs/job-...
```

## Configuration

Every flag also works as an env var (`ZDNS_` + upper-snake name) or in a
config file (`--config /path/zdns-rest.yaml`, or auto-detected
`~/.zdns-rest.{yaml,conf}`). Examples:

```bash
# Env vars
ZDNS_BIND_PORT=9090 ZDNS_API_KEY=secret ./zdns-rest

# Config file (~/.zdns-rest.yaml)
bind-port: 9090
api-key: secret
cache-enabled: true
name-servers: [8.8.8.8, 1.1.1.1]
```

Useful flags for a first run:

| Flag | Purpose |
|------|---------|
| `--name-servers 8.8.8.8,1.1.1.1` | resolvers to use (default: system) |
| `--iterative` | resolve from the root servers yourself |
| `--verbosity 5` | debug logging |
| `--api-key <key>` | require `X-API-Key` / `?api_key=` on all endpoints |
| `--rate-limit 100` | per-IP request limit (`--rate-limit-window` seconds) |
| `--cache-enabled` | cache definitive answers (TTL `--cache-ttl`) |
| `--output-format v1` | legacy flat response envelope |

Full flag reference: `./zdns-rest --help` or [README.md](README.md).

## What's next

- [API.md](API.md) — endpoints, error codes, auth, CORS, circuit breaker
- [ARCHITECTURE.md](ARCHITECTURE.md) — how requests and jobs flow through
  the internals
- Production notes: put it behind your ingress/reverse proxy (set
  `--trusted-proxies` so client IPs survive), enable `--tls-*` or terminate
  TLS upstream, and export `/metrics` to Prometheus.
