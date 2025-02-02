# zdns-rest

A simple REST API for zdns. See [zmap/zdns](https://github.com/zmap/zdns) for more information.


## Build

go build -o zdns-rest cmd/main.go

## Run

./zdns-rest --bind-ip 127.0.0.1 --bind-port 8080

## API

### POST /job/{lookup}

- `lookup`: string, name of the lookup module to use (e.g. MX, A, AAAA, etc.) - see [zmap/zdns](https://github.com/zmap/zdns?tab=readme-ov-file#raw-dns-modules) for more information, optional (default: A)

- Body:
  - `queries`: array of strings, names to lookup
  - `module`: string, name of the lookup module to use (e.g. MX, A, AAAA, etc.) (optional, default: A)

- Response: JSON response, delimited by newlines - see [zmap/zdns](https://github.com/zmap/zdns?tab=readme-ov-file#raw-dns-modules)
  - `data`: array of DNS records
  - `name`: string, name of the lookup
  - `status`: string, status of the lookup
  - `timestamp`: string, timestamp of the lookup

### GET /ping

- Body: empty

- Response: JSON string with code 1000 and message "Command completed successfully"


## Example

```bash
$ ./zdns-rest --iterative
$ curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"module": "MXLOOKUP", "queries": ["google.com", "bing.com"]}' \
  http://localhost:8080/job
```

```json
{
  "data": {
    "exchanges": [
      {
        "class": "IN",
        "ipv4_addresses": [
          "74.125.71.27",
          "74.125.71.26",
          "74.125.133.27",
          "74.125.133.26",
          "64.233.166.27"
        ],
        "name": "smtp.google.com",
        "preference": 10,
        "ttl": 300,
        "type": "MX"
      }
    ]
  },
  "name": "google.com",
  "status": "NOERROR",
  "timestamp": "2025-02-02T17:28:04+01:00"
}
{
  "data": {
    "exchanges": [
      {
        "class": "IN",
        "name": "bing-com.mail.protection.outlook.com",
        "preference": 10,
        "ttl": 3600,
        "type": "MX"
      }
    ]
  },
  "name": "bing.com",
  "status": "NOERROR",
  "timestamp": "2025-02-02T18:01:47+01:00"
}
```
