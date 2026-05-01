# CI/CD Pipeline

This document describes the continuous integration and deployment pipeline for zdns-rest.

## Overview

The CI/CD pipeline is defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and runs on GitHub Actions. It includes automated testing, cross-platform builds, Docker image publishing, and release artifact generation.

## Triggers

The pipeline runs on:

- **Push** to `main` or `master` branches
- **Pull requests** targeting `main` or `master`
- **Release** creation (triggers Docker build and binary release)
- **Manual dispatch** via GitHub Actions UI

## Pipeline Stages

```
┌─────────┐    ┌─────────┐    ┌─────────────────┐    ┌─────────┐    ┌─────────┐
│  Lint   │───▶│  Test   │───▶│ Integration Test│───▶│  Build  │───▶│ Release │
└─────────┘    └─────────┘    └─────────────────┘    └─────────┘    └─────────┘
                    │                                   │
                    ▼                                   ▼
              ┌─────────┐                        ┌──────────────┐
              │ Coverage│                        │ Cross-Platform│
              │ Upload  │                        │    Build     │
              └─────────┘                        └──────────────┘
                                                      │
                                                      ▼
                                              ┌──────────────┐
                                              │ Docker Build │
                                              │    & Push    │
                                              └──────────────┘
```

## Jobs

### 1. Lint

Runs static analysis and code quality checks:

- **Tool**: `golangci-lint` (latest version)
- **Go Version**: 1.24
- **Timeout**: 5 minutes
- **Checks**:
  - Code style and patterns
  - Potential bugs
  - Performance issues

### 2. Test

Runs the complete test suite:

- **Go Version**: 1.24
- **Commands**:
  ```bash
  go mod download
  go vet ./...
  gofmt -l .  # Format check
  go build -v ./...
  go test -v -race -coverprofile=coverage.out ./...
  ```

- **Coverage Threshold**: 70% minimum
- **Artifacts**: Coverage uploaded to Codecov

### 3. Integration Test

Runs end-to-end tests with a real server:

- **Build Tag**: `integration`
- **Command**: `go test -v -race -tags=integration ./...`
- **Timeout**: 5 minutes
- **Continue on Error**: Yes (due to external DNS dependency)
- **Tests**:
  - HTTP API endpoints
  - Authentication middleware
  - Cache functionality
  - Async job processing
  - Health/readiness probes

### 4. Build

Builds the binary for the current platform:

- **Output**: `zdns-rest`
- **Depends on**: lint, test

### 5. Build Cross-Platform

Creates binaries for multiple platforms:

| GOOS    | GOARCH        |
|---------|---------------|
| linux   | 386, amd64, arm64 |
| windows | 386, amd64        |
| darwin  | amd64, arm64      |

- **Artifacts**: Uploaded to GitHub Actions
- **Exclusions**: darwin/386, windows/arm64 (not supported)

### 6. Docker

Builds and publishes multi-architecture Docker images:

- **Platforms**: `linux/amd64`, `linux/arm64`
- **Registries**:
  - Docker Hub (`secrets.DOCKER_USERNAME`)
  - GitHub Container Registry (`ghcr.io`)
- **Tags**:
  - Semantic version tags
  - `latest` for default branch
- **Features**:
  - BuildKit with caching
  - QEMU for cross-platform builds

### 7. Release

Publishes pre-built binaries to GitHub Releases:

- **Trigger**: Release creation only
- **Tool**: `wangyoucao577/go-release-action`
- **Platforms**: Same matrix as cross-platform build
- **Includes**: LICENSE, README.md, Dockerfile, docker-compose.yml

## Required Secrets

| Secret | Used In | Purpose |
|--------|---------|---------|
| `DOCKER_USERNAME` | Docker job | Docker Hub login |
| `DOCKER_PASSWORD` | Docker job | Docker Hub authentication |
| `GITHUB_TOKEN` | Docker, Release jobs | GHCR login, release artifacts |

## Local Development

Run the same checks locally:

```bash
# Lint (requires golangci-lint)
golangci-lint run ./...

# Run tests with coverage
make test
make coverage

# Run integration tests
make test-integration

# Format code
gofmt -w .

# Build binary
make build

# Build Docker image
make docker-build
```

## Coverage Requirements

- **Minimum Threshold**: 70%
- **Upload**: Codecov with `fail_ci_if_error: false`
- **View Report**: `go tool cover -html=coverage.out -o coverage.html`

## Release Process

1. Create a new GitHub Release with a semantic version tag (e.g., `v1.0.0`)
2. The `docker` and `release` jobs trigger automatically
3. Docker images are pushed to Docker Hub and GHCR
4. Binary artifacts are attached to the release

## Matrix Strategy

The cross-platform build uses a matrix strategy for efficiency:

```yaml
strategy:
  matrix:
    goos: [linux, windows, darwin]
    goarch: ["386", amd64, arm64]
  exclude:
    - goarch: "386"
      goos: darwin
    - goarch: arm64
      goos: windows
```

This produces 7 unique build targets.
