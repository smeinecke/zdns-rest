.PHONY: all build test test-integration lint fmt coverage clean help

# Build variables
BINARY_NAME := zdns-rest
GO := go
GOFLAGS := -v

# Default target
all: build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .

## test: Run unit tests with race detection
test:
	@echo "Running unit tests..."
	$(GO) test -v -race ./...

## test-integration: Run integration tests
test-integration:
	@echo "Running integration tests..."
	$(GO) test -v -race -tags=integration ./...

## lint: Run golangci-lint
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	gofmt -w .

## coverage: Generate and display test coverage
coverage:
	@echo "Generating coverage report..."
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

## coverage-html: Generate HTML coverage report
coverage-html: coverage
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html in your browser"

## tidy: Tidy go modules
tidy:
	@echo "Tidying go modules..."
	$(GO) mod tidy

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME) coverage.out coverage.html

## docker-build: Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):latest .

## docker-run: Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run -p 8080:8080 $(BINARY_NAME):latest

## help: Show this help message
help:
	@echo "Available targets:"
	@awk '/^[a-zA-Z_-]+:/ { helpMsg = match(lastLine, /^## (.*)/); if (helpMsg) { target = $$1; sub(/:/, "", target); printf "  \033[36m%-20s\033[0m %s\n", target, substr(lastLine, RSTART + 3, RLENGTH) } } { lastLine = $$0 }' $(MAKEFILE_LIST)
