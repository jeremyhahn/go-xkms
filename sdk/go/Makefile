.PHONY: all test test-coverage lint clean build examples

# Go SDK Makefile

all: lint test build

# Run unit tests
test:
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run linter
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping lint"; \
	fi

# Build examples
examples:
	go build -o bin/basic ./examples/basic
	go build -o bin/embedded ./examples/embedded
	go build -o bin/mtls ./examples/mtls

# Build all
build:
	go build ./...

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html
	rm -rf bin/

# Update dependencies
deps:
	go mod tidy

# Show module info
info:
	go list -m all
