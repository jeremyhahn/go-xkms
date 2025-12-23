# Dockerfile for FROST threshold signature integration tests
FROM golang:1.25.5-bookworm

ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Download dependencies (will be overridden by volume mount)
COPY go.mod go.sum ./
RUN go mod download

# Build the CLI with frost support for CLI tests
RUN --mount=type=bind,source=.,target=/workspace \
    go build -tags="frost" -o /usr/local/bin/keychain ./cmd/cli/main.go || true

# Default command runs tests
CMD ["go", "test", "-v", "-tags=integration frost", "-timeout", "30m", "./test/integration/frost/..."]
