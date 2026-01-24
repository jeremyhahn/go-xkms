# Dockerfile for FROST threshold signature integration tests
FROM golang:bookworm

ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy SDK module first (required for go.mod replace directive)
COPY sdk/go ./sdk/go

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build the CLI with frost support for CLI tests
RUN --mount=type=bind,source=.,target=/workspace \
    go build -tags="frost" -o /usr/local/bin/keychainctl ./cmd/keychainctl || true

# Default command runs tests
CMD ["go", "test", "-v", "-tags=integration frost", "-timeout", "30m", "./test/integration/frost/..."]
