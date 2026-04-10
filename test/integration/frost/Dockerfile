# Dockerfile for FROST threshold signature integration tests
FROM golang:1.26.1-bookworm

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

# Copy the xkey module files (required for go.mod replace directive)
COPY xkey/go.mod xkey/go.sum ./xkey/

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download || true

# Build the CLI with frost support for CLI tests
RUN --mount=type=bind,source=.,target=/workspace \
    go build -tags="frost" -o /usr/local/bin/xkmsctl ./cmd/xkmsctl || true

# Default command runs tests
CMD ["go", "test", "-v", "-tags=integration frost codec_cbor codec_json codec_msgpack", "-timeout", "30m", "./test/integration/frost/..."]
