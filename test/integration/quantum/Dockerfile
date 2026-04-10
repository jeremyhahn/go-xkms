# Dockerfile for quantum-safe cryptography integration tests
# Pure-Go implementations: circl (ML-DSA) and crypto/mlkem (ML-KEM)
# No CGO or external libraries required.
FROM golang:1.26.1-bookworm

ENV GOTOOLCHAIN=auto

# Install minimal build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy SDK module first (required for go.mod replace directive)
COPY sdk/go ./sdk/go

# Copy the xkey module files (required for go.mod replace directive)
COPY xkey/go.mod xkey/go.sum ./xkey/

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download || true

# Default command runs tests
CMD ["go", "test", "-v", "-tags=integration codec_cbor codec_json codec_msgpack", "-timeout", "30m", "./test/integration/quantum/..."]
