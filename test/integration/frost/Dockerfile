# Dockerfile for FROST threshold signature integration tests
FROM golang:1.27.3-bookworm
# apt retries transient fetch errors with backoff (go-xkms#342).
COPY build/docker/devcontainer/apt-retries.conf /etc/apt/apt.conf.d/80-retries

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

# Build the frost-enabled CLI at runtime (after the workspace is resolved), then
# run the integration tests. The CLI is required by the multi-protocol CLI tests.
CMD ["sh", "-c", "go build -tags=frost -o /usr/local/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack gms_pure_go' -timeout 30m ./test/integration/frost/..."]
