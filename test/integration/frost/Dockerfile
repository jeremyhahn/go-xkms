# Dockerfile for FROST threshold signature integration tests
FROM golang:1.26.6-bookworm

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

# Materialize /tmp/go.work + GOWORK (resolves the in-house module workspace from
# the bind-mounted siblings) before running the test CMD passed as args.
ENTRYPOINT ["bash", ".devcontainer/scripts/ensure-gowork.sh"]

# Build the frost-enabled CLI at runtime (after the workspace is resolved), then
# run the integration tests. The CLI is required by the multi-protocol CLI tests.
CMD ["sh", "-c", "go build -tags=frost -o /usr/local/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack' -timeout 30m ./test/integration/frost/..."]
