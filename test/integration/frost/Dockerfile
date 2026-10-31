# Dockerfile for FROST threshold signature integration tests
FROM golang:1.27.3-bookworm

ENV GOTOOLCHAIN=auto
ENV GOWORK=off

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Bake the source into the image rather than bind-mounting the checkout: on
# the CI runner the docker daemon resolves bind-mount sources on its own host,
# not in the job container that holds the checkout (see pkcs8/Dockerfile,
# DS-4181).
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

# In-house modules resolve from Gitea tags through the optional gomodauth
# BuildKit secret (dependency-resolution.md §6), as in pkcs8/Dockerfile.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .

# Build the frost-enabled CLI at runtime, then
# run the integration tests. The CLI is required by the multi-protocol CLI tests.
CMD ["sh", "-c", "go build -tags=frost -o /usr/local/bin/xkmsctl ./cmd/xkmsctl && go test -v -tags='integration frost codec_cbor codec_json codec_msgpack gms_pure_go' -timeout 30m ./test/integration/frost/..."]
