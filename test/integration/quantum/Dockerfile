# Dockerfile for quantum-safe cryptography integration tests
# Pure-Go implementations: circl (ML-DSA) and crypto/mlkem (ML-KEM)
# No CGO or external libraries required.
FROM golang:1.27.4-bookworm
# apt retries transient fetch errors with backoff (go-xkms#342).
COPY build/docker/devcontainer/apt-retries.conf /etc/apt/apt.conf.d/80-retries

ENV GOTOOLCHAIN=auto
ENV GOWORK=off

# Install minimal build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
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

# Default command runs tests
CMD ["go", "test", "-v", "-tags=integration codec_cbor codec_json codec_msgpack gms_pure_go", "-timeout", "30m", "./test/integration/quantum/..."]
