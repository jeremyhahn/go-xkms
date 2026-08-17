FROM golang:1.26.6-bookworm

# Install dependencies including tcpdump for optional packet capture debugging
RUN apt-get update && apt-get install -y \
    ca-certificates \
    netcat-openbsd \
    build-essential \
    libssl-dev \
    tcpdump \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV GOWORK=off
ENV CGO_ENABLED=1

WORKDIR /app

# Bake the source into the image at build time -- see pkcs8/Dockerfile's
# identical comment for why the compose file's runtime bind mount
# (`volumes: - ../../..:/app`) is unreliable on the Gitea Actions runner.
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .

# Run all TPM2 integration tests including encryption verification
CMD ["sh", "-c", "echo 'Waiting for TPM simulator to be ready...'; while ! nc -z tpm-simulator 2421; do sleep 1; done; echo 'TPM simulator is ready, running tests...'; go test -v -tags='integration tpm2 codec_cbor codec_json codec_msgpack gms_pure_go' -timeout 30m ./test/integration/tpm2/..."]
