FROM golang:1.27.3-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV GOWORK=off

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

CMD ["sh", "-c", "echo 'Waiting for Floci GCP to be ready...'; while ! curl -sf http://floci-gcp:4588/health > /dev/null; do sleep 1; done; echo 'Floci GCP is ready, running tests...'; go test -v -tags='integration gcpkms codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/gcpkms/..."]
