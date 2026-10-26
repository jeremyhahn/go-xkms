FROM golang:1.27.3-bookworm
# apt retries transient fetch errors with backoff (go-xkms#342).
COPY build/docker/devcontainer/apt-retries.conf /etc/apt/apt.conf.d/80-retries

RUN apt-get update && apt-get install -y ca-certificates curl netcat-openbsd && rm -rf /var/lib/apt/lists/*

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

CMD ["sh", "-c", "echo 'Waiting for Vault to be ready...'; \
     while ! curl -sf http://vault:8200/v1/sys/health > /dev/null; do sleep 1; done; \
     echo 'Vault is ready!'; \
     echo 'Enabling Transit engine...'; \
     curl -X POST -H 'X-Vault-Token: root' -d '{\"type\":\"transit\"}' http://vault:8200/v1/sys/mounts/transit; \
     echo ''; \
     echo 'Transit engine setup complete!'; \
     echo 'Running tests...'; \
     go test -v -tags='integration vault codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/vault/..."]
