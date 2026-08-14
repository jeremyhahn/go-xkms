FROM golang:1.26.6-bookworm

RUN apt-get update && apt-get install -y ca-certificates curl netcat-openbsd && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

# Materialize /tmp/go.work + GOWORK before running the test CMD passed as args.
ENTRYPOINT ["bash", ".devcontainer/scripts/ensure-gowork.sh"]

CMD ["sh", "-c", "echo 'Waiting for Vault to be ready...'; \
     while ! curl -sf http://vault:8200/v1/sys/health > /dev/null; do sleep 1; done; \
     echo 'Vault is ready!'; \
     echo 'Enabling Transit engine...'; \
     curl -X POST -H 'X-Vault-Token: root' -d '{\"type\":\"transit\"}' http://vault:8200/v1/sys/mounts/transit; \
     echo ''; \
     echo 'Transit engine setup complete!'; \
     echo 'Running tests...'; \
     go test -v -tags='integration vault codec_cbor codec_json codec_msgpack' ./test/integration/vault/..."]
