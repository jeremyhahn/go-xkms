FROM golang:1.26.1-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

# Materialize /tmp/go.work + GOWORK before running the test CMD passed as args.
ENTRYPOINT ["bash", ".devcontainer/scripts/ensure-gowork.sh"]

CMD ["sh", "-c", "echo 'Running Azure Key Vault integration tests with mock client...'; go test -v -tags='integration azurekv codec_cbor codec_json codec_msgpack' ./test/integration/azurekv/..."]
