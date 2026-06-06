FROM golang:1.26.1-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

# Materialize /tmp/go.work + GOWORK before running the test CMD passed as args.
ENTRYPOINT ["bash", ".devcontainer/scripts/ensure-gowork.sh"]

CMD ["sh", "-c", "echo 'Running GCP KMS integration tests with mock client...'; go test -v -tags='integration gcpkms codec_cbor codec_json codec_msgpack' ./test/integration/gcpkms/..."]
