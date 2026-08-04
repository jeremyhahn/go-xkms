FROM golang:1.26.1-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

# Materialize /tmp/go.work + GOWORK before running the test CMD passed as args.
ENTRYPOINT ["bash", ".devcontainer/scripts/ensure-gowork.sh"]

CMD ["sh", "-c", "echo 'Waiting for Floci GCP to be ready...'; while ! curl -sf http://floci-gcp:4588/health > /dev/null; do sleep 1; done; echo 'Floci GCP is ready, running tests...'; go test -v -tags='integration gcpkms codec_cbor codec_json codec_msgpack' ./test/integration/gcpkms/..."]
