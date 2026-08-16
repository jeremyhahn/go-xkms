FROM golang:1.26.6-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Waiting for Floci GCP to be ready...'; while ! curl -sf http://floci-gcp:4588/health > /dev/null; do sleep 1; done; echo 'Floci GCP is ready, running tests...'; go test -v -tags='integration gcpkms codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/gcpkms/..."]
