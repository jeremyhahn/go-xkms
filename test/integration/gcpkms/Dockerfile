FROM golang:1.26.1-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Running GCP KMS integration tests with mock client...'; go test -v -tags='integration gcpkms codec_cbor codec_json codec_msgpack' ./test/integration/gcpkms/..."]
