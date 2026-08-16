FROM golang:1.26.6-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Waiting for Floci to be ready...'; while ! curl -sf http://floci:4566/_floci/health > /dev/null; do sleep 1; done; echo 'Floci is ready, running tests...'; go test -v -tags='integration awskms codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/awskms/..."]
