FROM golang:1.26.1-bookworm

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download || true

COPY . .

CMD ["go", "test", "-v", "-tags=integration codec_cbor codec_json codec_msgpack", "./test/integration/certstore/..."]
