FROM golang:1.26.1-bookworm

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["go", "test", "-v", "-tags=integration pkcs8 codec_cbor codec_json codec_msgpack", "./test/integration/pkcs8/..."]
