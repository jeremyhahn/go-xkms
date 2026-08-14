FROM golang:1.26.5-bookworm

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

# Materialize /tmp/go.work + GOWORK (resolves the in-house module workspace from
# the bind-mounted siblings) before running the test CMD passed as args.
ENTRYPOINT ["bash", ".devcontainer/scripts/ensure-gowork.sh"]

CMD ["go", "test", "-v", "-tags=integration pkcs8 codec_cbor codec_json codec_msgpack", "./test/integration/pkcs8/..."]
