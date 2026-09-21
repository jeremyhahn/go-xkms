FROM golang:1.27.0-bookworm

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV GOWORK=off

WORKDIR /app

# Bake the source into the image at build time rather than relying on the
# compose file's runtime bind mount (`volumes: - ../../..:/app`). On the
# Gitea Actions runner, that relative path resolves against the JOB
# CONTAINER's filesystem (e.g. /workspace/jeremyhahn/go-xkms), which the
# HOST docker daemon doesn't share -- the mount silently succeeds against an
# unrelated (often empty) host directory instead of erroring, so /app ends
# up without a go.mod. Runner-log-proven (task 3001): "pattern
# ./test/integration/pkcs8/...: directory prefix test/integration/pkcs8 does
# not contain main module or its selected dependencies". `docker buildx`'s
# COPY doesn't have this problem -- it streams the build context over the
# API rather than asking the daemon to resolve a bind-mount path itself.
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

# In-house modules resolve from Gitea tags (dependency-resolution.md §6). The
# fetch token arrives as a BuildKit secret, never a build arg or ENV, mounted
# on tmpfs for this RUN alone and never becoming a layer. Optional by
# design: with no secret supplied these modules resolve from the public
# proxy once tags are mirrored (§7).
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .

CMD ["go", "test", "-v", "-tags=integration pkcs8 codec_cbor codec_json codec_msgpack gms_pure_go", "./test/integration/pkcs8/..."]
