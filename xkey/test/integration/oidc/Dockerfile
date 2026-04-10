# Dockerfile for xkey OIDC integration tests
# Uses ORY Hydra as the OIDC provider

FROM golang:1.26.1-bookworm

# Install dependencies (libusb-dev needed for gousb CGO build)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        netcat-openbsd \
        jq \
        libusb-1.0-0-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ORY Hydra CLI for client management
RUN bash -c "bash <(curl https://raw.githubusercontent.com/ory/meta/master/install.sh) -b /usr/local/bin hydra v2.2.0"

# Setup workspace — copy go-xkms source and go-qrdb (needed by replace directive)
WORKDIR /workspace
COPY . .
COPY --from=go-qrdb . /go-qrdb/
COPY --from=go-quicraft . /go-quicraft/

# Environment
ENV CGO_ENABLED=1 \
    GOPROXY=https://proxy.golang.org,direct

# Pre-build the xkey binary so tests don't need to compile at runtime
RUN cd /workspace/xkey && go build -buildvcs=false -o /usr/local/bin/xkey ./cmd/xkey

# Copy setup script
COPY xkey/test/integration/oidc/setup-hydra.sh /setup-hydra.sh
RUN chmod +x /setup-hydra.sh

# Run setup and tests
CMD ["bash", "-c", "\
    echo 'Waiting for Hydra to be ready...'; \
    for i in {1..30}; do \
        if curl -s ${HYDRA_PUBLIC_URL}/health/ready > /dev/null 2>&1; then \
            echo 'Hydra is ready'; \
            break; \
        fi; \
        if [ $i -eq 30 ]; then \
            echo 'Hydra failed to become ready'; \
            exit 1; \
        fi; \
        sleep 1; \
    done; \
    /setup-hydra.sh; \
    SETUP_STATUS=$?; \
    if [ $SETUP_STATUS -ne 0 ]; then \
        echo 'Hydra client setup failed'; \
        exit $SETUP_STATUS; \
    fi; \
    source /tmp/xkey-oidc-test-env.sh; \
    cd /workspace/xkey && XKEY_BINARY=/usr/local/bin/xkey go test -v -buildvcs=false -tags integration ./test/integration/oidc/... -timeout 5m; \
    TEST_STATUS=$?; \
    exit $TEST_STATUS"]
