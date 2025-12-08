FROM golang:1.25.5

# Install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    netcat-openbsd \
    build-essential \
    libssl-dev \
    tpm2-tools \
    libtss2-dev \
    pkg-config \
    openssl \
    && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1
ENV GOTOOLCHAIN=auto
ENV GOPROXY=direct
ENV GOSUMDB=off

WORKDIR /app

# Copy go modules first for caching
COPY go.mod go.sum* ./
RUN go mod download || true

# Copy the entire project
COPY . .

# Pre-generate an EK certificate for testing
RUN mkdir -p /app/testdata/certs && \
    openssl req -x509 -newkey rsa:2048 -keyout /app/testdata/certs/ek_ca.key \
    -out /app/testdata/certs/ek_ca.crt -days 365 -nodes \
    -subj "/C=US/ST=Test/L=Test/O=TestCA/CN=Test EK CA" 2>/dev/null

# Create test bootstrap script that pre-provisions TPM
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "Waiting for TPM simulator..."\n\
for i in $(seq 1 60); do\n\
    if nc -z ${TPM2_SIMULATOR_HOST:-tpm-simulator} ${TPM2_SIMULATOR_PORT:-2421}; then\n\
        echo "TPM simulator is ready"\n\
        break\n\
    fi\n\
    if [ $i -eq 60 ]; then\n\
        echo "Timeout waiting for TPM simulator"\n\
        exit 1\n\
    fi\n\
    sleep 1\n\
done\n\
\n\
echo "Running IDevID-specific integration tests..."\n\
go test -v -p 1 -tags="integration tpm2 idevid" -timeout=30m \\\n\
    -coverprofile=/app/coverage-idevid.out \\\n\
    -covermode=atomic \\\n\
    -coverpkg=github.com/jeremyhahn/go-tpm/tpm2 \\\n\
    ./test/integration/idevid/...\n\
\n\
if [ -f /app/coverage-idevid.out ]; then\n\
    echo "IDevID test coverage:"\n\
    go tool cover -func=/app/coverage-idevid.out | tail -1\n\
fi\n\
' > /app/run_idevid_tests.sh && chmod +x /app/run_idevid_tests.sh

CMD ["/app/run_idevid_tests.sh"]
