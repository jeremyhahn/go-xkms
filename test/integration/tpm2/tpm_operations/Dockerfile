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

# Create test bootstrap script that provisions TPM before running tests
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "=== TPM Operations Test Suite ==="\n\
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
echo "Running TPM operations tests with coverage..."\n\
mkdir -p /app/coverage\n\
\n\
# Run tests for HashSequence, SignValidate, CreateIDevID flows\n\
go test -v -p 1 -tags="integration tpm2 tpmops" -timeout=30m \\\n\
    -coverprofile=/app/coverage/tpm_operations.out \\\n\
    -covermode=atomic \\\n\
    -coverpkg=github.com/jeremyhahn/go-tpm/tpm2 \\\n\
    ./test/integration/tpm_operations/...\n\
\n\
if [ -f /app/coverage/tpm_operations.out ]; then\n\
    echo "TPM operations test coverage:"\n\
    go tool cover -func=/app/coverage/tpm_operations.out | tail -1\n\
fi\n\
' > /app/run_tpm_ops_tests.sh && chmod +x /app/run_tpm_ops_tests.sh

CMD ["/app/run_tpm_ops_tests.sh"]
