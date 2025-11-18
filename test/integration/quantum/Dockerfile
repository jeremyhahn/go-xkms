# Dockerfile for quantum-safe cryptography integration tests
FROM golang:1.25-bookworm

ENV GOTOOLCHAIN=auto

# Install build dependencies for liboqs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    cmake \
    ninja-build \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cd /tmp/liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON .. && \
    ninja && \
    ninja install && \
    ldconfig && \
    rm -rf /tmp/liboqs

# Create liboqs-go.pc for the Go bindings (liboqs-go expects this name)
RUN mkdir -p /usr/local/lib/pkgconfig && \
    cat > /usr/local/lib/pkgconfig/liboqs-go.pc << 'EOF'
prefix=/usr/local
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: liboqs-go
Description: Open Quantum Safe liboqs library for Go bindings
Version: 0.9.0
Libs: -L${libdir} -loqs
Cflags: -I${includedir}
EOF

# Set library paths for CGO
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV CGO_LDFLAGS="-L/usr/local/lib"
ENV CGO_CFLAGS="-I/usr/local/include"

WORKDIR /workspace

# Download dependencies (will be overridden by volume mount)
COPY go.mod go.sum ./
RUN go mod download

# Default command runs tests
CMD ["go", "test", "-v", "-tags=integration quantum", "-timeout", "30m", "./test/integration/quantum/..."]
