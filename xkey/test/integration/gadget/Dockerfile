FROM ubuntu:24.04

ENV GOTOOLCHAIN=auto
ENV DEBIAN_FRONTEND=noninteractive

# Install Go from the official tarball.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && GOVERSION=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1) \
    && curl -fsSL "https://go.dev/dl/${GOVERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install build dependencies. Ubuntu 24.04 has gcc-13 natively.
RUN apt-get update && apt-get install -y --no-install-recommends \
    kmod \
    usbutils \
    build-essential \
    gcc-13 \
    make \
    git \
    libelf-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/x86_64-linux-gnu-gcc-13 /usr/local/bin/gcc-13

WORKDIR /src

# Copy go module files first for better layer caching.
COPY go.mod go.sum ./

# Copy sub-module go.mod/go.sum files required by replace directives.
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

# Copy local replace directive dependencies.
COPY --from=go-qrdb . /go-qrdb/
COPY --from=go-quicraft . /go-quicraft/

RUN cd xkey && go mod download

# Copy full source.
COPY . .

# Copy the dummy_hcd build script.
COPY xkey/test/integration/gadget/build-dummy-hcd.sh /usr/local/bin/build-dummy-hcd.sh
RUN chmod +x /usr/local/bin/build-dummy-hcd.sh

WORKDIR /src/xkey
