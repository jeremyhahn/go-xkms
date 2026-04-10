# Stage 1: Build xkey Go binary
FROM golang:1.26.1-bookworm AS go-builder

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    libusb-1.0-0-dev pkg-config gcc libc-dev \
    libgtk-3-dev libwebkit2gtk-4.0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy go module files first for better layer caching.
COPY go.mod go.sum ./

# Copy sub-module go.mod/go.sum files required by replace directives.
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

# Copy local replace directive dependencies.
COPY --from=go-qrdb . /go-qrdb/
COPY --from=go-quicraft . /go-quicraft/

RUN go mod download

# Copy full source and build.
COPY . .
WORKDIR /src/xkey
RUN CGO_ENABLED=1 go build -buildvcs=false -tags "production" -o /usr/local/bin/xkey ./cmd/xkey

# Stage 2: Build browser extension
FROM node:22-bookworm-slim AS ext-builder

WORKDIR /ext
COPY xkey/extension/package*.json ./
RUN npm ci --production=false 2>/dev/null || npm install
COPY xkey/extension/ ./
RUN npm run build 2>/dev/null || echo "Extension build skipped (no build script)"

# Stage 3: Test runner with Playwright + Chrome
FROM node:22-bookworm

# Install runtime dependencies for xkey binary (CGO-linked shared libraries).
# The xkey binary links against Wails GUI libs even in CLI mode.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libusb-1.0-0 \
    libgtk-3-0 \
    libwebkit2gtk-4.0-37 \
    && rm -rf /var/lib/apt/lists/*

# Install Google Chrome as root (needs apt for system deps), then fix ownership
# so the non-root `node` user (UID 1000, provided by base image) can find it.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN npx playwright install --with-deps chrome && \
    chmod -R o+rx /opt/pw-browsers

# Copy xkey binary
COPY --from=go-builder /usr/local/bin/xkey /usr/local/bin/xkey

# Copy built extension
COPY --from=ext-builder /ext/dist /extension/dist
# Fallback: copy source if no build output
COPY --from=ext-builder /ext /extension/src

# Create test workdir owned by the non-root node user.
RUN mkdir -p /tests && chown node:node /tests
WORKDIR /tests
COPY --chown=node:node xkey/test/integration/extension/package.json ./
COPY --chown=node:node xkey/test/integration/extension/tsconfig.json ./
COPY --chown=node:node xkey/test/integration/extension/playwright.config.ts ./
COPY --chown=node:node xkey/test/integration/extension/setup.sh ./
COPY --chown=node:node xkey/test/integration/extension/tests/ ./tests/
COPY --chown=node:node xkey/test/integration/extension/fixtures/ ./fixtures/

# Switch to non-root node user for npm install and test execution.
USER node

RUN npm install
RUN chmod +x setup.sh

CMD ["bash", "-c", "./setup.sh && npx playwright test"]
