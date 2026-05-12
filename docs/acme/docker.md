# Docker Multi-Architecture Support

This document describes the Docker multi-architecture build system for go-trusted-ca.

## Overview

The go-trusted-ca project supports multi-architecture Docker images for:
- **linux/amd64** - x86_64 systems
- **linux/arm64** - ARM64 systems (including Apple Silicon, Raspberry Pi 4+, AWS Graviton)

Images are automatically built and published to GitHub Container Registry (ghcr.io) via GitHub Actions.

## Quick Start

### Pull Pre-built Images

```bash
# Pull latest version
docker pull ghcr.io/jeremyhahn/go-trusted-ca:latest

# Pull specific version
docker pull ghcr.io/jeremyhahn/go-trusted-ca:v1.0.0

# Docker will automatically select the correct architecture for your platform
```

### Run the Server

```bash
# Run with default configuration
docker run -p 8080:8080 -p 8081:8081 ghcr.io/jeremyhahn/go-trusted-ca:latest

# Run with custom configuration
docker run -p 8080:8080 -p 8081:8081 \
  -v $(pwd)/config:/etc/trusted-acme \
  -v $(pwd)/data:/var/lib/trusted-acme \
  ghcr.io/jeremyhahn/go-trusted-ca:latest
```

## Building Multi-Arch Images Locally

### Prerequisites

- Docker 19.03 or newer
- Docker Buildx (included in Docker Desktop)

### Build for All Architectures

```bash
# Setup buildx (first time only)
make docker-buildx-setup

# Build multi-arch images (not pushed)
make docker-multiarch-build

# Build and load to local Docker (native arch only)
make docker-buildx-load
```

### Build and Push to Registry

```bash
# Login to GitHub Container Registry
export GITHUB_TOKEN=your_github_token
make docker-login-ghcr

# Build and push multi-arch images
make docker-multiarch-push
```

## Makefile Targets

### Local Development

```bash
# Build single-arch image for local testing
make docker-build

# Run locally built image
make docker-run
```

### Multi-Architecture Builds

```bash
# Setup Docker buildx
make docker-buildx-setup

# Build multi-arch images
make docker-multiarch-build

# Build and push to ghcr.io
make docker-multiarch-push

# Build and load to local Docker
make docker-buildx-load
```

### Registry Authentication

```bash
# Login to GitHub Container Registry
export GITHUB_TOKEN=your_github_token
make docker-login-ghcr
```

## GitHub Actions Workflow

The `.github/workflows/docker.yml` workflow automatically:

1. **Builds** multi-arch images on push to main/master/develop branches and tags
2. **Pushes** images to GitHub Container Registry (ghcr.io)
3. **Tags** images based on git branches and tags:
   - `latest` - latest commit on default branch
   - `v1.2.3` - semantic version tags
   - `develop` - develop branch
   - `sha-abcd123` - commit SHA
4. **Scans** images for vulnerabilities using Trivy
5. **Generates** SBOM and build provenance attestations
6. **Tests** images on both amd64 and arm64 runners

### Workflow Triggers

- Push to `master`, `main`, or `develop` branches
- Push of version tags (`v*`)
- Pull requests (builds but doesn't push)
- Manual workflow dispatch

### Required Secrets

No additional secrets required - the workflow uses the built-in `GITHUB_TOKEN`.

## Dockerfile Architecture

The Dockerfile uses multi-stage builds for optimal image size:

### Build Stage
- Uses `golang:alpine` as builder
- Supports cross-compilation via `TARGETOS` and `TARGETARCH` build args
- Builds binaries with `-trimpath` and `-ldflags="-w -s"` for smaller size
- Leverages layer caching for faster builds

### Runtime Stage
- Uses minimal `alpine:3.21` base image
- Runs as non-root user (`acme`)
- Includes only runtime dependencies
- Adds OCI image labels for metadata

### Build Arguments

The Dockerfile accepts the following build arguments:

- `VERSION` - Version string (from git tags)
- `BUILD_DATE` - ISO 8601 build timestamp
- `VCS_REF` - Git commit SHA
- `TARGETPLATFORM` - Target platform (e.g., linux/amd64)
- `TARGETOS` - Target OS (linux)
- `TARGETARCH` - Target architecture (amd64, arm64)

## Image Labels

Images include OCI-compliant labels:

```dockerfile
org.opencontainers.image.title="go-trusted-ca"
org.opencontainers.image.description="ACME RFC-8555 compliant server with TPM and secure keystore support"
org.opencontainers.image.vendor="Jeremy Hahn"
org.opencontainers.image.source="https://github.com/jeremyhahn/go-trusted-ca"
org.opencontainers.image.version="v1.0.0"
org.opencontainers.image.created="2026-01-03T..."
org.opencontainers.image.revision="abc123"
org.opencontainers.image.platform="linux/amd64"
```

## Advanced Usage

### Build Specific Architecture

```bash
# Build only for amd64
docker buildx build --platform linux/amd64 -t go-trusted-ca:amd64 .

# Build only for arm64
docker buildx build --platform linux/arm64 -t go-trusted-ca:arm64 .
```

### Custom Build Arguments

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v1.2.3 \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg VCS_REF=$(git rev-parse --short HEAD) \
  -t go-trusted-ca:custom \
  .
```

### Inspect Multi-Arch Manifest

```bash
# View manifest for multi-arch image
docker buildx imagetools inspect ghcr.io/jeremyhahn/go-trusted-ca:latest

# Example output:
# Name:      ghcr.io/jeremyhahn/go-trusted-ca:latest
# MediaType: application/vnd.docker.distribution.manifest.list.v2+json
# Digest:    sha256:abc123...
#
# Manifests:
#   Name:      ghcr.io/jeremyhahn/go-trusted-ca:latest@sha256:def456...
#   MediaType: application/vnd.docker.distribution.manifest.v2+json
#   Platform:  linux/amd64
#
#   Name:      ghcr.io/jeremyhahn/go-trusted-ca:latest@sha256:789abc...
#   MediaType: application/vnd.docker.distribution.manifest.v2+json
#   Platform:  linux/arm64
```

## Image Size Optimization

The multi-stage build and Alpine base keep images small:

- **amd64**: ~25MB compressed
- **arm64**: ~23MB compressed

Optimization techniques used:
- Multi-stage builds (separate build and runtime stages)
- Alpine Linux base (minimal footprint)
- Static compilation with CGO disabled
- Binary stripping (`-ldflags="-w -s"`)
- Trimmed build paths (`-trimpath`)
- Layer caching via GitHub Actions cache

## Security Features

### Non-Root User
Images run as the `acme` user (non-root) for security.

### Vulnerability Scanning
All pushed images are scanned with Trivy for known vulnerabilities.

### Supply Chain Security
- SBOM (Software Bill of Materials) generated for each image
- Build provenance attestation for traceability
- Images signed and verified

### Minimal Attack Surface
- Minimal base image (Alpine)
- Only required runtime dependencies
- No build tools in runtime image

## Troubleshooting

### Buildx Not Found

```bash
# Install buildx plugin
docker buildx install

# Verify installation
docker buildx version
```

### Platform Not Supported

If you see "platform not supported" errors:

```bash
# Ensure QEMU is installed and configured
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

# Verify available platforms
docker buildx ls
```

### Push Permission Denied

```bash
# Ensure you're logged in to ghcr.io
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Verify authentication
docker logout ghcr.io
docker login ghcr.io
```

## CI/CD Integration

### GitHub Actions

The provided workflow is production-ready and includes:
- Multi-arch builds
- Automated testing
- Security scanning
- Provenance generation
- Registry publishing

### Other CI Systems

For other CI systems (GitLab, Jenkins, etc.), use:

```bash
# Setup
docker buildx create --use

# Build and push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --push \
  -t registry/image:tag \
  .
```

## Performance Considerations

### Build Times

Multi-arch builds are parallelized by buildx:
- Native arch builds are fast (use host CPU)
- Cross-platform builds use QEMU (slower but still efficient)
- GitHub Actions caching reduces subsequent build times

### Optimization Tips

1. **Use layer caching**: Dependencies are cached in separate layers
2. **Minimize context**: Use `.dockerignore` to exclude unnecessary files
3. **Parallel builds**: Buildx builds all platforms in parallel
4. **Cache from registry**: Use `--cache-from` for faster rebuilds

## References

- [Docker Buildx Documentation](https://docs.docker.com/buildx/working-with-buildx/)
- [Multi-platform Images](https://docs.docker.com/build/building/multi-platform/)
- [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [OCI Image Spec](https://github.com/opencontainers/image-spec)
