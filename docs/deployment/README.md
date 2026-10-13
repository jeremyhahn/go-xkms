# Deployment Documentation

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: index of the container deployment guides in this folder; service units live in `deploy/`.

This directory contains deployment guides for go-xkms.

## Available Guides

- [docker.md](docker.md) - Comprehensive Docker deployment guide covering:
  - Multi-protocol server deployment
  - Individual protocol servers (REST, gRPC, QUIC, MCP)
  - Configuration management
  - TLS and mTLS setup
  - Security best practices
  - Performance tuning
  - Troubleshooting

- [docker-quickstart.md](docker-quickstart.md) - Quick start guide for Docker deployment:
  - 5-minute setup
  - Basic configuration examples
  - Production setup with `docker-compose.production.yml`
  - Common use cases

## Deployment Options

go-xkms provides multiple deployment options:

1. **Unified Server** - Run all protocols (REST, gRPC, QUIC, MCP) in one container
2. **Protocol-Specific Servers** - Deploy individual protocol servers for focused use cases
3. **CLI Tool** - Command-line interface for direct xkms operations

See the individual guides for detailed instructions on each deployment option.
For systemd and OpenRC service units, see [deploy/README.md](../../deploy/README.md).
