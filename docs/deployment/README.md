# Deployment Documentation

This directory contains deployment guides for go-keychain.

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
  - Development and production setups
  - Common use cases

## Deployment Options

go-keychain provides multiple deployment options:

1. **Unified Server** - Run all protocols (REST, gRPC, QUIC, MCP) in one container
2. **Protocol-Specific Servers** - Deploy individual protocol servers for focused use cases
3. **CLI Tool** - Command-line interface for direct keychain operations

See the individual guides for detailed instructions on each deployment option.
