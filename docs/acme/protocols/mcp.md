# MCP Protocol

Model Context Protocol for AI/LLM integration.

> **Correction (go-xkms#942):** there is no `trusted-acme-server` binary,
> no `cactl` binary, and no `TRUSTEDCA_` environment prefix. The real CLI
> is `xkmsctl acme` (`docs/acme-issuance/cli.md`); the ACME admin surface
> is mounted on `xkmsd`'s own unified listener
> (`cmd/xkmsd/admin.go:finalizeAdminModule`). This page's tool catalog,
> addresses and `claude_desktop_config.json` example are otherwise
> unverified against the current wiring.

## Overview

The MCP (Model Context Protocol) API enables AI assistants and Large Language Models to interact with the CA administration interface. It provides structured tool definitions that LLMs can use to perform certificate operations.

## Connection

| Property | Value |
|----------|-------|
| Protocol | MCP over HTTP or stdio |
| Default Port | 9445 |
| Transport | HTTP/HTTPS or stdin/stdout |
| Format | JSON-RPC 2.0 |

## Configuration

### Server

Unverified — see the correction above.

### Client (`xkmsctl acme`)

```bash
xkmsctl acme --acme-server mcp://localhost:9444 status
```

## MCP Tools

The server exposes Admin operations as MCP tools:

### Status Tools

| Tool | Description |
|------|-------------|
| `ca.getStatus` | Get CA status and health |
| `ca.getStats` | Get CA statistics |

### Certificate Tools

| Tool | Description |
|------|-------------|
| `certificates.list` | List certificates with filtering |
| `certificates.get` | Get certificate by serial number |
| `certificates.revoke` | Revoke a certificate |
| `certificates.getExpiring` | List certificates expiring soon |

### Account Tools

| Tool | Description |
|------|-------------|
| `accounts.list` | List ACME accounts |
| `accounts.get` | Get account by ID |
| `accounts.disable` | Disable an account |

### Tenant Tools

| Tool | Description |
|------|-------------|
| `tenants.create` | Create a new tenant |
| `tenants.get` | Get tenant by ID |
| `tenants.update` | Update tenant |
| `tenants.delete` | Delete tenant |
| `tenants.list` | List all tenants |

### EAB Tools

| Tool | Description |
|------|-------------|
| `eab.create` | Create EAB credential |
| `eab.get` | Get EAB by ID |
| `eab.delete` | Delete EAB |
| `eab.list` | List EABs for tenant |

### Policy Tools

| Tool | Description |
|------|-------------|
| `policies.create` | Create ABAC policy |
| `policies.get` | Get policy by ID |
| `policies.update` | Update policy |
| `policies.delete` | Delete policy |
| `policies.list` | List policies for tenant |

## Tool Definitions

### Example: certificates.list

```json
{
  "name": "certificates.list",
  "description": "List certificates issued by the CA with optional filtering",
  "inputSchema": {
    "type": "object",
    "properties": {
      "limit": {
        "type": "integer",
        "description": "Maximum number of certificates to return",
        "default": 50
      },
      "offset": {
        "type": "integer",
        "description": "Number of certificates to skip",
        "default": 0
      },
      "status": {
        "type": "string",
        "enum": ["valid", "revoked", "expired", "all"],
        "description": "Filter by certificate status",
        "default": "all"
      },
      "subject": {
        "type": "string",
        "description": "Filter by subject (partial match)"
      }
    }
  }
}
```

### Example: certificates.revoke

```json
{
  "name": "certificates.revoke",
  "description": "Revoke a certificate by serial number",
  "inputSchema": {
    "type": "object",
    "required": ["serial"],
    "properties": {
      "serial": {
        "type": "string",
        "description": "Certificate serial number"
      },
      "reason": {
        "type": "integer",
        "description": "Revocation reason code (0=unspecified, 1=keyCompromise, etc.)",
        "default": 0
      }
    }
  }
}
```

## Usage with AI Assistants

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "trusted-ca": {
      "command": "<unverified — there is no cactl binary; see the correction above>",
      "env": {}
    }
  }
}
```

### Programmatic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
)

func main() {
    client, err := mcp.NewClient(&mcp.Config{
        Address: "localhost:9445",
        TLS:     true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Call tool
    result, err := client.CallTool(context.Background(), "ca.getStatus", nil)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("CA Status: %v", result)
}
```

## JSON-RPC Format

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "certificates.list",
    "arguments": {
      "limit": 10,
      "status": "valid"
    }
  }
}
```

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"serial\": \"ABC123\", \"subject\": \"CN=example.com\", ...}]"
      }
    ]
  }
}
```

### Error Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "field": "serial",
      "reason": "required"
    }
  }
}
```

## stdio Mode

For local integrations, MCP can run over stdio:

Unverified — there is no `cactl` binary; see the correction above.

## Use Cases

| Scenario | Example |
|----------|---------|
| AI-assisted ops | "List all certificates expiring in 7 days" |
| Chatbot integration | "Revoke certificate ABC123 due to compromise" |
| Automated workflows | LLM-driven certificate lifecycle management |
| Natural language queries | "How many certificates are currently valid?" |

## Security Considerations

### Authentication

MCP inherits authentication from the underlying transport:

- **HTTP mode**: Uses mTLS for authentication
- **stdio mode**: Assumes local trusted execution

### Authorization

All MCP tool calls are subject to ABAC policy evaluation. The authenticated identity must have permission for the requested operation.

### Rate Limiting

MCP requests are rate-limited per client to prevent abuse.

## Debugging

### List Available Tools

```bash
# Via curl
curl -X POST https://localhost:9445/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Test Tool Call

Unverified — there is no `cactl` binary; see the correction above.

## See Also

- [Protocol Overview](README.md)
- [REST Protocol](rest.md)
- [`xkmsctl acme` CLI](../../acme-issuance/cli.md)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
