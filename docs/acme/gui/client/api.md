# Client Embedded API

The ACME client desktop app mounts these endpoints in the Wails asset server, in-process and same-origin with the frontend; no port is bound. The same router is served over TCP by `trusted-acme-client serve`. All endpoints are under `/api/v1`.

## Endpoints

### Accounts (Multi-Account)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/accounts` | List all configured accounts |
| POST | `/accounts` | Add a new account |
| GET | `/accounts/{name}` | Get account details |
| DELETE | `/accounts/{name}` | Remove an account |
| POST | `/account/register` | Register via workflow (legacy) |

**Register Request:**
```json
{
  "contact": ["mailto:admin@example.com"],
  "terms_of_service_agreed": true,
  "eab_kid": "optional-key-id",
  "eab_hmac_key": "optional-hmac-key"
}
```

**Register Response:**
```json
{
  "data": {
    "account_url": "https://ca.example.com/acme/acct/1",
    "account_id": 1,
    "status": "valid"
  }
}
```

### Certificates (Multi-Account)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/certificates` | List all certificate specs (optional `?account=` filter) |
| GET | `/certificates/{name}` | Get managed certificate info |
| POST | `/certificates/{name}/deploy` | Deploy a managed certificate |
| POST | `/certificate/request` | Request a certificate by spec name |
| POST | `/certificate/renew` | Renew a certificate by spec name |
| POST | `/certificate/revoke` | Revoke a certificate by spec name |

### Device (TPM)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/device/enroll` | Enroll a TPM device |
| POST | `/device/attest` | Perform remote attestation |

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| GET | `/config` | Get current client configuration |
| PUT | `/config` | Update client configuration |

### Renewal Service

| Method | Path | Description |
|--------|------|-------------|
| GET | `/renewal/status` | Get renewal service status and tracked certificates |
| GET | `/renewal/config` | Get renewal configuration |
| PUT | `/renewal/config` | Update renewal configuration |

## Response Envelope

All responses use the standard envelope:

```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

Error responses:

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "not_found",
    "message": "certificate not found"
  }
}
```

## CORS

All endpoints accept `OPTIONS` preflight requests. Response headers:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization`
