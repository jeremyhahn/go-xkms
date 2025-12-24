# CanoKey Configuration

## PIV Backend Configuration

### Go Configuration

```go
type Config struct {
    // PKCS#11 library path
    Library string `yaml:"library" json:"library"`

    // Token label (discovered automatically if empty)
    TokenLabel string `yaml:"token_label" json:"token_label"`

    // User PIN
    PIN string `yaml:"pin" json:"pin"`

    // Security Officer PIN (for admin operations)
    SOPIN string `yaml:"so_pin" json:"so_pin"`

    // Use virtual CanoKey QEMU device
    UseQEMU bool `yaml:"use_qemu" json:"use_qemu"`

    // QEMU socket path (if UseQEMU is true)
    QEMUSocketPath string `yaml:"qemu_socket_path" json:"qemu_socket_path"`
}
```

### YAML Configuration

```yaml
backends:
  canokey:
    library: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
    token_label: "CanoKey PIV"
    pin: "123456"
    so_pin: "12345678"
    use_qemu: false
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CANOKEY_PKCS11_LIBRARY` | PKCS#11 library path | `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| `CANOKEY_TOKEN_LABEL` | Token label | Auto-detected |
| `CANOKEY_PIN` | User PIN | `123456` |
| `CANOKEY_SOPIN` | SO PIN | `12345678` |
| `CANOKEY_QEMU` | Enable QEMU mode | `false` |
| `CANOKEY_QEMU_SOCKET` | QEMU socket path | `/tmp/canokey-qemu.sock` |

## FIDO2 Handler Configuration

### Go Configuration

```go
type Config struct {
    // Timeout for device operations
    Timeout time.Duration `yaml:"timeout" json:"timeout"`

    // Timeout for user presence (touch)
    UserPresenceTimeout time.Duration `yaml:"user_presence_timeout" json:"user_presence_timeout"`

    // Retry count for transient errors
    RetryCount int `yaml:"retry_count" json:"retry_count"`

    // Delay between retries
    RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`

    // Specific device path (optional)
    DevicePath string `yaml:"device_path" json:"device_path"`

    // Relying party ID
    RelyingPartyID string `yaml:"relying_party_id" json:"relying_party_id"`

    // Relying party name
    RelyingPartyName string `yaml:"relying_party_name" json:"relying_party_name"`

    // Require PIN verification
    RequireUserVerification bool `yaml:"require_user_verification" json:"require_user_verification"`

    // Allowed vendor IDs (filter devices)
    AllowedVendors []uint16 `yaml:"allowed_vendors" json:"allowed_vendors"`

    // Allowed product IDs (filter devices)
    AllowedProducts []uint16 `yaml:"allowed_products" json:"allowed_products"`

    // Enable CanoKey CBOR workaround
    WorkaroundCanoKey bool `yaml:"workaround_canokey" json:"workaround_canokey"`
}
```

### YAML Configuration

```yaml
fido2:
  timeout: 30s
  user_presence_timeout: 60s
  retry_count: 3
  retry_delay: 100ms
  relying_party_id: "example.com"
  relying_party_name: "Example Application"
  require_user_verification: false
  workaround_canokey: true
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FIDO2_TIMEOUT` | Operation timeout | `30s` |
| `FIDO2_UP_TIMEOUT` | User presence timeout | `60s` |
| `FIDO2_RP_ID` | Relying party ID | `go-keychain` |
| `FIDO2_RP_NAME` | Relying party name | `Go Keychain` |
| `FIDO2_DEVICE` | Specific device path | Auto-detected |
| `FIDO2_REQUIRE_UV` | Require user verification | `false` |

## Devcontainer Configuration

### CanoKey QEMU Service

```yaml
# docker-compose.yml
services:
  canokey-qemu:
    image: canokey-qemu:latest
    container_name: keychain-dev-canokey
    privileged: true
    volumes:
      - canokey-state:/var/lib/canokey
    environment:
      - CANOKEY_FIRMWARE_VERSION=3.0.0
    healthcheck:
      test: ["CMD", "pgrep", "qemu-system"]
      interval: 5s
      timeout: 5s
      retries: 3

volumes:
  canokey-state:
```

### VS Code Settings

```json
{
  "go.buildTags": "integration,frost,pkcs11,canokey,fido2",
  "go.testTags": "integration,canokey,fido2"
}
```

## Common Configurations

### Development (with QEMU)

```yaml
backends:
  canokey:
    use_qemu: true
    qemu_socket_path: "/tmp/canokey-qemu.sock"
    pin: "123456"

fido2:
  timeout: 30s
  workaround_canokey: true
```

### Production (Physical Device)

```yaml
backends:
  canokey:
    library: "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
    use_qemu: false
    # PIN should be in secure vault or HSM

fido2:
  timeout: 60s
  user_presence_timeout: 120s
  require_user_verification: true
```

### CI/CD (Headless)

```yaml
backends:
  canokey:
    use_qemu: true
    pin: "123456"

fido2:
  timeout: 10s
  user_presence_timeout: 5s  # Auto-approve in QEMU
  workaround_canokey: true
```

## PIV Slot Configuration

### Slot Selection

```go
// Use specific slot
attrs := &types.KeyAttributes{
    PIVSlot: canokey.SlotSignature,  // 0x9c
}

// Or by slot name
attrs := &types.KeyAttributes{
    PIVSlotName: "signature",  // 9c
}
```

### Available Slots

| Name | ID | Usage |
|------|-----|-------|
| `authentication` | 0x9a | General auth, TLS client |
| `signature` | 0x9c | Document signing |
| `key_management` | 0x9d | Encryption/decryption |
| `card_authentication` | 0x9e | Contactless auth |
| `retired_1` to `retired_20` | 0x82-0x95 | Additional storage |
