# Agent Enrollment

Enrollment is the process by which a remote agent obtains an mTLS certificate from the master, establishing a trust relationship. The `EnrollmentService` manages all enrollment operations and enforces the policy configured by the security officer.

## Enrollment Methods

Four methods are supported. Each must be explicitly enabled in the server configuration via the `enrollment_methods` list.

### one_time_code

The master generates a short-lived code that is communicated to the agent operator out-of-band (displayed in the GUI, read over the phone, etc.). The agent presents the code along with a CSR to receive a signed certificate.

**Flow:**

1. Administrator calls `GenerateOneTimeCode(validity)` on the master
2. Code is communicated to the agent operator out-of-band
3. Agent generates a key pair and CSR locally
4. Agent submits the code and CSR to the master
5. Master validates the code (not expired, not used), signs the CSR, and returns the certificate and CA chain
6. Agent stores the certificate and connects via mTLS

**Defaults:** 8-character hex code, 15-minute validity. Codes are single-use and deleted after consumption or expiration.

### admin_approval

The agent submits a CSR without any pre-shared secret. The request enters a pending queue. An administrator reviews and approves or rejects it through the GUI or API.

**Flow:**

1. Agent generates a key pair and CSR locally
2. Agent calls `SubmitEnrollmentRequest(csrPEM)`, receives a request ID
3. Request appears in the pending queue with status `pending`
4. Administrator calls `ApproveEnrollment(requestID)` or `RejectEnrollment(requestID, reason)`
5. On approval, the CSR is signed and the certificate is returned
6. On rejection, the request is marked `rejected` with a reason

### enterprise_ca

The master trusts an external enterprise CA. Any agent presenting a valid certificate signed by the trusted CA is accepted without additional enrollment steps.

**Flow:**

1. Agent obtains a certificate from the enterprise CA through the organization's existing PKI
2. Master is configured with the enterprise CA certificate in `tls_ca_file`
3. Agent connects directly using its enterprise-issued certificate
4. mTLS handshake verifies the chain; no enrollment API call is needed

This method is suited for organizations with an existing PKI infrastructure.

### noise_direct

Uses the Noise protocol framework for direct pairing between master and agent without a pre-existing PKI. Both parties perform an interactive handshake to establish trust and derive a shared secret used to bootstrap the certificate exchange.

This method is designed for air-gapped or offline provisioning scenarios where no CA infrastructure is available.

## Security Considerations

**Certificate fingerprints.** Agent identity is derived from the SHA-256 fingerprint of the CSR public key. This fingerprint becomes the agent ID stored in the enrollment store.

**CSR validation.** Every submitted CSR is parsed, and its self-signature is verified before the CA signs it. Malformed or unsigned CSRs are rejected with `ErrInvalidCSR`.

**Single-use codes.** One-time codes are deleted from memory immediately after use. Expired codes are cleaned up by `CleanExpiredCodes()`, which the server can call periodically.

**Max agent limit.** The `max_agents` configuration caps the total number of enrolled agents. The limit is checked before every enrollment operation. Set to 0 for unlimited.

**TLS 1.3 minimum.** Both the server and client enforce TLS 1.3 as the minimum protocol version. The server requires and verifies client certificates when `tls_ca_file` is configured.

**Platform attestation.** When `require_attestation` is enabled, agents must present platform attestation evidence during enrollment. This binds the agent certificate to specific hardware.

**Certificate revocation.** The `CAService` interface includes `RevokeCertificate(serialNumber)` for revoking compromised agent certificates.

## EnrollmentStore

The `EnrollmentStore` interface persists enrolled agent records. Two implementations are provided:

### FileStore

Persists each agent as a JSON file in a directory (created with `0700` permissions). Files are written with `0600` permissions. Agent IDs are sanitized with `filepath.Base` to prevent directory traversal.

```go
store, err := agent.NewFileStore("/var/lib/xkey/agents", logger)
```

### MemoryStore

In-memory map-based store for testing and short-lived sessions. Data is lost when the process exits.

```go
store := agent.NewMemoryStore()
```

Both implementations are safe for concurrent use.

## Policy Configuration

Enrollment policy is set through the `Config` struct:

```yaml
agent:
  listen_address: ":9443"
  tls_cert_file: /etc/xkey/agent-server.crt
  tls_key_file: /etc/xkey/agent-server.key
  tls_ca_file: /etc/xkey/ca.crt
  enrollment_methods:
    - one_time_code
    - admin_approval
  require_attestation: false
  cert_validity_days: 365
  max_agents: 50
  one_time_code_length: 8
  one_time_code_validity: 15m
```

**Method gating.** Every enrollment operation checks `IsMethodAllowed(method)` before proceeding. If the requested method is not in the `enrollment_methods` list, `ErrEnrollmentMethodNotAllowed` is returned.

**Validation.** `Config.Validate()` checks that the listen address is set, all enrollment methods are recognized, and applies sensible defaults for zero-valued fields (365-day certs, 8-char codes, 15-minute validity).

## See Also

- [Agent Overview](README.md) -- server, client, and SSH proxy architecture
- [SSH Agent](../ssh.md) -- SSH key management and agent usage
