# Key Escrow — Engineering Contract

> **Status: NORMATIVE** · Feature: `escrow` · Repo: `go-xkms` · Last verified: 2026-09-15

## Exported surface — `pkg/escrow`

```go
type EscrowAgent interface {
	Type() string
	Available(ctx context.Context) bool
	EscrowKey(ctx context.Context, req *EscrowRequest) (*EscrowReceipt, error)
	RecoverKey(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error)
	ListEscrowed(ctx context.Context) ([]EscrowRecord, error)
	RevokeEscrow(ctx context.Context, escrowID string) error
	Close() error
}

type Config struct {
	Enabled bool          `yaml:"enabled"`
	Agents  []AgentConfig `yaml:"agents"`
}

type AgentConfig struct {
	Type           string        `yaml:"type"`     // "kmip" or "xkms"
	Endpoint       string        `yaml:"endpoint"`
	ClientCert     string        `yaml:"client_cert,omitempty"`
	ClientKey      string        `yaml:"client_key,omitempty"`
	CACert         string        `yaml:"ca_cert,omitempty"`
	Authentication string        `yaml:"authentication,omitempty"`
	Name           string        `yaml:"name,omitempty"` // registry key; defaults to Type
	Timeout        time.Duration `yaml:"timeout,omitempty"`
}

func (c *Config) Validate() error            // no-op unless Enabled
func (c *AgentConfig) Validate() error       // Type and Endpoint required

func NewAgent(cfg *AgentConfig) (EscrowAgent, error)
func NewRegistryFromConfig(cfg *Config) (*Registry, error) // nil, nil if cfg is nil/disabled
func RegisterAgentFactory(agentType string, factory AgentFactory)

type Registry struct{ /* unexported */ }
func NewRegistry() *Registry
func (r *Registry) Register(name string, agent EscrowAgent) error
func (r *Registry) Get(name string) (EscrowAgent, error)
func (r *Registry) Agents() []string
func (r *Registry) EscrowKeyAll(ctx context.Context, req *EscrowRequest) ([]*EscrowReceipt, error)
func (r *Registry) RecoverKeyAny(ctx context.Context, req *RecoverRequest) (*RecoverResponse, error)
func (r *Registry) ListAll(ctx context.Context) ([]EscrowRecord, error)
func (r *Registry) RevokeEscrowAll(ctx context.Context, escrowID string) error
func (r *Registry) Close() error
```

Implementations: `pkg/escrow/xkms.FederationAgent`, `pkg/escrow/kmip.KMIPAgent`.
Each registers its `AgentFactory` from its own `init()` in a small
`register.go` file, keyed on `escrow.AgentTypeXKMS` / `escrow.AgentTypeKMIP`.

## Service layer — `pkg/xkms`

```go
type EscrowServicer interface {
	EscrowKey(ctx context.Context, req *escrow.EscrowRequest) ([]*escrow.EscrowReceipt, error)
	RecoverKey(ctx context.Context, req *escrow.RecoverRequest) (*escrow.RecoverResponse, error)
	ListEscrowed(ctx context.Context) ([]escrow.EscrowRecord, error)
	RevokeEscrow(ctx context.Context, escrowID string) error
}

func (s *XKMSService) SetEscrowRegistry(r *escrow.Registry)
```

`XKMSService` is the only caller of `*escrow.Registry` outside `pkg/escrow`
itself and its tests — a transport calls `EscrowServicer`, never the registry
or an agent directly. Every method returns `xkms.ErrNotConfigured` when no
registry has been set (escrow disabled or not configured) and
`xkms.ErrNilRequest` for a nil request argument, matching every other
servicer in the package (see `servicer_seal_store.go`, `servicer_custodian.go`
for the same two guards).

Request/response types are `pkg/escrow`'s own domain types
(`EscrowRequest`, `EscrowReceipt`, `RecoverRequest`, `RecoverResponse`,
`EscrowRecord`) — they already carry the JSON tags and `Validate()` methods a
wire contract needs, so the servicer does not re-declare them under
`pkg/api/transport`. This mirrors `CustodianGroupServicer`, which passes
qrdb's own transport types through unchanged rather than wrapping them.

## Daemon wiring — `pkg/config`, `pkg/server`

- `config.Config.Escrow *escrow.Config` (`yaml:"escrow,omitempty"`) — nil when
  the section is absent, exactly like `Config.ACME` and `Config.Trust`.
- `Config.Validate()` calls `c.Escrow.Validate()` unconditionally (nil- and
  disabled-safe, mirrors `c.ACME.Validate()`).
- `server.Server.initializeEscrow()` calls `escrow.NewRegistryFromConfig(s.config.Escrow)`
  and stores the result on `s.escrowRegistry`; a nil result (escrow off) is
  not an error. Failure returns `&ErrServiceInit{Service: "escrow", Err: err,
  Sentinel: ErrEscrowRegistryFailed}`, matching every other subsystem
  initializer in `New()`.
- `svc.SetEscrowRegistry(s.escrowRegistry)` runs alongside the other
  `svc.SetX` calls once the embedded `XKMSService` is resolved.
- `Server.Shutdown()` closes `s.escrowRegistry` alongside the audit logger,
  logging (not failing) a close error — an agent that fails to close cleanly
  should not block the rest of shutdown.
- `pkg/server/server.go` blank-imports `pkg/escrow/xkms` and
  `pkg/escrow/kmip` so their `init()` factories are always registered; there
  is no build tag gating either (unlike the PKCS#11/cloud-KMS crypto
  backends), since both link cleanly with no external system dependency at
  build time.

## Configuration

```yaml
escrow:
  enabled: true
  agents:
    - type: "xkms"
      name: "dr-site"                       # optional; defaults to type
      endpoint: "https://dr-xkms.example.com:8443"
      client_cert: "<install-dir>/certs/escrow-client.pem"
      client_key: "<install-dir>/certs/escrow-client-key.pem"
      ca_cert: "<install-dir>/certs/escrow-ca.pem"
    - type: "kmip"
      name: "kmip-appliance"
      endpoint: "kmip://kmip.example.com:5696"
      client_cert: "<install-dir>/certs/kmip-client.pem"
      client_key: "<install-dir>/certs/kmip-client-key.pem"
      ca_cert: "<install-dir>/certs/kmip-ca.pem"
```

Two agents of the same `type` must each set a distinct `name`:
`NewRegistryFromConfig` registers by `Name`, falling back to `Type`, and a
collision fails closed with `ErrAgentAlreadyRegistered` rather than silently
dropping the second agent.

## Invariants

- **No agent ever receives plaintext key material.** `EscrowRequest.WrappedKey`
  and `RecoverResponse.WrappedKey` are always already wrapped (AES-KW or
  RSA-OAEP); wrapping and unwrapping are the caller's responsibility.
- **`EscrowKeyAll` and `RevokeEscrowAll` are belt-and-suspenders**: they
  succeed if at least one agent succeeds, and collect the rest into a joined
  error. A partial failure is visible via `errors.Is` against the per-agent
  wrapped errors, not swallowed.
- **`RecoverKeyAny` is failover**: first success wins, order is
  registration-map order (unordered) — callers needing a specific agent use
  `Registry.Get` plus the agent's own methods directly, in-process, not
  through `EscrowServicer`.
- **`pkg/escrow` cannot import its own agent implementations.** Adding a third
  agent type is always a new leaf package plus a `RegisterAgentFactory` call
  in its `init()`, never an edit to `pkg/escrow/factory.go`'s dispatch.

## Errors

Typed sentinels in `pkg/escrow/errors.go`: `ErrAgentNotConfigured`,
`ErrAgentUnavailable`, `ErrEscrowFailed`, `ErrRecoverFailed`,
`ErrRevokeFailed`, `ErrKeyNotFound`, `ErrInvalidRequest`, `ErrNilWrappedKey`,
`ErrEmptyKeyID`, `ErrEmptyEndpoint`, `ErrAuthenticationFailed`,
`ErrAlreadyEscrowed`, `ErrRegistryEmpty`, `ErrAgentAlreadyRegistered`,
`ErrEmptyAgentName`, `ErrNilAgent`, `ErrNilRequest`, `ErrAgentClosed`,
`ErrUnknownAgentType` (factory dispatch miss), `ErrNoAgentsConfigured`
(`enabled: true` with an empty `agents` list). Service-layer errors:
`xkms.ErrNotConfigured`, `xkms.ErrNilRequest`. Daemon-layer:
`server.ErrEscrowRegistryFailed` (wraps the underlying `pkg/escrow` error via
`ErrServiceInit`).

## Tests

- `pkg/escrow/factory_test.go` — factory dispatch for a registered type,
  `ErrUnknownAgentType` for an unregistered one, nil/invalid config guards,
  `NewRegistryFromConfig` success/duplicate-name/no-agents/unknown-type paths.
- `pkg/escrow/registry_test.go` — `RevokeEscrowAll` success, empty escrow ID,
  empty registry, partial failure, and all-agents-fail paths (added to the
  existing `mockAgent`-based suite).
- `pkg/config/escrow_test.go` — `Escrow` stays nil when undeclared, a full
  `escrow:` section round-trips through `Load`, `enabled: true` with no
  agents fails `Validate` with `ErrNoAgentsConfigured`, a disabled section is
  a `Validate` no-op.
- `pkg/xkms/servicer_escrow_test.go` — `EscrowKey`/`RecoverKey`/
  `ListEscrowed`/`RevokeEscrow` against a `fakeEscrowAgent`, plus
  `ErrNotConfigured` (no registry set) and `ErrNilRequest` (nil request)
  guards for every method that takes one.

Run: `GOTOOLCHAIN=go1.27.2 GOWORK=off go test ./pkg/escrow/... ./pkg/config/... -run Escrow` and
`GOTOOLCHAIN=go1.27.2 GOWORK=off go test ./pkg/xkms/... -run 'Escrow|RecoverKey' -tags "codec_cbor codec_json codec_msgpack tpm_simulator"`.
