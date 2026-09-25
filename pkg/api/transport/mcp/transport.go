// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package mcp provides an MCP transport implementation for the xkms SDK.
// The MCP transport speaks the real Model Context Protocol over Streamable
// HTTP (github.com/mark3labs/mcp-go): every xkms operation is invoked as an
// MCP tool call against the unified qrdb MCP server, mTLS-authenticated and
// TLS-only. The tool name is "xkms_" plus the legacy JSON-RPC method name
// with its dots replaced by underscores (see mcptool.ToolName), and each
// tool takes one optional string argument, "params_json", carrying the
// method's params encoded exactly as the legacy JSON-RPC request carried
// them. The tool's result is a single JSON text content item; tool-level
// failures come back as an MCP tool error (IsError=true with a text
// message).
//
// The connection, handshake, and tool-call machinery -- including decoding a
// failing call's go-qrdb wire.ErrorEnvelope -- lives in pkg/mcptool, not
// here: sdk/go/client/ssh's MCP client builds on the identical code (see
// that package's doc comment for why it is not this package's Transport
// directly). This package layers xkms's REST-path-to-JSON-RPC-method
// mapping, its typed request/response DTOs, and its JSON-RPC-style
// error-code classification (status.go's classifyWireCode) on top.
//
// WebAuthn registration and authentication are a named exclusion from this
// transport, not a gap awaiting an MCP tool: an agent tool-call surface must
// not mint sessions or enrol credentials, since MCP holds no
// identity-ceremony state of its own. Session minting and credential
// enrolment stay on operator-facing transports (REST, gRPC). See
// ErrIdentityCeremonyExcluded.
package mcp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/mcptool"
)

// ErrNotSupported is returned when an operation is not supported.
var ErrNotSupported = errors.New("operation not supported by this protocol")

// ErrIdentityCeremonyExcluded is returned by BeginRegistration,
// FinishRegistration, BeginAuthentication, and FinishAuthentication. It is a
// deliberate, permanent exclusion (issue #193), not a transitional stub: an
// agent tool-call surface must not mint sessions or enrol credentials, and
// MCP holds no identity-ceremony state to correlate a Begin call with its
// matching Finish call. Session minting and credential enrolment stay on
// operator-facing transports.
var ErrIdentityCeremonyExcluded = errors.New("mcp: WebAuthn registration and authentication are excluded from the MCP transport by design; use the REST or gRPC transport")

// ErrNotConnected is returned when the client is not connected. It is the
// pkg/mcptool sentinel, re-exported here for callers that only imported this
// package.
var ErrNotConnected = mcptool.ErrNotConnected

// ErrConnectionFailed is returned when a connection fails. It is the
// pkg/mcptool sentinel, re-exported here for callers that only imported this
// package.
var ErrConnectionFailed = mcptool.ErrConnectionFailed

// RPCError, EnvelopeMissingError, MarshalError, UnmarshalError, ReceiveError,
// and TLSSetupError are pkg/mcptool's typed errors for a failed MCP tool
// call, aliased here so existing callers of this package keep the same
// types. See pkg/mcptool for their definitions; RPCError's WireCode field
// carries go-qrdb's raw classification, and Code carries that classification
// translated onto xkms's JSON-RPC vocabulary by status.go's classifyWireCode.
type (
	RPCError             = mcptool.RPCError
	EnvelopeMissingError = mcptool.EnvelopeMissingError
	MarshalError         = mcptool.MarshalError
	UnmarshalError       = mcptool.UnmarshalError
	ReceiveError         = mcptool.ReceiveError
	TLSSetupError        = mcptool.TLSSetupError
)

// methodMapping maps REST-style SDK paths to JSON-RPC method names.
// The SDK client calls Request with REST paths; this table translates them
// to the JSON-RPC method names that the MCP server expects.
var methodMapping = map[string]string{
	// Health
	"/health": "health",

	// Backends
	"/api/v1/backends": "xkms.listBackends",

	// Keys
	"/api/v1/keys":               "xkms.generateKey",
	"/api/v1/keys/import":        "xkms.importKey",
	"/api/v1/keys/copy":          "xkms.copyKey",
	"/api/v1/keys/wrap":          "xkms.wrapKey",
	"/api/v1/keys/unwrap":        "xkms.unwrapKey",
	"/api/v1/keys/wrap-by-id":    "xkms.wrapKeyByID",
	"/api/v1/keys/unwrap-by-id":  "xkms.unwrapKeyByID",
	"/api/v1/keys/import-params": "xkms.getImportParameters",

	// Certificates
	"/api/v1/certs": "xkms.saveCert",

	// Seal
	"/api/v1/seal":   "xkms.seal",
	"/api/v1/unseal": "xkms.unseal",

	// CA
	"/api/v1/ca/bundle":      "xkms.ca.bundle",
	"/api/v1/ca/certificate": "xkms.ca.certificate",
	"/api/v1/ca/sign-csr":    "xkms.ca.sign-csr",
	"/api/v1/ca/issue":       "xkms.ca.issue",
	"/api/v1/ca/revoke":      "xkms.ca.revoke",
	"/api/v1/ca/crl":         "xkms.ca.crl",

	// TCG CA
	"/api/v1/tcg-ca/issue-ek-cert": "xkms.ca.tcg.issue-ek",
	"/api/v1/tcg-ca/issue-ak-cert": "xkms.ca.tcg.issue-ak",
	"/api/v1/tcg-ca/sign-tcg-csr":  "xkms.ca.tcg.sign-csr",
	"/api/v1/tcg-ca/enroll-device": "xkms.ca.tcg.enroll",

	// Barrier
	"/v1/barrier/initialize":             "barrier.initialize",
	"/v1/barrier/initialize-shamir":      "barrier.initializeShamir",
	"/v1/barrier/unseal":                 "barrier.unseal",
	"/v1/barrier/unseal-share":           "barrier.unsealShare",
	"/v1/barrier/unseal-shares":          "barrier.unsealShares",
	"/v1/barrier/seal":                   "barrier.seal",
	"/v1/barrier/status":                 "barrier.status",
	"/v1/barrier/rekey":                  "barrier.rekey",
	"/v1/barrier/root-token":             "barrier.generateRootToken",
	"/v1/barrier/recovery-keys":          "barrier.deleteRecoveryKeys",
	"/v1/barrier/recovery-keys/generate": "barrier.generateRecoveryKeys",
	"/v1/barrier/recovery-keys/recover":  "barrier.recoverWithKeys",

	// Attestation
	"/api/v1/attest": "xkms.attestKey",

	// Init Ceremony
	"/api/v1/init/status":               "init.getStatus",
	"/api/v1/init/claim-cert/begin":     "init.claimCertBegin",
	"/api/v1/init/claim-cert/complete":  "init.claimCertComplete",
	"/api/v1/init/claim-share/begin":    "init.claimShareBegin",
	"/api/v1/init/claim-share/complete": "init.claimShareComplete",
	"/api/v1/init/sign-csr":             "init.signCSR",

	// Credentials
	"/api/v1/credentials/submit":   "credentials.submit",
	"/api/v1/credentials/strategy": "credentials.strategy",

	// PIN Operations
	"/v1/pin/so-pin":          "xkms.setSOPIN",
	"/v1/pin/user-pin":        "xkms.setUserPIN",
	"/v1/pin/so-pin/change":   "xkms.changeSOPIN",
	"/v1/pin/user-pin/change": "xkms.changeUserPIN",
	"/v1/pin/so-pin/verify":   "xkms.verifySOPIN",
	"/v1/pin/user-pin/verify": "xkms.verifyUserPIN",
	"/v1/pin/lockout":         "xkms.getLockoutStatus",
	"/v1/pin/lockout/reset":   "xkms.resetLockout",

	// Password Store
	"/api/v1/passwords":             "password.list",
	"/api/v1/passwords/unlock":      "password.unlock",
	"/api/v1/passwords/lock":        "password.lock",
	"/api/v1/passwords/status":      "password.status",
	"/api/v1/passwords/access-mode": "password.setAccessMode",
	"/api/v1/passwords/generate":    "password.generate",

	// Key derivation
	"/api/v1/keys/derive":      "xkms.deriveKey",
	"/api/v1/keys/derive-ecdh": "xkms.deriveKeyECDH",

	// Custodian Groups
	"/api/v1/custodian/groups": "xkms.listCustodianGroups",

	// Shares
	"/api/v1/shares/submit": "xkms.submitShare",
	"/api/v1/shares":        "xkms.listShares",

	// Audit
	"/api/v1/audit": "xkms.queryAudit",

	// Tenants
	"/api/v1/tenants": "xkms.listTenants",

	// Users
	"/api/v1/users/": "xkms.listUsers",
}

// pathPatterns maps REST path patterns with dynamic segments to JSON-RPC methods.
// These are checked when an exact match is not found in methodMapping.
// The key is a path prefix pattern, the value contains the suffix and method.
type pathPattern struct {
	suffix string
	method string
}

var dynamicPatterns = []struct {
	prefix   string
	patterns []pathPattern
}{
	{
		prefix: "/api/v1/keys/",
		patterns: []pathPattern{
			{suffix: "/sign", method: "xkms.sign"},
			{suffix: "/verify", method: "xkms.verify"},
			{suffix: "/encrypt", method: "xkms.encrypt"},
			{suffix: "/decrypt", method: "xkms.decrypt"},
			{suffix: "/encrypt-asym", method: "xkms.asymmetricEncrypt"},
			{suffix: "/decrypt-asym", method: "xkms.asymmetricDecrypt"},
			{suffix: "/rotate", method: "xkms.rotateKey"},
			{suffix: "/export", method: "xkms.exportKey"},
			{suffix: "/export-material", method: "xkms.exportKeyMaterial"},
			{suffix: "", method: "xkms.getKey"},
		},
	},
	{
		prefix: "/api/v1/certs/",
		patterns: []pathPattern{
			{suffix: "/chain", method: "xkms.getCertChain"},
			{suffix: "", method: "xkms.getCert"},
		},
	},
	{
		prefix: "/api/v1/tls/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getTLSCertificate"},
		},
	},
	{
		prefix: "/api/v1/seal/capability",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.canSeal"},
		},
	},
	{
		prefix: "/api/v1/ca/revoked/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.ca.is-revoked"},
		},
	},
	{
		prefix: "/api/v1/users/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getUser"},
		},
	},
	{
		prefix: "/api/v1/backends/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getBackend"},
		},
	},
	{
		prefix: "/api/v1/passwords/",
		patterns: []pathPattern{
			{suffix: "", method: "password.get"},
		},
	},
	{
		prefix: "/v1/piv/slots",
		patterns: []pathPattern{
			{suffix: "/certificate", method: "xkms.getPIVCertificate"},
			{suffix: "/generate", method: "xkms.generatePIVKey"},
			{suffix: "/import", method: "xkms.importPIVCertificate"},
			{suffix: "/export", method: "xkms.exportPIVCertificate"},
			{suffix: "/csr", method: "xkms.generatePIVCSR"},
			{suffix: "", method: "xkms.listPIVSlots"},
		},
	},
	{
		prefix: "/api/v1/custodian/groups/",
		patterns: []pathPattern{
			{suffix: "/distribute", method: "xkms.distributeShares"},
			{suffix: "/members", method: "xkms.addCustodianMember"},
			{suffix: "", method: "xkms.getCustodianGroup"},
		},
	},
	{
		prefix: "/api/v1/tenants/",
		patterns: []pathPattern{
			{suffix: "/barrier/init", method: "xkms.tenantBarrierInit"},
			{suffix: "/barrier/unseal", method: "xkms.tenantBarrierUnseal"},
			{suffix: "", method: "xkms.getTenant"},
		},
	},
	{
		prefix: "/api/v1/shares/status/",
		patterns: []pathPattern{
			{suffix: "", method: "xkms.getShareCollectionStatus"},
		},
	},
}

// resolveMethod maps a REST-style path to a JSON-RPC method name.
// It strips query parameters before matching.
func resolveMethod(path string) (string, bool) {
	// Strip query parameters
	cleanPath := path
	if idx := strings.IndexByte(cleanPath, '?'); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}

	// Try exact match first (O(1) lookup)
	if method, ok := methodMapping[cleanPath]; ok {
		return method, true
	}

	// Try dynamic path patterns
	for _, dp := range dynamicPatterns {
		if !strings.HasPrefix(cleanPath, dp.prefix) {
			continue
		}
		for _, p := range dp.patterns {
			if p.suffix == "" {
				// Catch-all pattern for this prefix
				return p.method, true
			}
			if strings.HasSuffix(cleanPath, p.suffix) {
				return p.method, true
			}
		}
	}

	return "", false
}

// mcpEndpointPath is the Streamable HTTP path the unified qrdb MCP server
// mounts the xkms tool surface under. It must match pkg/mcptool's own
// (unexported) endpointPath constant, which Connect uses via the Client it
// constructs below.
const mcpEndpointPath = "/mcp"

// Transport implements the transport.Client interface over the Model
// Context Protocol's Streamable HTTP transport. Every xkms operation is
// invoked as a "tools/call" request against the unified qrdb MCP server;
// see the package doc for the tool-naming and argument convention. The
// connection and tool-call mechanics belong to the embedded *mcptool.Client;
// this type adds the REST-path mapping, typed DTOs, and xkms error-code
// classification (status.go's classifyWireCode).
type Transport struct {
	config *transport.Config
	core   *mcptool.Client
}

// New creates a new MCP transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	cfg := transport.DefaultConfig()
	if err := transport.ApplyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	return NewWithConfig(cfg)
}

// NewWithConfig creates a new MCP transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	if cfg == nil {
		cfg = transport.DefaultConfig()
	}

	return &Transport{
		config: cfg,
		core:   mcptool.NewClient(cfg, mcptool.WithErrorClassifier(classifyWireCode)),
	}, nil
}

// Connect establishes an MCP Streamable HTTP session with the xkms server:
// it builds the mTLS HTTP client, starts the Streamable HTTP transport,
// negotiates the MCP protocol version with Initialize, and confirms the
// session is usable with an "xkms_health" tool call before returning.
func (t *Transport) Connect(ctx context.Context) error {
	if err := t.core.Connect(ctx); err != nil {
		return err
	}

	if _, healthErr := t.Health(ctx); healthErr != nil {
		if closeErr := t.core.Close(); closeErr != nil {
			return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("health check failed: %v (close error: %v)", healthErr, closeErr)}
		}
		return &errs.Detail{Err: ErrConnectionFailed, Detail: fmt.Sprintf("health check failed: %v", healthErr)}
	}
	return nil
}

// Close closes the MCP session.
func (t *Transport) Close() error {
	return t.core.Close()
}

// Healthy checks if the transport can communicate with the server.
func (t *Transport) Healthy(ctx context.Context) bool {
	_, err := t.Health(ctx)
	return err == nil
}

// Conn returns the underlying MCP client.
func (t *Transport) Conn() interface{} {
	return t.core.Conn()
}

// IsConnected returns whether the transport is connected. This is safe to
// call on a Transport constructed as a bare zero value (core == nil), as
// the coverage tests for every guarded method's not-connected path do:
// *mcptool.Client's accessors tolerate a nil receiver.
func (t *Transport) IsConnected() bool {
	return t.core.IsConnected()
}

// Config returns the transport configuration.
func (t *Transport) Config() *transport.Config {
	return t.config
}

// Request performs an MCP tool call to the xkms server.
// The method parameter is a REST-style path that gets mapped to a JSON-RPC
// method name, which in turn addresses an MCP tool.
func (t *Transport) Request(ctx context.Context, method string, req, resp interface{}) error {
	rpcMethod, ok := resolveMethod(method)
	if !ok {
		return &transport.TransportError{
			Code:    transport.ErrCodeMethodNotFound,
			Message: "no JSON-RPC mapping for path: " + method,
		}
	}

	return t.rpcCall(ctx, rpcMethod, req, resp)
}

// rpcCall invokes method as an MCP tool call. params, when non-nil, is
// marshaled to JSON and passed as the tool's single "params_json" string
// argument. On success, the tool's first text content item is unmarshaled
// into result (when result is non-nil); a tool-level failure (IsError=true)
// is classified from its go-qrdb wire.ErrorEnvelope into an *RPCError (its
// Code translated by classifyWireCode, status.go), or into an
// *EnvelopeMissingError when the result carries no envelope, and any
// failure to complete the tool call at all becomes a *ReceiveError. The
// framing and envelope decoding belong to the embedded *mcptool.Client; this
// method only supplies the classifier passed to mcptool.NewClient in
// NewWithConfig.
func (t *Transport) rpcCall(ctx context.Context, method string, params interface{}, result interface{}) error {
	return t.core.Call(ctx, method, params, result)
}

// Health checks the health of the server.
func (t *Transport) Health(ctx context.Context) (*transport.HealthResponse, error) {
	var result transport.HealthResponse
	if err := t.rpcCall(ctx, "health", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListBackends returns a list of available backends.
func (t *Transport) ListBackends(ctx context.Context, _ ...transport.ListOption) (*transport.ListBackendsResponse, error) {
	var result transport.ListBackendsResponse
	if err := t.rpcCall(ctx, "xkms.listBackends", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetBackend returns information about a specific backend.
func (t *Transport) GetBackend(ctx context.Context, backendID string) (*transport.BackendInfo, error) {
	params := map[string]string{"backend": backendID}
	var result transport.BackendInfo
	if err := t.rpcCall(ctx, "xkms.getBackend", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Algorithms reports the algorithms the server supports.
func (t *Transport) Algorithms(ctx context.Context) (*transport.AlgorithmsResponse, error) {
	var result transport.AlgorithmsResponse
	if err := t.rpcCall(ctx, "xkms.algorithms", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GenerateKey generates a new key.
func (t *Transport) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	var result transport.GenerateKeyResponse
	if err := t.rpcCall(ctx, "xkms.generateKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListKeys returns a list of keys in the specified backend.
func (t *Transport) ListKeys(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListKeysResponse, error) {
	params := map[string]string{"backend": backend}
	var result transport.ListKeysResponse
	if err := t.rpcCall(ctx, "xkms.listKeys", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetKey returns information about a specific key.
func (t *Transport) GetKey(ctx context.Context, backend, keyID string) (*transport.GetKeyResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetKeyResponse
	if err := t.rpcCall(ctx, "xkms.getKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteKey deletes a key.
func (t *Transport) DeleteKey(ctx context.Context, backend, keyID string) (*transport.DeleteKeyResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.DeleteKeyResponse
	if err := t.rpcCall(ctx, "xkms.deleteKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Sign signs data with the specified key.
func (t *Transport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	var result transport.SignResponse
	if err := t.rpcCall(ctx, "xkms.sign", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Verify verifies a signature.
func (t *Transport) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	var result transport.VerifyResponse
	if err := t.rpcCall(ctx, "xkms.verify", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Encrypt encrypts data with the specified key.
func (t *Transport) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	var result transport.EncryptResponse
	if err := t.rpcCall(ctx, "xkms.encrypt", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Decrypt decrypts data with the specified key.
func (t *Transport) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	var result transport.DecryptResponse
	if err := t.rpcCall(ctx, "xkms.decrypt", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (t *Transport) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	var result transport.EncryptAsymResponse
	if err := t.rpcCall(ctx, "xkms.asymmetricEncrypt", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeriveKey derives a key using the specified algorithm and parameters.
func (t *Transport) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	var result transport.DeriveKeyResponse
	if err := t.rpcCall(ctx, "xkms.deriveKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a key using a KDF.
func (t *Transport) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	var result transport.DeriveKeyECDHResponse
	if err := t.rpcCall(ctx, "xkms.deriveKeyECDH", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AttestKey requests key attestation from a backend.
func (t *Transport) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.AttestKeyResponse
	if err := t.rpcCall(ctx, "xkms.attestKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCertificate returns the certificate for a key.
func (t *Transport) GetCertificate(ctx context.Context, backend, keyID string) (*transport.GetCertificateResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetCertificateResponse
	if err := t.rpcCall(ctx, "xkms.getCert", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SaveCertificate saves a certificate for a key.
func (t *Transport) SaveCertificate(ctx context.Context, req *transport.SaveCertificateRequest) error {
	return t.rpcCall(ctx, "xkms.saveCert", req, nil)
}

// DeleteCertificate deletes a certificate.
func (t *Transport) DeleteCertificate(ctx context.Context, backend, keyID string) error {
	params := map[string]string{"key_id": keyID, "backend": backend}
	return t.rpcCall(ctx, "xkms.deleteCert", params, nil)
}

// CertificateExists checks if a certificate exists for a key.
func (t *Transport) CertificateExists(ctx context.Context, backend, keyID string) (bool, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result struct {
		Exists bool `json:"exists"`
	}
	if err := t.rpcCall(ctx, "xkms.certExists", params, &result); err != nil {
		return false, err
	}
	return result.Exists, nil
}

// ImportKey imports a key.
// ImportKey sends the import to the MCP server.
//
// The params value is built field by field into the handler's own
// xkmsmcp.ImportKeyParams rather than marshalling req directly. Marshalling req
// looked equivalent and was not: the two structs name the key material
// differently ("wrapped_key_material" here, "wrapped_key" there), so every
// import over this transport arrived with no key at all, and aes_key_size,
// hash and partition were dropped with it (go-xkms#159). Naming the struct
// makes a rename on either side a compile error instead of a silent runtime
// break, which is the property the old code lacked.
//
// TenantID is deliberately not forwarded: this transport's handlers take the
// tenant from the authenticated caller (see tenantForRequest in pkg/api/mcp)
// and reject a wire-supplied one. Stamping it on the imported key is go-xkms
// #163/#222 and is not settled here.
func (t *Transport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.ImportKeyParams{
		KeyID:       req.KeyID,
		Backend:     req.Backend,
		KeyType:     req.KeyType,
		KeySize:     req.KeySize,
		Curve:       req.Curve,
		WrappedKey:  req.WrappedKeyMaterial,
		Algorithm:   req.Algorithm,
		ImportToken: req.ImportToken,
		Metadata:    req.Metadata,
		AESKeySize:  req.AESKeySize,
		Hash:        req.Hash,
		Partition:   req.Partition,
		Exportable:  req.Exportable,
		Sensitive:   req.Sensitive,
	}

	var result transport.ImportKeyResponse
	if err := t.rpcCall(ctx, "xkms.importKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportKey exports a key.
// ExportKey exports a key in wrapped form.
//
// The audit in go-xkms#255 found this pair already agreeing, so building the
// params by name changes nothing that travels. It is done anyway so that a
// later rename on either side is a compile error rather than a silent drop,
// which is the failure mode the other four ops were in.
func (t *Transport) ExportKey(ctx context.Context, req *transport.ExportKeyRequest) (*transport.ExportKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.ExportKeyParams{
		KeyID:     req.KeyID,
		Backend:   req.Backend,
		Algorithm: req.Algorithm,
	}

	var result transport.ExportKeyResponse
	if err := t.rpcCall(ctx, "xkms.exportKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RotateKey rotates a key.
func (t *Transport) RotateKey(ctx context.Context, req *transport.RotateKeyRequest) (*transport.RotateKeyResponse, error) {
	var result transport.RotateKeyResponse
	if err := t.rpcCall(ctx, "xkms.rotateKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetImportParameters gets the parameters needed to import a key.
// GetImportParameters asks the backend what it will accept for an import.
//
// Params are built by name into the handler's own struct, and the result is
// decoded from the handler's own struct: the two sides carry the wrapping
// key in different encodings (PEM text here, DER bytes on the contract), so
// marshalling req and decoding into the contract's response sent the
// caller's key type nowhere and brought the wrapping key back empty.
func (t *Transport) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.GetImportParametersParams{
		KeyID:     req.KeyID,
		Backend:   req.Backend,
		Algorithm: req.Algorithm,
		KeyType:   req.KeyType,
		KeySize:   req.KeySize,
		Curve:     req.Curve,
	}

	var result xkmsmcp.GetImportParametersResult
	if err := t.rpcCall(ctx, "xkms.getImportParameters", params, &result); err != nil {
		return nil, err
	}

	der, err := pkixDERFromPEM(result.WrappingPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	resp := &transport.GetImportParametersResponse{
		WrappingPublicKey: der,
		ImportToken:       result.ImportToken,
		Algorithm:         result.Algorithm,
		KeySpec:           result.KeySpec,
	}
	if result.ExpiresAt != nil {
		resp.ExpiresAt = *result.ExpiresAt
	}
	return resp, nil
}

// ErrWrappingPublicKeyNotPEM is returned when the import parameters carry a
// wrapping public key that is not a PEM PKIX public key.
var ErrWrappingPublicKeyNotPEM = errors.New("mcp: wrapping public key in the import parameters is not a PEM PKIX public key")

// WrappingPublicKeyError carries the decode failure behind
// ErrWrappingPublicKeyNotPEM.
type WrappingPublicKeyError struct {
	Err error
}

func (e *WrappingPublicKeyError) Error() string {
	return ErrWrappingPublicKeyNotPEM.Error() + ": " + e.Err.Error()
}

func (e *WrappingPublicKeyError) Unwrap() error { return e.Err }

func (e *WrappingPublicKeyError) Is(target error) bool { return target == ErrWrappingPublicKeyNotPEM }

// pkixDERFromPEM is the inverse of pemEncodePKIXPublicKey: the PEM text the
// handler returns becomes the DER bytes the contract carries, and no key at
// all stays no key.
func pkixDERFromPEM(pemText string) ([]byte, error) {
	if pemText == "" {
		return nil, nil
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, &WrappingPublicKeyError{Err: errors.New("no PEM block")}
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, &WrappingPublicKeyError{Err: err}
	}
	return block.Bytes, nil
}

// pemEncodePKIXPublicKey renders a DER-encoded PKIX public key as the PEM text
// the MCP handlers expect, and returns "" for no key at all.
//
// The wrapping public key crosses this boundary in two different encodings:
// transport.WrapKeyRequest and UnwrapKeyRequest carry DER bytes, while the MCP
// params carry PEM text that the handler feeds to pem.Decode and
// x509.ParsePKIXPublicKey. Assigning the DER into the string field marshals it
// as base64 — non-empty, plausible-looking, and rejected by pem.Decode with a
// bare "invalid wrapping public key PEM" (go-xkms#255).
//
// An empty input yields an empty string rather than an empty PEM block, so an
// omitted optional key stays omitted instead of becoming a value the handler
// would try to parse.
func pemEncodePKIXPublicKey(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// WrapKey wraps key material for secure transport.
//
// Params are built by name into the handler's own struct rather than
// marshalled from req: the two disagree on the wrapping key's field name AND
// its encoding, so marshalling req sent nothing the handler could read, and
// dropped backend and key_spec besides. See pemEncodePKIXPublicKey.
func (t *Transport) WrapKey(ctx context.Context, req *transport.WrapKeyRequest) (*transport.WrapKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.WrapKeyParams{
		KeyMaterial:          req.KeyMaterial,
		WrappingPublicKeyPEM: pemEncodePKIXPublicKey(req.WrappingPublicKey),
		ImportToken:          req.ImportToken,
		Algorithm:            req.Algorithm,
		Backend:              req.Backend,
		KeySpec:              req.KeySpec,
	}

	var result transport.WrapKeyResponse
	if err := t.rpcCall(ctx, "xkms.wrapKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnwrapKey unwraps key material.
//
// Params are built by name for the reason WrapKey gives. The material itself is
// "wrapped_key_material" on the request and "wrapped_key" in the params, which
// is the go-xkms#159 defect repeated verbatim on this path.
func (t *Transport) UnwrapKey(ctx context.Context, req *transport.UnwrapKeyRequest) (*transport.UnwrapKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.UnwrapKeyParams{
		WrappedKey:        req.WrappedKeyMaterial,
		Algorithm:         req.Algorithm,
		ImportToken:       req.ImportToken,
		WrappingPublicKey: pemEncodePKIXPublicKey(req.WrappingPublicKey),
		Metadata:          req.Metadata,
		Backend:           req.Backend,
		KeySpec:           req.KeySpec,
	}

	var result transport.UnwrapKeyResponse
	if err := t.rpcCall(ctx, "xkms.unwrapKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WrapKeyByID wraps a key using another key, both identified by their IDs.
func (t *Transport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	var result transport.WrapKeyByIDResponse
	if err := t.rpcCall(ctx, "xkms.wrapKeyByID", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *Transport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	var result transport.UnwrapKeyByIDResponse
	if err := t.rpcCall(ctx, "xkms.unwrapKeyByID", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportKeyMaterial exports raw symmetric key material.
func (t *Transport) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	var result transport.ExportKeyMaterialResponse
	if err := t.rpcCall(ctx, "xkms.exportKeyMaterial", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CopyKey copies a key from one backend to another.
// CopyKey copies a key from one backend to another.
//
// Params are built by name so the pair cannot drift. Note what this does NOT
// fix: xkmsmcp.CopyKeyParams carries hash and aes_key_size, and
// transport.CopyKeyRequest has no field for either, so no caller of this
// transport can populate them. That gap is go-xkms#155 and closing it means
// deciding whether the request struct gains the fields on every transport --
// the gRPC CopyKeyRequest message would need them too. Left alone deliberately
// rather than papered over here.
func (t *Transport) CopyKey(ctx context.Context, req *transport.CopyKeyRequest) (*transport.CopyKeyResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}

	params := &xkmsmcp.CopyKeyParams{
		SourceBackend: req.SourceBackend,
		SourceKeyID:   req.SourceKeyID,
		DestBackend:   req.DestBackend,
		DestKeyID:     req.DestKeyID,
		KeyType:       req.KeyType,
		Algorithm:     req.Algorithm,
		KeySize:       req.KeySize,
		Curve:         req.Curve,
	}

	var result transport.CopyKeyResponse
	if err := t.rpcCall(ctx, "xkms.copyKey", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListCertificates lists all certificates in the specified backend.
func (t *Transport) ListCertificates(ctx context.Context, backend string, _ ...transport.ListOption) (*transport.ListCertificatesResponse, error) {
	params := map[string]string{"backend": backend}
	var result transport.ListCertificatesResponse
	if err := t.rpcCall(ctx, "xkms.listCerts", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (t *Transport) SaveCertificateChain(ctx context.Context, req *transport.SaveCertificateChainRequest) error {
	return t.rpcCall(ctx, "xkms.saveCertChain", req, nil)
}

// GetCertificateChain returns the certificate chain for a key.
func (t *Transport) GetCertificateChain(ctx context.Context, backend, keyID string) (*transport.GetCertificateChainResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetCertificateChainResponse
	if err := t.rpcCall(ctx, "xkms.getCertChain", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (t *Transport) GetTLSCertificate(ctx context.Context, backend, keyID string) (*transport.GetTLSCertificateResponse, error) {
	params := map[string]string{"key_id": keyID, "backend": backend}
	var result transport.GetTLSCertificateResponse
	if err := t.rpcCall(ctx, "xkms.getTLSCertificate", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Seal seals data using the backend's sealing mechanism.
func (t *Transport) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.SealResponse
	if err := t.rpcCall(ctx, "xkms.seal", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Unseal unseals previously sealed data.
func (t *Transport) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.UnsealResponse
	if err := t.rpcCall(ctx, "xkms.unseal", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CanSeal checks if the backend supports sealing operations.
func (t *Transport) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	params := map[string]string{"backend": backend}
	var result transport.CanSealResponse
	if err := t.rpcCall(ctx, "xkms.canSeal", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WebAuthn/FIDO2 Operations
//
// These four methods are a named exclusion, not an unimplemented tool: the
// MCP transport is an agent-facing tool-call surface, and WebAuthn
// registration and authentication mint sessions and enrol credentials — an
// identity ceremony that must stay on operator-facing transports (REST,
// gRPC). They always fail with ErrIdentityCeremonyExcluded; see that error
// and the package comment for the rationale.

// BeginRegistration is excluded from the MCP transport by design; see
// ErrIdentityCeremonyExcluded. It always returns ErrIdentityCeremonyExcluded.
func (t *Transport) BeginRegistration(ctx context.Context, _ *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, ErrIdentityCeremonyExcluded
}

// FinishRegistration is excluded from the MCP transport by design; see
// ErrIdentityCeremonyExcluded. It always returns ErrIdentityCeremonyExcluded.
func (t *Transport) FinishRegistration(ctx context.Context, _ *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, ErrIdentityCeremonyExcluded
}

// BeginAuthentication is excluded from the MCP transport by design; see
// ErrIdentityCeremonyExcluded. It always returns ErrIdentityCeremonyExcluded.
func (t *Transport) BeginAuthentication(ctx context.Context, _ *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, ErrIdentityCeremonyExcluded
}

// FinishAuthentication is excluded from the MCP transport by design; see
// ErrIdentityCeremonyExcluded. It always returns ErrIdentityCeremonyExcluded.
func (t *Transport) FinishAuthentication(ctx context.Context, _ *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, ErrIdentityCeremonyExcluded
}

// CA Operations

// GetCABundle retrieves the CA certificate bundle.
func (t *Transport) GetCABundle(ctx context.Context, req *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	var result transport.GetCABundleResponse
	if err := t.rpcCall(ctx, "xkms.ca.bundle", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCACertificate retrieves the CA certificate.
func (t *Transport) GetCACertificate(ctx context.Context, req *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	var result transport.GetCACertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.certificate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignCSR signs a certificate signing request.
func (t *Transport) SignCSR(ctx context.Context, req *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	var result transport.SignCSRResponse
	if err := t.rpcCall(ctx, "xkms.ca.sign-csr", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IssueCertificate issues a new certificate.
func (t *Transport) IssueCertificate(ctx context.Context, req *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	var result transport.IssueCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.issue", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeCertificate revokes a certificate.
func (t *Transport) RevokeCertificate(ctx context.Context, req *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	var result transport.RevokeCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.revoke", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GenerateCRL generates a certificate revocation list.
func (t *Transport) GenerateCRL(ctx context.Context, req *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	var result transport.GenerateCRLResponse
	if err := t.rpcCall(ctx, "xkms.ca.crl", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IsRevoked checks if a certificate is revoked.
func (t *Transport) IsRevoked(ctx context.Context, req *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	var result transport.IsRevokedResponse
	if err := t.rpcCall(ctx, "xkms.ca.is-revoked", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TCG CA Operations

// IssueEKCertificate issues an Endorsement Key certificate.
func (t *Transport) IssueEKCertificate(ctx context.Context, req *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	var result transport.IssueEKCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.issue-ek", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// IssueAKCertificate issues an Attestation Key certificate.
func (t *Transport) IssueAKCertificate(ctx context.Context, req *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	var result transport.IssueAKCertificateResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.issue-ak", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignTCGCSR signs a TCG-CSR-IDEVID for device identity enrollment.
func (t *Transport) SignTCGCSR(ctx context.Context, req *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	var result transport.SignTCGCSRResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.sign-csr", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// EnrollDevice performs complete TCG device enrollment.
func (t *Transport) EnrollDevice(ctx context.Context, req *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	var result transport.EnrollDeviceResponse
	if err := t.rpcCall(ctx, "xkms.ca.tcg.enroll", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PIV Operations

// ListPIVSlots returns the list of PIV slots and their status.
func (t *Transport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.ListPIVSlotsResponse
	if err := t.rpcCall(ctx, "xkms.listPIVSlots", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPIVCertificate retrieves the certificate from a PIV slot.
func (t *Transport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.GetPIVCertificateResponse
	if err := t.rpcCall(ctx, "xkms.getPIVCertificate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// StorePIVCertificate stores a certificate into a PIV slot.
func (t *Transport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.storePIVCertificate", req, nil)
}

// DeletePIVCertificate removes the certificate from a PIV slot.
func (t *Transport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.deletePIVCertificate", req, nil)
}

// GeneratePIVKey generates a new key pair in a PIV slot.
func (t *Transport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.GeneratePIVKeyResponse
	if err := t.rpcCall(ctx, "xkms.generatePIVKey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ImportPIVCertificate imports a certificate into a PIV slot.
func (t *Transport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.importPIVCertificate", req, nil)
}

// ExportPIVCertificate exports the certificate from a PIV slot.
func (t *Transport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.GetPIVCertificateResponse
	if err := t.rpcCall(ctx, "xkms.exportPIVCertificate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GeneratePIVCSR generates a Certificate Signing Request for a PIV slot key.
func (t *Transport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.GeneratePIVCSRResponse
	if err := t.rpcCall(ctx, "xkms.generatePIVCSR", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Barrier Operations

// BarrierInitialize initializes the barrier by generating a root key and sealing it.
func (t *Transport) BarrierInitialize(ctx context.Context, req *transport.BarrierInitializeRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.initialize", req, nil)
}

// BarrierUnseal unseals the barrier by loading and decrypting the root key.
func (t *Transport) BarrierUnseal(ctx context.Context, req *transport.BarrierUnsealRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.unseal", req, nil)
}

// BarrierSeal transitions the barrier to sealed state, zeroing the DEK.
func (t *Transport) BarrierSeal(ctx context.Context) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.seal", nil, nil)
}

// BarrierStatus returns the current barrier status.
func (t *Transport) BarrierStatus(ctx context.Context) (*transport.BarrierStatusResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierStatusResponse
	if err := t.rpcCall(ctx, "barrier.status", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BootstrapListenerKeys returns the running trust-bootstrap listener's
// public static keys.
func (t *Transport) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BootstrapListenerKeysResponse
	if err := t.rpcCall(ctx, "bootstrap.showKeys", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierInitializeShamir initializes the barrier using Shamir secret sharing.
func (t *Transport) BarrierInitializeShamir(ctx context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierInitializeShamirResponse
	if err := t.rpcCall(ctx, "barrier.initializeShamir", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierUnsealWithShare submits a single Shamir share toward the quorum.
func (t *Transport) BarrierUnsealWithShare(ctx context.Context, req *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierUnsealShareResponse
	if err := t.rpcCall(ctx, "barrier.unsealShare", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierUnsealWithShares submits all Shamir shares at once.
func (t *Transport) BarrierUnsealWithShares(ctx context.Context, req *transport.BarrierUnsealSharesRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.unsealShares", req, nil)
}

// BarrierRekey rotates Shamir shares while keeping the same root key.
func (t *Transport) BarrierRekey(ctx context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierRekeyResponse
	if err := t.rpcCall(ctx, "barrier.rekey", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierGenerateRecoveryKeys generates recovery keys for disaster recovery.
func (t *Transport) BarrierGenerateRecoveryKeys(ctx context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierRecoveryKeysResponse
	if err := t.rpcCall(ctx, "barrier.generateRecoveryKeys", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierEnableEncryption migrates a previously-unencrypted barrier to a keyed
// strategy in place.
func (t *Transport) BarrierEnableEncryption(ctx context.Context, req *transport.BarrierEnableEncryptionRequest) (*transport.BarrierEnableEncryptionResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierEnableEncryptionResponse
	if err := t.rpcCall(ctx, "barrier.enableEncryption", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierRecoverWithKeys unseals the barrier using recovery keys.
func (t *Transport) BarrierRecoverWithKeys(ctx context.Context, req *transport.BarrierRecoverWithKeysRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.recoverWithKeys", req, nil)
}

// BarrierDeleteRecoveryKeys deletes stored recovery key metadata.
func (t *Transport) BarrierDeleteRecoveryKeys(ctx context.Context) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "barrier.deleteRecoveryKeys", nil, nil)
}

// BarrierHasRecoveryKeys checks if recovery keys exist.
func (t *Transport) BarrierHasRecoveryKeys(ctx context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierHasRecoveryKeysResponse
	if err := t.rpcCall(ctx, "barrier.hasRecoveryKeys", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// BarrierGenerateRootToken generates a one-time root token.
func (t *Transport) BarrierGenerateRootToken(ctx context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.BarrierRootTokenResponse
	if err := t.rpcCall(ctx, "barrier.generateRootToken", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PIN Operations

// SetSOPIN sets the Security Officer PIN.
func (t *Transport) SetSOPIN(ctx context.Context, req *transport.SetSOPINRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.setSOPIN", req, nil)
}

// SetUserPIN sets the user PIN.
func (t *Transport) SetUserPIN(ctx context.Context, req *transport.SetUserPINRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.setUserPIN", req, nil)
}

// ChangeSOPIN changes the Security Officer PIN.
func (t *Transport) ChangeSOPIN(ctx context.Context, req *transport.ChangeSOPINRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.changeSOPIN", req, nil)
}

// ChangeUserPIN changes the user PIN.
func (t *Transport) ChangeUserPIN(ctx context.Context, req *transport.ChangeUserPINRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.changeUserPIN", req, nil)
}

// VerifySOPIN verifies the Security Officer PIN.
func (t *Transport) VerifySOPIN(ctx context.Context, req *transport.VerifySOPINRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.verifySOPIN", req, nil)
}

// VerifyUserPIN verifies the user PIN.
func (t *Transport) VerifyUserPIN(ctx context.Context, req *transport.VerifyUserPINRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.verifyUserPIN", req, nil)
}

// GetLockoutStatus returns the current PIN lockout status.
func (t *Transport) GetLockoutStatus(ctx context.Context) (*transport.LockoutStatusResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.LockoutStatusResponse
	if err := t.rpcCall(ctx, "xkms.getLockoutStatus", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ResetLockout resets the PIN lockout counter.
func (t *Transport) ResetLockout(ctx context.Context, req *transport.ResetLockoutRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "xkms.resetLockout", req, nil)
}

// Password Store Operations

// PasswordAdd adds a new static password.
func (t *Transport) PasswordAdd(ctx context.Context, req *transport.PasswordAddRequest) (*transport.PasswordAddResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.PasswordAddResponse
	if err := t.rpcCall(ctx, "password.add", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordGet retrieves a password entry.
func (t *Transport) PasswordGet(ctx context.Context, req *transport.PasswordGetRequest) (*transport.PasswordGetResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.PasswordGetResponse
	if err := t.rpcCall(ctx, "password.get", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordList lists password entries.
func (t *Transport) PasswordList(ctx context.Context, req *transport.PasswordListRequest) (*transport.PasswordListResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.PasswordListResponse
	if err := t.rpcCall(ctx, "password.list", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordUpdate updates a password entry.
func (t *Transport) PasswordUpdate(ctx context.Context, req *transport.PasswordUpdateRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "password.update", req, nil)
}

// PasswordDelete deletes a password entry.
func (t *Transport) PasswordDelete(ctx context.Context, req *transport.PasswordDeleteRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "password.delete", req, nil)
}

// PasswordStoreUnlock unlocks the password store.
func (t *Transport) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "password.unlock", req, nil)
}

// PasswordStoreLock locks the password store.
func (t *Transport) PasswordStoreLock(ctx context.Context) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "password.lock", nil, nil)
}

// PasswordStoreStatus returns the password store status.
func (t *Transport) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.PasswordStoreStatusResponse
	if err := t.rpcCall(ctx, "password.status", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PasswordStoreSetAccessMode sets the password store access mode.
func (t *Transport) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "password.setAccessMode", req, nil)
}

// PasswordGenerate generates a random password.
func (t *Transport) PasswordGenerate(ctx context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.PasswordGenerateResponse
	if err := t.rpcCall(ctx, "password.generate", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Platform Store Operations

// SealStorePut stores a secret in the platform-sealed store.
func (t *Transport) SealStorePut(ctx context.Context, req *transport.SealStorePutRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "sealStore.put", req, nil)
}

// SealStoreGet retrieves a secret from the platform-sealed store.
func (t *Transport) SealStoreGet(ctx context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.SealStoreGetResponse
	if err := t.rpcCall(ctx, "sealStore.get", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SealStoreDelete deletes a secret from the platform-sealed store.
func (t *Transport) SealStoreDelete(ctx context.Context, req *transport.SealStoreDeleteRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "sealStore.delete", req, nil)
}

// SealStoreList lists all stored secret names in the platform-sealed store.
func (t *Transport) SealStoreList(ctx context.Context) (*transport.SealStoreListResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.SealStoreListResponse
	if err := t.rpcCall(ctx, "sealStore.list", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SealStoreReseal reseals a secret with the current platform sealing key.
func (t *Transport) SealStoreReseal(ctx context.Context, req *transport.SealStoreResealRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "sealStore.reseal", req, nil)
}

// SealStoreStatus returns the platform-sealed store status.
func (t *Transport) SealStoreStatus(ctx context.Context) (*transport.SealStoreStatusResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var result transport.SealStoreStatusResponse
	if err := t.rpcCall(ctx, "sealStore.status", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// External key escrow (pkg/escrow) is embedded-only (go-xkms#692): its RBAC
// model is undecided, so Transport does not implement EscrowKey/RecoverKey/
// ListEscrowed/RevokeEscrow at all. transport.EscrowService is no longer
// part of transport.Client — see docs/escrow/architecture.md.

// Policy Operations

// PolicyCreate creates a new PCR policy.
func (t *Transport) PolicyCreate(ctx context.Context, req *transport.PolicyCreateRequest) (*transport.PolicyCreateResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PolicyCreateResponse
	if err := t.rpcCall(ctx, "policy.create", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PolicyGet retrieves a policy by name.
func (t *Transport) PolicyGet(ctx context.Context, req *transport.PolicyGetRequest) (*transport.PolicyGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PolicyGetResponse
	if err := t.rpcCall(ctx, "policy.get", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PolicyList lists all policies.
func (t *Transport) PolicyList(ctx context.Context) (*transport.PolicyListResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PolicyListResponse
	if err := t.rpcCall(ctx, "policy.list", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PolicyDelete deletes a policy.
func (t *Transport) PolicyDelete(ctx context.Context, req *transport.PolicyDeleteRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "policy.delete", req, nil)
}

// PolicyRefresh refreshes a policy with current PCR values.
func (t *Transport) PolicyRefresh(ctx context.Context, req *transport.PolicyRefreshRequest) (*transport.PolicyGetResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PolicyGetResponse
	if err := t.rpcCall(ctx, "policy.refresh", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PolicyVerify verifies a policy against current PCR values.
func (t *Transport) PolicyVerify(ctx context.Context, req *transport.PolicyVerifyRequest) (*transport.PolicyVerifyResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PolicyVerifyResponse
	if err := t.rpcCall(ctx, "policy.verify", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PolicyExport exports a policy.
func (t *Transport) PolicyExport(ctx context.Context, req *transport.PolicyExportRequest) (*transport.PolicyExportResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	var result transport.PolicyExportResponse
	if err := t.rpcCall(ctx, "policy.export", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CustodianGroupService methods.

// CreateCustodianGroup creates a new custodian group.
func (t *Transport) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	var result transport.CreateCustodianGroupResponse
	if err := t.rpcCall(ctx, "xkms.createCustodianGroup", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (t *Transport) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	params := map[string]string{"group_id": groupID}
	var result transport.GetCustodianGroupResponse
	if err := t.rpcCall(ctx, "xkms.getCustodianGroup", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListCustodianGroups returns all custodian groups.
func (t *Transport) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	var result transport.ListCustodianGroupsResponse
	if err := t.rpcCall(ctx, "xkms.listCustodianGroups", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteCustodianGroup deletes a custodian group by ID.
func (t *Transport) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	params := map[string]string{"group_id": groupID}
	return t.rpcCall(ctx, "xkms.deleteCustodianGroup", params, nil)
}

// AddCustodianMember adds a member to a custodian group.
func (t *Transport) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	var result transport.AddCustodianMemberResponse
	if err := t.rpcCall(ctx, "xkms.addCustodianMember", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (t *Transport) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	return t.rpcCall(ctx, "xkms.removeCustodianMember", req, nil)
}

// DistributeShares triggers share distribution for a custodian group.
func (t *Transport) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	var result transport.DistributeSharesResponse
	if err := t.rpcCall(ctx, "xkms.distributeShares", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ShareService methods.

// SubmitShare submits a Shamir share for storage.
func (t *Transport) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	var result transport.SubmitShareResponse
	if err := t.rpcCall(ctx, "xkms.submitShare", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListShares returns all stored shares.
func (t *Transport) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	var result transport.ListSharesResponse
	if err := t.rpcCall(ctx, "xkms.listShares", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetShare returns a single stored share. Share material is never included
// in the response — the server returns metadata only.
func (t *Transport) GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error) {
	var result transport.ShareInfo
	if err := t.rpcCall(ctx, "xkms.getShare", shareParams(serverURL, groupID, shareIndex), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteShare removes a single stored share.
func (t *Transport) DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	var result struct{}
	return t.rpcCall(ctx, "xkms.deleteShare", shareParams(serverURL, groupID, shareIndex), &result)
}

// shareParams builds the JSON-RPC parameter object addressing a single share.
func shareParams(serverURL, groupID string, shareIndex int) map[string]any {
	return map[string]any{
		"server_url":  serverURL,
		"group_id":    groupID,
		"share_index": shareIndex,
	}
}

// GetShareCollectionStatus returns the share collection status for a group.
func (t *Transport) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	params := map[string]string{"group_id": groupID}
	var result transport.ShareCollectionStatus
	if err := t.rpcCall(ctx, "xkms.getShareCollectionStatus", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AuditService methods.

// QueryAudit returns one page of audit events from the tamper-evident audit
// chain owned by the embedded qrdb node.
func (t *Transport) QueryAudit(ctx context.Context, filter *transport.AuditFilter) (*transport.AuditPage, error) {
	if filter == nil {
		return nil, transport.ErrInvalidRequest
	}
	var result transport.AuditPage
	if err := t.rpcCall(ctx, "xkms.queryAudit", filter, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// TenantService methods.

// CreateTenant creates a new tenant.
func (t *Transport) CreateTenant(ctx context.Context, req *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	var result transport.CreateTenantResponse
	if err := t.rpcCall(ctx, "xkms.createTenant", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTenant retrieves a tenant by ID.
func (t *Transport) GetTenant(ctx context.Context, tenantID string) (*transport.GetTenantResponse, error) {
	params := map[string]string{"tenant_id": tenantID}
	var result transport.GetTenantResponse
	if err := t.rpcCall(ctx, "xkms.getTenant", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListTenants returns all tenants.
func (t *Transport) ListTenants(ctx context.Context) (*transport.ListTenantsResponse, error) {
	var result transport.ListTenantsResponse
	if err := t.rpcCall(ctx, "xkms.listTenants", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteTenant deletes a tenant by ID.
func (t *Transport) DeleteTenant(ctx context.Context, tenantID string) error {
	params := map[string]string{"tenant_id": tenantID}
	return t.rpcCall(ctx, "xkms.deleteTenant", params, nil)
}

// TenantBarrierInit initializes the barrier for a tenant.
func (t *Transport) TenantBarrierInit(ctx context.Context, req *transport.TenantBarrierInitRequest) error {
	return t.rpcCall(ctx, "xkms.tenantBarrierInit", req, nil)
}

// TenantBarrierUnseal unseals the barrier for a tenant.
func (t *Transport) TenantBarrierUnseal(ctx context.Context, req *transport.TenantBarrierUnsealRequest) error {
	return t.rpcCall(ctx, "xkms.tenantBarrierUnseal", req, nil)
}

// TenantBarrierStatus reports the status of a per-tenant barrier.
func (t *Transport) TenantBarrierStatus(ctx context.Context, tenantID string) (*transport.TenantBarrierStatusResponse, error) {
	params := map[string]string{"tenant_id": tenantID}
	var result transport.TenantBarrierStatusResponse
	if err := t.rpcCall(ctx, "xkms.tenantBarrierStatus", params, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements.
func (t *Transport) UpdateTenantEntitlements(ctx context.Context, req *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	var result transport.UpdateTenantEntitlementsResponse
	if err := t.rpcCall(ctx, "xkms.updateTenantEntitlements", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas.
func (t *Transport) UpdateTenantQuotas(ctx context.Context, req *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	var result transport.UpdateTenantQuotasResponse
	if err := t.rpcCall(ctx, "xkms.updateTenantQuotas", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Init Ceremony Methods

// GetInitStatus returns the current init ceremony state.
func (t *Transport) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	var result transport.InitStatusResponse
	if err := t.rpcCall(ctx, "init.getStatus", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimCertBegin begins the certificate claim process for an officer.
func (t *Transport) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	var result transport.ClaimCertBeginResponse
	if err := t.rpcCall(ctx, "init.claimCertBegin", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimCertComplete completes the certificate claim by verifying the officer's signature.
func (t *Transport) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	var result transport.ClaimCertCompleteResponse
	if err := t.rpcCall(ctx, "init.claimCertComplete", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimShare retrieves the Shamir share for the named officer.
func (t *Transport) ClaimShareBegin(ctx context.Context, req *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	var result transport.ClaimShareBeginResponse
	if err := t.rpcCall(ctx, "init.claimShareBegin", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ClaimShareComplete completes the Shamir share claim handshake for the named
// officer.
func (t *Transport) ClaimShareComplete(ctx context.Context, req *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	var result transport.ClaimShareCompleteResponse
	if err := t.rpcCall(ctx, "init.claimShareComplete", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// SignCSRInit signs a CSR during initialization with SO authorization.
func (t *Transport) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	var result transport.SignCSRInitResponse
	if err := t.rpcCall(ctx, "init.signCSR", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Credential Management Methods

// SubmitCredential submits a credential for manual mode.
func (t *Transport) SubmitCredential(ctx context.Context, req *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	var result transport.CredentialSubmitResponse
	if err := t.rpcCall(ctx, "credentials.submit", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCredentialStrategy returns the configured credential strategy.
func (t *Transport) GetCredentialStrategy(ctx context.Context) (*transport.CredentialStrategyResponse, error) {
	var result transport.CredentialStrategyResponse
	if err := t.rpcCall(ctx, "credentials.strategy", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ==================== User Operations ====================
//
// xkms presents its own user model; the backing store is the embedded qrdb
// node, reached server-side through pkg/api/mcp's user.* handlers
// (handlers_user.go), the same XKMSService the REST transport dials.
// WebAuthn/FIDO2 enrollment itself stays off this transport (#193, see the
// package doc); these eight cover account lifecycle only.

// bindUserCertParams is the wire shape for user.bindCert: username plus the
// two fields BindUserCert takes as positional arguments.
type bindUserCertParams struct {
	Username     string `json:"username"`
	Thumbprint   string `json:"thumbprint"`
	NotAfterUnix int64  `json:"not_after_unix"`
}

// CreateUser creates a new xkms user.
func (t *Transport) CreateUser(ctx context.Context, req *transport.CreateUserRequest) (*transport.GetUserResponse, error) {
	var result transport.GetUserResponse
	if err := t.rpcCall(ctx, "user.create", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListUsers lists xkms users.
func (t *Transport) ListUsers(ctx context.Context, _ ...transport.ListOption) (*transport.ListUsersResponse, error) {
	var result transport.ListUsersResponse
	if err := t.rpcCall(ctx, "user.list", nil, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUser retrieves a user by username.
func (t *Transport) GetUser(ctx context.Context, username string) (*transport.GetUserResponse, error) {
	var result transport.GetUserResponse
	if err := t.rpcCall(ctx, "user.get", map[string]string{"username": username}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteUser deletes a user by username.
func (t *Transport) DeleteUser(ctx context.Context, username string) error {
	return t.rpcCall(ctx, "user.delete", map[string]string{"username": username}, nil)
}

// EnableUser enables a user by username.
func (t *Transport) EnableUser(ctx context.Context, username string) error {
	return t.rpcCall(ctx, "user.enable", map[string]string{"username": username}, nil)
}

// DisableUser disables a user by username.
func (t *Transport) DisableUser(ctx context.Context, username string) error {
	return t.rpcCall(ctx, "user.disable", map[string]string{"username": username}, nil)
}

// BindUserCert binds an mTLS certificate's SPKI thumbprint to a user.
func (t *Transport) BindUserCert(ctx context.Context, username, thumbprint string, notAfterUnix int64) error {
	params := bindUserCertParams{Username: username, Thumbprint: thumbprint, NotAfterUnix: notAfterUnix}
	return t.rpcCall(ctx, "user.bindCert", params, nil)
}

// ListUserCredentials lists the credentials enrolled for a user.
func (t *Transport) ListUserCredentials(ctx context.Context, username string) (*transport.ListUserCredentialsResponse, error) {
	var result transport.ListUserCredentialsResponse
	if err := t.rpcCall(ctx, "user.listCredentials", map[string]string{"username": username}, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Compile-time interface assertion.
var _ transport.Client = (*Transport)(nil)
