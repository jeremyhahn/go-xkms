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

package pairing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
)

// DefaultBridgeRequestTimeout is the default timeout for individual xkmsd requests.
const DefaultBridgeRequestTimeout = 30 * time.Second

// bridgeHandler is the handler function type for remote.* method dispatch.
type bridgeHandler func(ctx context.Context, params json.RawMessage) (interface{}, error)

// BridgeConfig configures the xkmsd bridge for remote.* request routing.
type BridgeConfig struct {
	// AllowedBackends restricts which xkmsd backends the phone can access.
	// Empty slice means all backends are accessible.
	AllowedBackends []string

	// DeniedBackends explicitly denies access to specific backends.
	DeniedBackends []string

	// RequestTimeout is the timeout for individual xkmsd requests.
	RequestTimeout time.Duration

	// Logger for structured logging.
	Logger *slog.Logger

	// AuditLogger for security audit logging. If nil, no audit logging occurs.
	AuditLogger audit.Logger

	// DeviceID is the identifier of the connected phone device (for audit logging).
	DeviceID string

	// DeviceName is the human-readable name of the connected phone (for audit logging).
	DeviceName string

	// TPMOpenErr, when set, records why an apparently-present TPM could not be
	// opened. Leave nil on a host that genuinely has no TPM: the two are
	// reported to the phone as different conditions.
	TPMOpenErr error

	// TPM answers the TCG/IDevID enrollment methods when this host has one.
	// Optional: leave nil on a host with no TPM, and those handlers report the
	// feature as unconfigured rather than failing.
	TPM TPMEnroller

	// OATHStore persists credentials added via remote.oathAdd and answers
	// remote.oathGenerate. Optional: leave nil to report the OATH methods as
	// unconfigured (ErrOATHNotConfigured) rather than faking success.
	OATHStore oath.Store

	// PIVStorage resolves PIV certificate storage for a named backend
	// (software, tpm2, pkcs11) so the bridge can serve remote.pivListSlots
	// and remote.pivGetCert. remote.pivSign does not need it: a PIV slot's
	// private key is addressed by KeyID == slot in the same key backend the
	// generic key handlers already reach through Client, so signing is
	// served by Client.Sign like any other key. Optional: leave nil to
	// report the certificate-storage methods as unconfigured
	// (ErrPIVNotConfigured).
	PIVStorage PIVStorageProvider

	// SyncService applies and computes trust store, OATH, and password sync
	// deltas for the remote.sync* methods. Optional: leave nil to report
	// sync as unconfigured (ErrSyncNotConfigured); remote.syncStatus still
	// answers without it, reporting an empty status rather than an error,
	// since "nothing has been synced yet" is a valid status.
	SyncService *xkeysync.Service

	// SyncApproval gates remote.syncPasswords, remote.syncOATH and
	// remote.syncAll -- the three methods that export this host's password
	// vault or OATH secrets to the phone -- behind an explicit desktop-side
	// decision. remote.syncTrustStore (public certificates) and
	// remote.syncStatus (metadata) are not gated by it.
	//
	// Required for those three methods to serve anything: nil fails every
	// one of them closed with ErrSyncApprovalRequired rather than exporting
	// secrets with no desktop check at all. A caller that wants the
	// existing "trust whoever the Noise session already pinned" behavior
	// must say so explicitly, by supplying an approver that always allows
	// (AlwaysApproveSync), not by leaving this nil.
	SyncApproval SyncApprovalFunc
}

// SyncApprovalRequest describes one remote.sync* call the bridge is about to
// serve, for whatever the approval function shows the operator or checks
// against policy.
type SyncApprovalRequest struct {
	// Method is the JSON-RPC method being approved: remote.syncPasswords,
	// remote.syncOATH, or remote.syncAll.
	Method string

	// DeviceName is the paired phone's name, from BridgeConfig.DeviceName.
	DeviceName string
}

// SyncApprovalFunc decides whether one secret-exporting remote.sync* call may
// proceed. It returns nil to allow the call and a non-nil error -- normally
// wrapping ErrSyncNotApproved -- to refuse it. The bridge does not
// distinguish "explicitly denied" from "approval mechanism itself failed":
// either way the export does not happen.
type SyncApprovalFunc func(ctx context.Context, req *SyncApprovalRequest) error

// AlwaysApproveSync is a SyncApprovalFunc that allows every request. It
// exists so a caller that has already made this decision by some other means
// -- a test double, or a trust boundary where the Noise session pinning is
// judged sufficient on its own -- can say so explicitly in one identifiable
// place, rather than leaving SyncApproval nil, which the bridge treats as
// "no decision has been made" and refuses.
func AlwaysApproveSync(context.Context, *SyncApprovalRequest) error { return nil }

// DefaultBridgeConfig returns a BridgeConfig with sensible defaults.
func DefaultBridgeConfig() *BridgeConfig {
	return &BridgeConfig{
		RequestTimeout: DefaultBridgeRequestTimeout,
		Logger:         slog.Default(),
	}
}

// Bridge routes remote.* JSON-RPC requests from the phone to xkmsd
// via the Go SDK transport.Client interface. It translates between the
// phone protocol types and the xkmsd SDK types.
//
// Bridge is safe for concurrent use. The handler map is read-only after
// initialization, and the underlying transport.Client handles its own
// concurrency.
type Bridge struct {
	client      transport.Client
	config      *BridgeConfig
	logger      *slog.Logger
	auditLogger audit.Logger
	handlers    map[string]bridgeHandler

	// tpmOpenErr records why a TPM that appears to exist could not be opened,
	// so the phone can be told "unreachable" rather than "absent".
	tpmOpenErr error

	// tpm answers the TCG/IDevID enrollment methods when this host has a TPM.
	// Optional: without it those handlers return ErrTPMNotConfigured, which
	// tells the phone the feature is unavailable rather than that we failed.
	tpm TPMEnroller

	// oathStore persists credentials added via remote.oathAdd and answers
	// remote.oathGenerate. Optional: nil reports ErrOATHNotConfigured.
	oathStore oath.Store

	// pivStorage resolves PIV certificate storage by backend name for
	// remote.pivListSlots and remote.pivGetCert. Optional: nil reports
	// ErrPIVNotConfigured.
	pivStorage PIVStorageProvider

	// syncService applies and computes sync deltas for the remote.sync*
	// methods. Optional: nil reports ErrSyncNotConfigured, except
	// remote.syncStatus which reports an empty status instead.
	syncService *xkeysync.Service

	// syncApproval gates the secret-exporting sync methods. nil refuses all
	// three with ErrSyncApprovalRequired; see BridgeConfig.SyncApproval.
	syncApproval SyncApprovalFunc

	// Pre-computed lookup sets for O(1) access control checks.
	allowedSet map[string]struct{}
	deniedSet  map[string]struct{}
}

// NewBridge creates a new Bridge that routes remote.* JSON-RPC requests
// to xkmsd via the provided transport client. The client must already
// be connected. The Bridge does not own the client and will not close it.
func NewBridge(client transport.Client, config *BridgeConfig) (*Bridge, error) {
	if client == nil {
		return nil, ErrBridgeNotConnected
	}
	if config == nil {
		config = DefaultBridgeConfig()
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = DefaultBridgeRequestTimeout
	}

	b := &Bridge{
		client:       client,
		config:       config,
		logger:       config.Logger.With("component", "bridge"),
		auditLogger:  config.AuditLogger,
		tpm:          config.TPM,
		tpmOpenErr:   config.TPMOpenErr,
		oathStore:    config.OATHStore,
		pivStorage:   config.PIVStorage,
		syncService:  config.SyncService,
		syncApproval: config.SyncApproval,
	}

	// Build O(1) access control lookup sets.
	b.allowedSet = make(map[string]struct{}, len(config.AllowedBackends))
	for _, backend := range config.AllowedBackends {
		b.allowedSet[backend] = struct{}{}
	}
	b.deniedSet = make(map[string]struct{}, len(config.DeniedBackends))
	for _, backend := range config.DeniedBackends {
		b.deniedSet[backend] = struct{}{}
	}

	// Initialize map-based dispatch for O(1) routing.
	b.handlers = map[string]bridgeHandler{
		MethodRemoteListBackends:         b.handleListBackends,
		MethodRemoteListKeys:             b.handleListKeys,
		MethodRemoteGetPublicKey:         b.handleGetPublicKey,
		MethodRemoteSign:                 b.handleSign,
		MethodRemoteVerify:               b.handleVerify,
		MethodRemoteEncrypt:              b.handleEncrypt,
		MethodRemoteDecrypt:              b.handleDecrypt,
		MethodRemoteDeriveKey:            b.handleDeriveKey,
		MethodRemoteGenerateKey:          b.handleGenerateKey,
		MethodRemoteGetKeyInfo:           b.handleGetKeyInfo,
		MethodRemoteDeleteKey:            b.handleDeleteKey,
		MethodRemoteAttestKey:            b.handleAttestKey,
		MethodRemoteAttestDevice:         b.handleAttestDevice,
		MethodRemoteGetTCGCSRIDevID:      b.handleGetTCGCSRIDevID,
		MethodRemoteActivateCredential:   b.handleActivateCredential,
		MethodRemoteGetAttestationQuote:  b.handleGetAttestationQuote,
		MethodRemoteStoreEnrollmentCerts: b.handleStoreEnrollmentCerts,
		// Key sharing handlers.
		MethodRemoteSharePublicKey:  b.handleSharePublicKey,
		MethodRemoteShareSymmetric:  b.handleShareSymmetric,
		MethodRemoteImportSharedKey: b.handleImportSharedKey,
		// Backup/restore handlers.
		MethodRemoteCreateBackup:  b.handleCreateBackup,
		MethodRemoteRestoreBackup: b.handleRestoreBackup,
		MethodRemoteListBackups:   b.handleListBackupsForRestore,
		// OATH credential sync handlers.
		MethodRemoteOATHAdd:      b.handleOATHAdd,
		MethodRemoteOATHGenerate: b.handleOATHGenerate,
		// PIV handlers.
		MethodRemotePIVListSlots: b.handlePIVListSlots,
		MethodRemotePIVSign:      b.handlePIVSign,
		MethodRemotePIVGetCert:   b.handlePIVGetCert,
		// Sync handlers.
		MethodRemoteSyncTrustStore: b.handleSyncTrustStore,
		MethodRemoteSyncOATH:       b.handleSyncOATH,
		MethodRemoteSyncPasswords:  b.handleSyncPasswords,
		MethodRemoteSyncAll:        b.handleSyncAll,
		MethodRemoteSyncStatus:     b.handleSyncStatus,
	}

	return b, nil
}

// HandleRequest dispatches a remote.* JSON-RPC request to the appropriate
// handler and returns the response. The caller (PhoneKeyBackend) is
// responsible for encrypting/decrypting with Noise.
func (b *Bridge) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return b.errorResponse(0, ErrorCodeInvalidRequest, "nil request")
	}

	b.logger.Debug("handling remote request",
		"method", req.Method,
		"id", req.ID)

	// Look up handler from dispatch map.
	handler, ok := b.handlers[req.Method]
	if !ok {
		b.logger.Warn("unknown remote method", "method", req.Method)
		return b.errorResponse(req.ID, ErrorCodeMethodNotFound, "unknown method: "+req.Method)
	}

	// Marshal params to json.RawMessage for handler consumption.
	var rawParams json.RawMessage
	if req.Params != nil {
		data, err := json.Marshal(req.Params)
		if err != nil {
			b.logger.Error("failed to marshal request params", "error", err)
			return b.errorResponse(req.ID, ErrorCodeInvalidParams, "invalid parameters")
		}
		rawParams = data
	}

	// Apply request timeout.
	ctx, cancel := context.WithTimeout(ctx, b.config.RequestTimeout)
	defer cancel()

	// Call handler.
	result, err := handler(ctx, rawParams)
	if err != nil {
		return b.handleError(req.ID, err)
	}

	// Marshal result to json.RawMessage.
	resultData, err := json.Marshal(result)
	if err != nil {
		b.logger.Error("failed to marshal result", "error", err)
		return b.errorResponse(req.ID, ErrorCodeInternalError, "failed to encode result")
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      req.ID,
		Result:  resultData,
	}
}

// Close is a no-op since the Bridge does not own the transport client.
// The caller is responsible for closing the client independently.
func (b *Bridge) Close() error {
	return nil
}

// isBackendAllowed checks whether the given backend is permitted by the
// bridge access control policy.
func (b *Bridge) isBackendAllowed(backend string) bool {
	// Check deny list first (explicit deny always wins).
	if _, denied := b.deniedSet[backend]; denied {
		return false
	}
	// If an allow list is configured, the backend must be in it.
	if len(b.allowedSet) > 0 {
		_, allowed := b.allowedSet[backend]
		return allowed
	}
	return true
}

// checkBackendAccess validates backend access and returns an RPC error
// if denied.
func (b *Bridge) checkBackendAccess(backend string) error {
	if !b.isBackendAllowed(backend) {
		b.logger.Warn("backend access denied", "backend", backend)
		// Log policy denial if audit logger is configured
		if b.auditLogger != nil {
			if auditErr := b.auditLogger.LogCryptoOperation(
				audit.OpPolicyDenied,
				backend,
				"",
				b.config.DeviceID,
				b.config.DeviceName,
				false,
				ErrBridgeBackendDenied,
				0,
			); auditErr != nil {
				return auditErr
			}
		}
		return ErrBridgeBackendDenied
	}
	return nil
}

// handleListBackends returns the list of xkmsd backends, filtered by
// the bridge access control policy.
func (b *Bridge) handleListBackends(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	resp, err := b.client.ListBackends(ctx)
	if err != nil {
		return nil, err
	}

	// Filter backends through the access control policy.
	backends := make([]BackendInfo, 0, len(resp.Backends))
	for i := range resp.Backends {
		sdkBackend := &resp.Backends[i]
		if !b.isBackendAllowed(sdkBackend.ID) {
			continue
		}
		backends = append(backends, mapSDKBackendInfo(sdkBackend))
	}

	return &RemoteListBackendsResult{Backends: backends}, nil
}

// handleListKeys returns the keys in a specific xkmsd backend.
func (b *Bridge) handleListKeys(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteListKeysParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.ListKeys(ctx, p.Backend)
	if err != nil {
		return nil, err
	}

	keys := make([]RemoteKeyInfo, 0, len(resp.Keys))
	for i := range resp.Keys {
		sdkKey := &resp.Keys[i]
		// Apply algorithm filter if specified.
		if p.Algorithm != "" && sdkKey.Algorithm != p.Algorithm {
			continue
		}
		keys = append(keys, RemoteKeyInfo{
			KeyID:     sdkKey.KeyID,
			Backend:   sdkKey.Backend,
			Algorithm: sdkKey.Algorithm,
		})
	}

	return &RemoteListKeysResult{Keys: keys}, nil
}

// handleGetPublicKey retrieves the public key for a specific key.
func (b *Bridge) handleGetPublicKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteGetPublicKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.GetKey(ctx, p.Backend, p.KeyID)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, format, err := extractPublicKey(resp.PublicKeyPEM, p.Format)
	if err != nil {
		return nil, err
	}

	return &RemoteGetPublicKeyResult{
		PublicKey: publicKeyBytes,
		Format:    format,
		Algorithm: resp.Algorithm,
	}, nil
}

// handleSign signs data using a key in a xkmsd backend.
func (b *Bridge) handleSign(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteSignParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.Sign(ctx, &transport.SignRequest{
		Backend: p.Backend,
		KeyID:   p.KeyID,
		Data:    p.Data,
		Hash:    p.Algorithm,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the sign operation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogCryptoOperation(
			audit.OpSignRequest,
			p.Backend,
			p.KeyID,
			b.config.DeviceID,
			b.config.DeviceName,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteSignResult{
		Signature: resp.Signature,
		Algorithm: resp.Algorithm,
	}, nil
}

// handleVerify verifies a signature using a key in a xkmsd backend.
func (b *Bridge) handleVerify(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteVerifyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.Verify(ctx, &transport.VerifyRequest{
		Backend:   p.Backend,
		KeyID:     p.KeyID,
		Data:      p.Data,
		Signature: p.Signature,
		Hash:      p.Algorithm,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the verify operation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogCryptoOperation(
			audit.OpVerifyRequest,
			p.Backend,
			p.KeyID,
			b.config.DeviceID,
			b.config.DeviceName,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteVerifyResult{Valid: resp.Valid}, nil
}

// handleEncrypt encrypts data using a key in a xkmsd backend.
func (b *Bridge) handleEncrypt(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteEncryptParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.Encrypt(ctx, &transport.EncryptRequest{
		Backend:        p.Backend,
		KeyID:          p.KeyID,
		Plaintext:      p.Plaintext,
		AdditionalData: p.AAD,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the encrypt operation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogCryptoOperation(
			audit.OpEncryptRequest,
			p.Backend,
			p.KeyID,
			b.config.DeviceID,
			b.config.DeviceName,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteEncryptResult{Ciphertext: resp.Ciphertext}, nil
}

// handleDecrypt decrypts data using a key in a xkmsd backend.
func (b *Bridge) handleDecrypt(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteDecryptParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.Decrypt(ctx, &transport.DecryptRequest{
		Backend:        p.Backend,
		KeyID:          p.KeyID,
		Ciphertext:     p.Ciphertext,
		AdditionalData: p.AAD,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the decrypt operation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogCryptoOperation(
			audit.OpDecryptRequest,
			p.Backend,
			p.KeyID,
			b.config.DeviceID,
			b.config.DeviceName,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteDecryptResult{Plaintext: resp.Plaintext}, nil
}

// handleDeriveKey performs ECDH key agreement using a key in a xkmsd backend.
func (b *Bridge) handleDeriveKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteDeriveKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{
		Backend:       p.Backend,
		KeyID:         p.KeyID,
		PeerPublicKey: p.PeerPublicKey,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the derive key operation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogCryptoOperation(
			audit.OpDeriveKey,
			p.Backend,
			p.KeyID,
			b.config.DeviceID,
			b.config.DeviceName,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteDeriveKeyResult{SharedSecret: resp.DerivedKey}, nil
}

// handleGenerateKey generates a new key in a xkmsd backend.
func (b *Bridge) handleGenerateKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteGenerateKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.GenerateKey(ctx, &transport.GenerateKeyRequest{
		Backend:   p.Backend,
		KeyID:     p.KeyID,
		Algorithm: p.Algorithm,
		KeySize:   p.KeySizeBits,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the key generation
	if b.auditLogger != nil {
		keyID := p.KeyID
		if err == nil && resp != nil {
			keyID = resp.KeyID
		}
		if auditErr := b.auditLogger.LogKeyOperation(
			audit.OpKeyCreated,
			p.Backend,
			keyID,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	// Extract public key DER bytes from PEM if present.
	var pubKeyDER []byte
	if resp.PublicKeyPEM != "" {
		block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
		if block != nil {
			pubKeyDER = block.Bytes
		}
	}

	return &RemoteGenerateKeyResult{
		KeyID:     resp.KeyID,
		PublicKey: pubKeyDER,
		Algorithm: resp.KeyType,
		Backend:   p.Backend,
	}, nil
}

// handleGetKeyInfo retrieves detailed information about a key in a xkmsd backend.
func (b *Bridge) handleGetKeyInfo(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p RemoteGetKeyInfoParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	keyResp, err := b.client.GetKey(ctx, p.Backend, p.KeyID)
	if err != nil {
		return nil, err
	}

	// Check if the backend is hardware-backed.
	backendInfo, backendErr := b.client.GetBackend(ctx, p.Backend)
	hardwareBacked := false
	if backendErr == nil && backendInfo != nil {
		hardwareBacked = backendInfo.HardwareBacked
	}

	return &RemoteGetKeyInfoResult{
		RemoteKeyInfo: RemoteKeyInfo{
			KeyID:     keyResp.KeyID,
			Backend:   keyResp.Backend,
			Algorithm: keyResp.Algorithm,
		},
		HardwareBacked: hardwareBacked,
	}, nil
}

// handleDeleteKey deletes a key from a xkmsd backend.
func (b *Bridge) handleDeleteKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteDeleteKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.DeleteKey(ctx, p.Backend, p.KeyID)

	durationMs := time.Since(start).Milliseconds()

	// Audit log the key deletion
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogKeyOperation(
			audit.OpKeyDeleted,
			p.Backend,
			p.KeyID,
			err == nil && resp != nil && resp.Success,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteDeleteKeyResult{Deleted: resp.Success}, nil
}

// handleAttestKey handles key attestation requests by forwarding them
// to the xkmsd server via the SDK client.
func (b *Bridge) handleAttestKey(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteAttestKeyParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}
	if err := b.checkBackendAccess(p.Backend); err != nil {
		return nil, err
	}

	resp, err := b.client.AttestKey(ctx, &transport.AttestKeyRequest{
		Backend: p.Backend,
		KeyID:   p.KeyID,
		Nonce:   p.Nonce,
	})

	durationMs := time.Since(start).Milliseconds()

	// Audit log the key attestation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogKeyOperation(
			audit.OpKeyAttested,
			p.Backend,
			p.KeyID,
			err == nil,
			err,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	if err != nil {
		return nil, err
	}

	return &RemoteAttestKeyResult{
		Format:           resp.Format,
		CertificateChain: resp.CertificateChain,
		AttestationData:  resp.AttestationData,
		Nonce:            resp.Nonce,
	}, nil
}

// handleAttestDevice handles device-level attestation requests. This provides
// the phone with information about the laptop/desktop's security posture,
// including whether hardware security (TPM2) is available.
func (b *Bridge) handleAttestDevice(ctx context.Context, params json.RawMessage) (interface{}, error) {
	start := time.Now()

	var p RemoteAttestDeviceParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, ErrBridgeInvalidParams
	}

	// Validate nonce length
	if len(p.Nonce) != 32 {
		return nil, ErrBridgeInvalidParams
	}

	// Query available backends to determine platform capabilities
	backendsResp, err := b.client.ListBackends(ctx)
	if err != nil {
		b.logger.Error("failed to list backends for device attestation", "error", err)
		return nil, err
	}

	// Determine security level based on available backends
	securityLevel := "software"
	format := "software"
	hasTPM2 := false
	var firmwareVersion string

	for _, backend := range backendsResp.Backends {
		if backend.Type == "tpm2" && backend.HardwareBacked {
			hasTPM2 = true
			securityLevel = "hardware"
			format = "tpm2"
			break
		}
	}

	// Generate a stable device identifier hash
	// This uses backend information to create a reproducible fingerprint
	bootHashHex := b.computeDeviceFingerprint(backendsResp.Backends, hasTPM2)

	durationMs := time.Since(start).Milliseconds()

	// Audit log the device attestation
	if b.auditLogger != nil {
		if auditErr := b.auditLogger.LogCryptoOperation(
			audit.OpDeviceAttested,
			"",
			"",
			b.config.DeviceID,
			b.config.DeviceName,
			true,
			nil,
			durationMs,
		); auditErr != nil {
			return nil, auditErr
		}
	}

	b.logger.Info("device attestation completed",
		"format", format,
		"securityLevel", securityLevel,
		"hasTPM2", hasTPM2)

	return &RemoteAttestDeviceResult{
		Format:            format,
		CertificateChain:  nil, // No cert chain for software attestation
		SecurityLevel:     securityLevel,
		Nonce:             p.Nonce,
		BootHashHex:       bootHashHex,
		BootStateVerified: hasTPM2, // Consider verified if TPM2 is present
		FirmwareVersion:   firmwareVersion,
	}, nil
}

// handleGetTCGCSRIDevID handles requests to generate a TCG-CSR-IDEVID structure
// for device identity certificate enrollment. This operation requires direct
// TPM2 access and is not currently supported via the bridge.
//
// The TCG-CSR-IDEVID structure contains the IDevID public key, IAK public key,
// EK certificate, and platform identification information needed for CA enrollment.
//

// handleActivateCredential handles TPM2 credential activation challenges from a CA.
// This operation requires direct TPM2 access and is not currently supported via the bridge.
//
// Credential activation proves EK possession to the CA by decrypting a challenge
// created with TPM2_MakeCredential. The decryption uses the EK private key which
// never leaves the TPM.
//

// handleGetAttestationQuote handles requests for TPM2 attestation quotes.
// This operation requires direct TPM2 access and is not currently supported via the bridge.
//
// An attestation quote provides cryptographic proof of platform state by signing
// PCR values with the IAK. The CA uses this to verify platform integrity and
// binding between the IAK and EK.
//

// computeDeviceFingerprint generates a stable device identifier based on
// available backends. For TPM2 systems, this could be enhanced to include
// the EK certificate fingerprint for stronger binding.
func (b *Bridge) computeDeviceFingerprint(backends []transport.BackendInfo, hasTPM2 bool) string {
	// Build a canonical string from backend info
	var fingerprint string
	for _, backend := range backends {
		fingerprint += backend.ID + ":" + backend.Type + ":"
		if backend.HardwareBacked {
			fingerprint += "hw:"
		}
	}

	// If we have TPM2, include that indicator for a more stable fingerprint
	if hasTPM2 {
		fingerprint += "tpm2-present"
	}

	// Hash the fingerprint for consistent length
	if fingerprint != "" {
		h := sha256.Sum256([]byte(fingerprint))
		return hex.EncodeToString(h[:])
	}

	return ""
}

// handleError maps Go errors to JSON-RPC error responses.
func (b *Bridge) handleError(id uint64, err error) *Response {
	code, message := mapErrorToRPC(err)
	return b.errorResponse(id, code, message)
}

// errorResponse constructs a JSON-RPC error response.
func (b *Bridge) errorResponse(id uint64, code int, message string) *Response {
	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
}

// mapErrorToRPC translates a Go error into an appropriate JSON-RPC error
// code and message.
func mapErrorToRPC(err error) (int, string) {
	// errors.Is, not `switch err`: the handlers wrap their causes (tpmError
	// returns a *SentinelCauseError), and identity comparison silently drops
	// every wrapped error through to ErrorCodeInternalError. That was observed
	// on real hardware — an unprovisioned IAK reported -32603 instead of an
	// attestation code, with only the cause text to go on.
	switch {
	case errors.Is(err, ErrBridgeNotConnected):
		return ErrorCodeInternalError, "xkmsd client not connected"
	case errors.Is(err, ErrBridgeBackendDenied):
		return ErrorCodeBackendDenied, "backend access denied"
	case errors.Is(err, ErrBridgeInvalidParams):
		return ErrorCodeInvalidParams, "invalid request parameters"
	case errors.Is(err, ErrAttestationNotSupported):
		return ErrorCodeAttestUnsupported, "attestation not supported via bridge"
	case errors.Is(err, ErrTPM2DirectAccessRequired):
		return ErrorCodeAttestUnsupported, "operation requires direct TPM2 access; use xkmsd TPM2 backend"
	case errors.Is(err, ErrTPMNotConfigured):
		return ErrorCodeAttestUnsupported, "no TPM is configured on this host"
	case errors.Is(err, ErrTPMUnavailable):
		return ErrorCodeAttestFailed, "this host has a TPM but xkey cannot reach it; check permissions on the TPM device"
	case errors.Is(err, ErrEKCertificateMissing):
		return ErrorCodeAttestUnsupported, "the TPM has no endorsement key certificate"
	case errors.Is(err, ErrTPMKeyNotProvisioned):
		return ErrorCodeAttestFailed, "TPM key is not provisioned; provision before enrolling"
	case errors.Is(err, ErrTPMOperationFailed):
		return ErrorCodeAttestFailed, "TPM operation failed"
	case errors.Is(err, ErrInvalidCertificate):
		return ErrorCodeInvalidParams, "certificate is not valid X.509"
	case errors.Is(err, ErrShareDenied):
		return ErrorCodeShareDenied, "key sharing denied by policy"
	case errors.Is(err, ErrShareNotExportable):
		return ErrorCodeShareNotExportable, "key not exportable for sharing"
	case errors.Is(err, ErrInvalidPublicKey):
		return ErrorCodeInvalidPublicKey, "invalid public key data"
	case errors.Is(err, ErrKeyNotFound):
		return ErrorCodeKeyNotFound, "key not found"
	case errors.Is(err, ErrKeyExists):
		return ErrorCodeKeyExists, "key already exists"
	case errors.Is(err, ErrInvalidFormat):
		return ErrorCodeInvalidFormat, "invalid format requested"
	case errors.Is(err, ErrBackupFailed):
		return ErrorCodeBackupFailed, "phone: backup creation failed"
	case errors.Is(err, ErrBackupRestoreFailed):
		return ErrorCodeBackupRestore, "phone: backup restore failed"
	case errors.Is(err, ErrBackupNotFound):
		return ErrorCodeBackupNotFound, "phone: backup not found"
	case errors.Is(err, ErrOATHCredentialNotFound):
		return ErrorCodeOATHNotFound, "phone: OATH credential not found"
	case errors.Is(err, ErrOATHGenerateFailed):
		return ErrorCodeOATHGenerate, "phone: OATH code generation failed"
	case errors.Is(err, ErrOATHStoreFailed):
		return ErrorCodeOATHStore, "phone: OATH store operation failed"
	case errors.Is(err, ErrPIVSlotNotFound):
		return ErrorCodePIVSlotNotFound, "phone: PIV slot not found"
	case errors.Is(err, ErrPIVSlotOccupied):
		return ErrorCodePIVSlotOccupied, "phone: PIV slot already occupied"
	case errors.Is(err, ErrPIVSignFailed):
		return ErrorCodePIVSignFailed, "phone: PIV signing failed"
	case errors.Is(err, ErrPIVInvalidSlot):
		return ErrorCodePIVInvalidSlot, "phone: invalid PIV slot identifier"
	case errors.Is(err, ErrSyncFailed):
		return ErrorCodeSyncFailed, "phone: sync failed"
	case errors.Is(err, ErrSyncConflict):
		return ErrorCodeSyncConflict, "phone: sync conflict detected"
	case errors.Is(err, ErrSyncRemoteUnavailable):
		return ErrorCodeSyncRemoteUnavail, "phone: sync remote device unavailable"
	case errors.Is(err, ErrSyncNoData):
		return ErrorCodeSyncNoData, "phone: no data available for sync"
	case errors.Is(err, ErrSyncVersionMismatch):
		return ErrorCodeSyncVersionMismatch, "phone: sync version mismatch"
	case errors.Is(err, ErrOATHNotConfigured):
		return ErrorCodeFeatureUnavailable, "phone: no OATH credential store is configured on this host"
	case errors.Is(err, ErrPIVNotConfigured):
		return ErrorCodeFeatureUnavailable, "phone: no PIV certificate storage is configured for this backend"
	case errors.Is(err, ErrSyncNotConfigured):
		return ErrorCodeFeatureUnavailable, "phone: sync is not configured on this host"
	case errors.Is(err, ErrBackupNotConfigured):
		return ErrorCodeFeatureUnavailable, "phone: backup is not configured on this host"
	case errors.Is(err, ErrSyncApprovalRequired):
		return ErrorCodeSyncApprovalRequired, "phone: exporting secrets to the phone requires desktop approval, which is not configured on this host"
	case errors.Is(err, ErrSyncNotApproved):
		return ErrorCodeSyncNotApproved, "phone: the desktop refused to export secrets to the phone"
	}

	// Fall through to a generic internal error for unrecognized errors.
	return ErrorCodeInternalError, err.Error()
}

// mapSDKBackendInfo converts an SDK BackendInfo to the phone protocol BackendInfo.
func mapSDKBackendInfo(sdk *transport.BackendInfo) BackendInfo {
	return BackendInfo{
		Name:            sdk.ID,
		Type:            sdk.Type,
		HardwareBacked:  sdk.HardwareBacked,
		Signing:         sdk.Capabilities.Signing,
		Decryption:      sdk.Capabilities.Decryption,
		SymmetricCrypto: sdk.Capabilities.SymmetricEncryption,
		KeyAgreement:    sdk.Capabilities.KeyAgreement,
		Attestation:     sdk.Capabilities.Attestation,
	}
}

// extractPublicKey extracts public key bytes from PEM-encoded key data in the
// requested format.
func extractPublicKey(publicKeyPEM string, requestedFormat string) ([]byte, string, error) {
	if publicKeyPEM == "" {
		return nil, "", ErrKeyNotFound
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, "", ErrInvalidPublicKey
	}

	switch requestedFormat {
	case "pem":
		return []byte(publicKeyPEM), "pem", nil
	case "der", "":
		// Default to DER format.
		return block.Bytes, "der", nil
	default:
		return nil, "", ErrInvalidFormat
	}
}

// unmarshalParams unmarshals json.RawMessage into the provided destination.
func unmarshalParams(params json.RawMessage, dest interface{}) error {
	if len(params) == 0 {
		return ErrBridgeInvalidParams
	}
	return json.Unmarshal(params, dest)
}
