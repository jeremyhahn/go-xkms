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

package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// FIDO2 service errors.
var (
	ErrFIDO2CredentialNotFound   = errors.New("fido2_service: credential not found")
	ErrFIDO2InvalidID            = errors.New("fido2_service: invalid credential ID")
	ErrFIDO2BridgeRunning        = errors.New("fido2_service: bridge already running")
	ErrFIDO2BridgeStopped        = errors.New("fido2_service: bridge not running")
	ErrFIDO2StorageNotSet        = errors.New("fido2_service: storage not configured")
	ErrFIDO2BridgeNoClient       = errors.New("fido2_service: no server connection for bridge")
	ErrFIDO2RPPolicyStoreNotSet  = errors.New("fido2_service: RP policy store not configured")
	ErrFIDO2TokenStoreNotSet     = errors.New("fido2_service: token store not configured")
	ErrFIDO2AuthResponseNotFound = errors.New("fido2_service: auth response not found")
	ErrFIDO2KeyBackendNotSet     = errors.New("fido2_service: key backend not configured")
	ErrFIDO2BackendNotFound      = errors.New("fido2_service: backend not found in composite")
)

// coseAlgorithmNames maps COSE algorithm identifiers to human-readable names.
var coseAlgorithmNames = map[int]string{
	-7:   "ES256",
	-35:  "ES384",
	-36:  "ES512",
	-257: "RS256",
	-258: "RS384",
	-259: "RS512",
	-8:   "EdDSA",
}

// FIDO2Credential describes a WebAuthn credential stored locally.
type FIDO2Credential struct {
	ID              string    `json:"id"`
	RelyingPartyID  string    `json:"relying_party_id"`
	RelyingParty    string    `json:"relying_party"`
	UserName        string    `json:"user_name"`
	UserDisplayName string    `json:"user_display_name"`
	Algorithm       string    `json:"algorithm"`
	KeyType         string    `json:"key_type"`
	CredProtect     int       `json:"cred_protect"`
	BackendType     string    `json:"backend_type"`
	BackendID       string    `json:"backend_id"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsed        time.Time `json:"last_used"`
	UseCount        int       `json:"use_count"`
	Discoverable    bool      `json:"discoverable"`
}

// credProtectLabel returns a human-readable label for a credProtect level.
var credProtectLabels = map[uint8]string{
	0: "None",
	1: "UV Optional",
	2: "UV Optional + Allow List",
	3: "UV Required",
}

// coseKeyTypes maps COSE algorithm identifiers to key type descriptions.
var coseKeyTypes = map[int]string{
	-7:   "ECDSA P-256",
	-35:  "ECDSA P-384",
	-36:  "ECDSA P-521",
	-257: "RSA",
	-258: "RSA",
	-259: "RSA",
	-8:   "EdDSA (Ed25519)",
}

// RelyingParty summarizes a relying party that has credentials.
type RelyingParty struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	CredentialCount int    `json:"credential_count"`
}

// BridgeStatus describes the state of the FIDO2 phone bridge.
type BridgeStatus struct {
	Running        bool      `json:"running"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	Uptime         string    `json:"uptime,omitempty"`
	Requests       int64     `json:"requests"`
	DeviceName     string    `json:"device_name,omitempty"`
	ConnectionType string    `json:"connection_type,omitempty"`
}

// FIDO2RPPolicy is a flat, JSON-serializable representation of an RP policy
// for the Svelte frontend. The UPOverride *bool from the domain type is
// represented as a string: "", "true", or "false".
type FIDO2RPPolicy struct {
	RPID                string `json:"rpid"`
	UVOverride          string `json:"uv_override"`
	UPOverride          string `json:"up_override"`
	AttestationOverride string `json:"attestation_override"`
	Enterprise          bool   `json:"enterprise"`
	Blocked             bool   `json:"blocked"`
}

// FIDO2AuthResponse represents a stored FIDO2 authentication response.
type FIDO2AuthResponse struct {
	CredentialID string    `json:"credential_id"`
	RPID         string    `json:"rpid"`
	Token        string    `json:"token"`
	TokenType    string    `json:"token_type"` // "jwt" or "json"
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// FIDO2Service exposes FIDO2/WebAuthn operations to the frontend.
type FIDO2Service struct {
	ctx           context.Context
	storage       authenticator.StatefulCredentialStorage
	rpPolicyStore authenticator.RPPolicyStore
	tokenStore    tokenstore.TokenStore
	auditLogger   audit.Logger
	clientFunc    func() xkms.Client
	keyBackend    *keybackend.CompositeBackend
	bridge        *phone.Bridge
	bridgeMu      sync.Mutex
	bridgeRunning atomic.Bool
	bridgeStart   time.Time
	bridgeReqs    atomic.Int64
}

// NewFIDO2Service creates a new FIDO2Service.
// The storage parameter may be nil; in that case the service operates in
// degraded mode and credential methods return empty data or ErrFIDO2StorageNotSet.
func NewFIDO2Service(storage authenticator.StatefulCredentialStorage) *FIDO2Service {
	return &FIDO2Service{
		storage: storage,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *FIDO2Service) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetStorage replaces the FIDO2 credential storage. This is used for deferred
// initialization when the data directory is created after construction.
func (s *FIDO2Service) SetStorage(storage authenticator.StatefulCredentialStorage) {
	s.storage = storage
}

// SetRPPolicyStore sets the RP policy store for deferred initialization.
func (s *FIDO2Service) SetRPPolicyStore(store authenticator.RPPolicyStore) {
	s.rpPolicyStore = store
}

// SetClientFunc sets the function used to obtain the SDK client for the phone bridge.
func (s *FIDO2Service) SetClientFunc(fn func() xkms.Client) {
	s.clientFunc = fn
}

// SetAuditLogger sets the audit logger for FIDO2 operations.
func (s *FIDO2Service) SetAuditLogger(l audit.Logger) {
	s.auditLogger = l
}

// SetTokenStore sets the token store for persisting FIDO2 auth responses.
func (s *FIDO2Service) SetTokenStore(store tokenstore.TokenStore) {
	s.tokenStore = store
}

// SetKeyBackend sets the composite FIDO2 key backend. This is used for deferred
// initialization when the authenticator is created after the barrier is unsealed.
func (s *FIDO2Service) SetKeyBackend(kb *keybackend.CompositeBackend) {
	s.keyBackend = kb
}

// SetDefaultBackend switches the active FIDO2 key backend used for new credential
// creation. The backendID must match a registered backend in the composite.
func (s *FIDO2Service) SetDefaultBackend(backendID types.BackendType) error {
	if s.keyBackend == nil {
		return ErrFIDO2KeyBackendNotSet
	}
	if s.keyBackend.Backend(backendID) == nil {
		return ErrFIDO2BackendNotFound
	}
	s.keyBackend.SetDefault(backendID)
	slog.Info("FIDO2 default backend changed", "backend_id", backendID)
	return nil
}

// DefaultBackend returns the current default FIDO2 key backend ID.
func (s *FIDO2Service) DefaultBackend() types.BackendType {
	if s.keyBackend == nil {
		return ""
	}
	return s.keyBackend.DefaultID()
}

// ListKeyBackends returns the IDs of all registered FIDO2 key backends.
func (s *FIDO2Service) ListKeyBackends() []types.BackendType {
	if s.keyBackend == nil {
		return nil
	}
	return s.keyBackend.Backends()
}

// ListCredentials returns all stored FIDO2 credentials.
func (s *FIDO2Service) ListCredentials() ([]FIDO2Credential, error) {
	if s.storage == nil {
		return []FIDO2Credential{}, nil
	}

	listable, ok := s.storage.(authenticator.ListableStorage)
	if !ok {
		return []FIDO2Credential{}, nil
	}

	credIDs, err := listable.ListAll()
	if err != nil {
		return nil, err
	}

	credentials := make([]FIDO2Credential, 0, len(credIDs))
	for _, credID := range credIDs {
		stored, err := s.storage.Load(credID)
		if err != nil {
			// Skip credentials that cannot be loaded.
			continue
		}
		credentials = append(credentials, storedToFIDO2Credential(stored))
	}

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2CredentialAccessed, "fido2", "", true, nil, 0)
	}

	return credentials, nil
}

// GetCredential returns a single FIDO2 credential by ID.
func (s *FIDO2Service) GetCredential(id string) (*FIDO2Credential, error) {
	if id == "" {
		return nil, ErrFIDO2InvalidID
	}

	if s.storage == nil {
		return nil, ErrFIDO2StorageNotSet
	}

	credID, err := hex.DecodeString(id)
	if err != nil {
		return nil, ErrFIDO2InvalidID
	}

	stored, err := s.storage.Load(credID)
	if err != nil {
		return nil, ErrFIDO2CredentialNotFound
	}

	cred := storedToFIDO2Credential(stored)

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2CredentialAccessed, "fido2", id, true, nil, 0)
	}

	return &cred, nil
}

// DeleteCredential removes a FIDO2 credential by ID.
func (s *FIDO2Service) DeleteCredential(id string) error {
	if id == "" {
		return ErrFIDO2InvalidID
	}

	if s.storage == nil {
		return ErrFIDO2StorageNotSet
	}

	credID, err := hex.DecodeString(id)
	if err != nil {
		return ErrFIDO2InvalidID
	}

	if err := s.storage.Delete(credID); err != nil {
		return ErrFIDO2CredentialNotFound
	}

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2CredentialDeleted, "fido2", id, true, nil, 0)
	}

	return nil
}

// GetRelyingParties returns all relying parties with stored credentials.
func (s *FIDO2Service) GetRelyingParties() ([]RelyingParty, error) {
	if s.storage == nil {
		return []RelyingParty{}, nil
	}

	credentials, err := s.ListCredentials()
	if err != nil {
		return nil, err
	}

	// Aggregate credentials by relying party ID.
	type rpInfo struct {
		name  string
		count int
	}
	rpMap := make(map[string]*rpInfo, len(credentials))

	for _, cred := range credentials {
		info, exists := rpMap[cred.RelyingPartyID]
		if !exists {
			rpMap[cred.RelyingPartyID] = &rpInfo{
				name:  cred.RelyingParty,
				count: 1,
			}
			continue
		}
		info.count++
	}

	parties := make([]RelyingParty, 0, len(rpMap))
	for id, info := range rpMap {
		parties = append(parties, RelyingParty{
			ID:              id,
			Name:            info.name,
			CredentialCount: info.count,
		})
	}

	return parties, nil
}

// StartPhoneBridge starts the FIDO2 phone bridge service.
func (s *FIDO2Service) StartPhoneBridge() error {
	if s.bridgeRunning.Load() {
		return ErrFIDO2BridgeRunning
	}
	s.bridgeMu.Lock()
	defer s.bridgeMu.Unlock()

	if s.clientFunc == nil {
		return ErrFIDO2BridgeNoClient
	}
	client := s.clientFunc()
	if client == nil {
		return ErrFIDO2BridgeNoClient
	}

	bridgeCfg := &phone.BridgeConfig{
		RequestTimeout: phone.DefaultBridgeRequestTimeout,
		Logger:         slog.Default(),
		AuditLogger:    s.auditLogger,
	}
	bridge, err := phone.NewBridge(client, bridgeCfg)
	if err != nil {
		return err
	}

	s.bridge = bridge
	s.bridgeStart = time.Now()
	s.bridgeRunning.Store(true)
	s.bridgeReqs.Store(0)

	if s.auditLogger != nil {
		s.auditLogger.LogServiceEvent(audit.OpServiceStarted, map[string]any{
			"service": "fido2_phone_bridge",
		})
	}
	return nil
}

// StopPhoneBridge stops the FIDO2 phone bridge service.
func (s *FIDO2Service) StopPhoneBridge() error {
	if !s.bridgeRunning.Load() {
		return ErrFIDO2BridgeStopped
	}
	s.bridgeMu.Lock()
	defer s.bridgeMu.Unlock()

	if s.bridge != nil {
		s.bridge.Close()
		s.bridge = nil
	}
	s.bridgeRunning.Store(false)

	if s.auditLogger != nil {
		s.auditLogger.LogServiceEvent(audit.OpServiceStopped, map[string]any{
			"service": "fido2_phone_bridge",
		})
	}
	return nil
}

// GetBridgeStatus returns the current state of the phone bridge.
func (s *FIDO2Service) GetBridgeStatus() *BridgeStatus {
	running := s.bridgeRunning.Load()
	status := &BridgeStatus{
		Running:  running,
		Requests: s.bridgeReqs.Load(),
	}
	if running {
		status.StartedAt = s.bridgeStart
		status.Uptime = time.Since(s.bridgeStart).Truncate(time.Second).String()
	}
	return status
}

// HandleBridgeRequest forwards a JSON-RPC request from a connected phone to the
// bridge and returns the raw JSON result.
func (s *FIDO2Service) HandleBridgeRequest(method string, params json.RawMessage) (json.RawMessage, error) {
	if !s.bridgeRunning.Load() || s.bridge == nil {
		return nil, ErrFIDO2BridgeStopped
	}
	s.bridgeReqs.Add(1)
	resp := s.bridge.HandleRequest(s.ctx, &phone.Request{
		JSONRPC: phone.JSONRPCVersion,
		ID:      uint64(s.bridgeReqs.Load()),
		Method:  method,
		Params:  params,
	})
	if resp.Error != nil {
		return nil, fmt.Errorf("fido2_service: bridge: %s", resp.Error.Message)
	}
	return resp.Result, nil
}

// StoreAuthResponse persists a FIDO2 authentication response in the token store.
func (s *FIDO2Service) StoreAuthResponse(resp *FIDO2AuthResponse) error {
	if s.tokenStore == nil {
		return ErrFIDO2TokenStoreNotSet
	}
	if resp == nil || resp.Token == "" {
		return ErrFIDO2InvalidID
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	entry := &tokenstore.TokenEntry{
		ServerURL: "fido2:" + resp.RPID,
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
		Token:     resp.Token,
		IssuedAt:  resp.CreatedAt,
		ExpiresAt: resp.ExpiresAt,
		Issuer:    resp.RPID,
		Subject:   resp.CredentialID,
	}

	if err := s.tokenStore.Save(ctx, entry); err != nil {
		return err
	}

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2CredentialAccessed, "fido2", resp.CredentialID, true, nil, 0)
	}

	return nil
}

// GetAuthResponses returns all stored FIDO2 authentication responses.
func (s *FIDO2Service) GetAuthResponses() []*FIDO2AuthResponse {
	if s.tokenStore == nil {
		return nil
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	entries, err := s.tokenStore.List(ctx)
	if err != nil {
		return nil
	}

	var responses []*FIDO2AuthResponse
	for _, entry := range entries {
		if entry.Source != tokenstore.SourceFIDO2 {
			continue
		}
		responses = append(responses, &FIDO2AuthResponse{
			CredentialID: entry.Subject,
			RPID:         entry.Issuer,
			Token:        entry.Token,
			TokenType:    "jwt",
			CreatedAt:    entry.IssuedAt,
			ExpiresAt:    entry.ExpiresAt,
		})
	}

	return responses
}

// GetLatestToken returns the latest JWT token for the given relying party ID.
func (s *FIDO2Service) GetLatestToken(rpID string) (string, error) {
	if s.tokenStore == nil {
		return "", ErrFIDO2TokenStoreNotSet
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	entry, err := s.tokenStore.Load(ctx, "fido2:"+rpID)
	if err != nil {
		return "", ErrFIDO2AuthResponseNotFound
	}

	return entry.Token, nil
}

// ListRPPolicies returns all SO-configured RP policies.
func (s *FIDO2Service) ListRPPolicies() ([]FIDO2RPPolicy, error) {
	if s.rpPolicyStore == nil {
		return []FIDO2RPPolicy{}, nil
	}

	policies, err := s.rpPolicyStore.ListPolicies()
	if err != nil {
		return nil, err
	}

	result := make([]FIDO2RPPolicy, 0, len(policies))
	for _, p := range policies {
		result = append(result, rpPolicyToGUI(p))
	}

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2RPPolicyAccessed, "fido2", "", true, nil, 0)
	}

	return result, nil
}

// GetRPPolicy returns the RP policy for the given RPID.
func (s *FIDO2Service) GetRPPolicy(rpID string) (*FIDO2RPPolicy, error) {
	if s.rpPolicyStore == nil {
		return nil, ErrFIDO2RPPolicyStoreNotSet
	}

	policy, err := s.rpPolicyStore.GetPolicy(rpID)
	if err != nil {
		return nil, err
	}

	gui := rpPolicyToGUI(policy)

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2RPPolicyAccessed, "fido2", rpID, true, nil, 0)
	}

	return &gui, nil
}

// SetRPPolicy creates or updates an RP policy.
func (s *FIDO2Service) SetRPPolicy(policy FIDO2RPPolicy) error {
	if s.rpPolicyStore == nil {
		return ErrFIDO2RPPolicyStoreNotSet
	}

	domain := guiToRPPolicy(policy)
	if err := domain.Validate(); err != nil {
		return err
	}

	if err := s.rpPolicyStore.SetPolicy(domain); err != nil {
		return err
	}

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2RPPolicySet, "fido2", policy.RPID, true, nil, 0)
	}

	return nil
}

// DeleteRPPolicy removes the RP policy for the given RPID.
func (s *FIDO2Service) DeleteRPPolicy(rpID string) error {
	if s.rpPolicyStore == nil {
		return ErrFIDO2RPPolicyStoreNotSet
	}

	if err := s.rpPolicyStore.DeletePolicy(rpID); err != nil {
		return err
	}

	if s.auditLogger != nil {
		s.auditLogger.LogKeyOperation(audit.OpFIDO2RPPolicyDeleted, "fido2", rpID, true, nil, 0)
	}

	return nil
}

// rpPolicyToGUI converts a domain RPPolicy to the GUI-friendly FIDO2RPPolicy.
func rpPolicyToGUI(p *authenticator.RPPolicy) FIDO2RPPolicy {
	upOverride := ""
	if p.UPOverride != nil {
		if *p.UPOverride {
			upOverride = "true"
		} else {
			upOverride = "false"
		}
	}
	return FIDO2RPPolicy{
		RPID:                p.RPID,
		UVOverride:          p.UVOverride,
		UPOverride:          upOverride,
		AttestationOverride: p.AttestationOverride,
		Enterprise:          p.Enterprise,
		Blocked:             p.Blocked,
	}
}

// guiToRPPolicy converts a GUI FIDO2RPPolicy to the domain RPPolicy.
func guiToRPPolicy(p FIDO2RPPolicy) *authenticator.RPPolicy {
	var upOverride *bool
	switch p.UPOverride {
	case "true":
		v := true
		upOverride = &v
	case "false":
		v := false
		upOverride = &v
	}
	return &authenticator.RPPolicy{
		RPID:                p.RPID,
		UVOverride:          p.UVOverride,
		UPOverride:          upOverride,
		AttestationOverride: p.AttestationOverride,
		Enterprise:          p.Enterprise,
		Blocked:             p.Blocked,
	}
}

// storedToFIDO2Credential converts an authenticator.StoredCredential to a
// FIDO2Credential suitable for the GUI frontend.
func storedToFIDO2Credential(stored *authenticator.StoredCredential) FIDO2Credential {
	keyType := coseKeyTypes[stored.Algorithm]
	if keyType == "" {
		keyType = fmt.Sprintf("Unknown(%d)", stored.Algorithm)
	}

	cpLabel := credProtectLabels[stored.CredProtect]
	if cpLabel == "" {
		cpLabel = "None"
	}

	// Determine backend type from BackendID or key material heuristic.
	// BackendType is the actual backend ID (e.g., "software", "tpm2", "softhsm2")
	// used by the frontend BackendSelector filter chips.
	backendType := "software"
	backendID := stored.BackendID
	if backendID != "" {
		backendType = string(backendID)
	} else if stored.PrivateKey == nil {
		// No exportable private key means a hardware backend (TPM, phone, etc.)
		backendType = "hardware"
	}

	return FIDO2Credential{
		ID:              hex.EncodeToString(stored.CredentialID),
		RelyingPartyID:  stored.RPID,
		RelyingParty:    stored.RPName,
		UserName:        stored.UserName,
		UserDisplayName: stored.UserDisplayName,
		Algorithm:       coseAlgorithmName(stored.Algorithm),
		KeyType:         keyType,
		CredProtect:     int(stored.CredProtect),
		BackendType:     backendType,
		BackendID:       string(backendID),
		CreatedAt:       time.Unix(stored.CreatedAt, 0),
		LastUsed:        time.Time{},
		UseCount:        int(stored.SignCount),
		Discoverable:    stored.Discoverable,
	}
}

// coseAlgorithmName returns the human-readable name for a COSE algorithm identifier.
func coseAlgorithmName(alg int) string {
	if name, ok := coseAlgorithmNames[alg]; ok {
		return name
	}
	return fmt.Sprintf("COSE(%d)", alg)
}
