// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package module

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Key provisioning gives a caller that cannot load this module -- a
// CGO_ENABLED=0 daemon -- the one thing it needs from the token: an EC key
// pair whose CKA_LABEL and CKA_ID are exactly the values a Cryptoki consumer
// will later look it up by.
//
// It does not write token records by hand. It drives a Module in process,
// against the same transport and the same token store the loaded module will
// use, and asks it for C_GenerateKeyPair. The objects on the token are
// therefore the objects the module itself creates, attribute for attribute,
// and a change to how the module represents a key pair reaches provisioned
// keys without a second implementation to keep in step.

// provisionSlot is the token's slot. The module presents a single slot.
const provisionSlot SlotID = 0

// provisionCurves maps the curves a provisioned key may use to their elliptic
// curve and canonical CKA_EC_PARAMS. P-256 and P-384 are the curves IKEv2
// (RFC 7427, RFC 8247) and X.509 issuance in this stack sign with.
var provisionCurves = map[string]struct {
	curve  elliptic.Curve
	params []byte
}{
	"P-256": {curve: elliptic.P256(), params: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}},
	"P-384": {curve: elliptic.P384(), params: []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}},
}

// Sentinel errors for key provisioning. ProvisionError wraps them.
var (
	// ErrProvisionClientRequired reports a ProvisionConfig with no transport.
	ErrProvisionClientRequired = errors.New("pkcs11 provision: transport client is required")

	// ErrProvisionStorageRequired reports a ProvisionConfig with no token store.
	ErrProvisionStorageRequired = errors.New("pkcs11 provision: token storage is required")

	// ErrProvisionLabelRequired reports a key request with no CKA_LABEL.
	ErrProvisionLabelRequired = errors.New("pkcs11 provision: key label is required")

	// ErrProvisionIDRequired reports a key request with no CKA_ID.
	ErrProvisionIDRequired = errors.New("pkcs11 provision: key id is required")

	// ErrProvisionCurveUnsupported reports a curve other than P-256 or P-384.
	ErrProvisionCurveUnsupported = errors.New("pkcs11 provision: curve must be P-256 or P-384")

	// ErrProvisionUserPINRequired reports a key request with no user PIN.
	ErrProvisionUserPINRequired = errors.New("pkcs11 provision: user PIN is required")

	// ErrProvisionSOPINRequired reports an uninitialized token and no SO PIN
	// to initialize it with.
	ErrProvisionSOPINRequired = errors.New("pkcs11 provision: token is not initialized and no SO PIN was given")

	// ErrProvisionECPoint reports a CKA_EC_POINT that is not a DER OCTET
	// STRING wrapping an uncompressed point.
	ErrProvisionECPoint = errors.New("pkcs11 provision: CKA_EC_POINT is not a DER OCTET STRING")

	// ErrProvisionKeyConflict reports a token that already holds a key under
	// the requested label or id that is not the requested key.
	ErrProvisionKeyConflict = errors.New("pkcs11 provision: token holds a different key under this label or id")
)

// ProvisionError reports the Cryptoki step that failed and why.
type ProvisionError struct {
	// Step names the operation, e.g. "C_Login(CKU_USER)".
	Step string
	// Err is the cause: a sentinel above or a *PKCS11Error.
	Err error
}

// Error implements error.
func (e *ProvisionError) Error() string {
	return "pkcs11 provision: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the cause.
func (e *ProvisionError) Unwrap() error { return e.Err }

// ProvisionConfig names where the key is created.
type ProvisionConfig struct {
	// Client reaches the key service that generates and holds the key: the
	// in-process embedded transport, or a gRPC/unix transport to xkmsd.
	Client PKCS11Transport

	// Storage is the token store the loaded module reads: for a remote-mode
	// module, the server's PKCS#11 state for (tenant, token label).
	Storage storage.Backend

	// Backend is the key-service backend that generates the key ("tpm2",
	// "software", "pkcs11", a cloud KMS). Empty selects the module default.
	Backend string

	// Timeout bounds each operation. Zero selects the module default.
	Timeout time.Duration
}

// KeyPairRequest describes the key to create.
type KeyPairRequest struct {
	// Label is the CKA_LABEL the key pair carries.
	Label string
	// ID is the CKA_ID the key pair carries.
	ID []byte
	// Curve is "P-256" or "P-384".
	Curve string
	// UserPIN logs in to the token.
	UserPIN string
	// SOPIN initializes the token when it is not yet initialized; it is not
	// needed, and not used, for an initialized token.
	SOPIN string
	// TokenLabel is the token label written when the token is initialized.
	TokenLabel string
}

// ProvisionedKeyPair describes the key pair on the token.
type ProvisionedKeyPair struct {
	// Label and ID are the CKA_LABEL and CKA_ID of both objects.
	Label string
	ID    []byte
	// KeyID is the key service's identifier for the private key, the value a
	// sign request names.
	KeyID string
	// Backend is the key-service backend that holds it.
	Backend string
	// Curve is the curve name.
	Curve string
	// PublicKey is the key pair's public half.
	PublicKey *ecdsa.PublicKey
	// Created is false when the token already held this exact key pair and
	// provisioning returned it unchanged.
	Created bool
}

// ProvisionECKeyPair creates an EC key pair on the token cfg names, labelled
// and identified as req asks, and returns it. It is idempotent: when the token
// already holds a key pair with the same label, id and curve it is returned
// with Created false, and when it holds a different key under either the
// label or the id ErrProvisionKeyConflict is returned and nothing is created.
func ProvisionECKeyPair(ctx context.Context, cfg ProvisionConfig, req KeyPairRequest) (*ProvisionedKeyPair, error) {
	curve, err := validateProvisionRequest(cfg, req)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, &ProvisionError{Step: "context", Err: err}
	}

	moduleConfig := DefaultConfig()
	if cfg.Backend != "" {
		moduleConfig.DefaultBackend = cfg.Backend
	}
	if cfg.Timeout > 0 {
		moduleConfig.Timeout = cfg.Timeout
	}
	m, err := New(WithConfig(moduleConfig), WithClient(cfg.Client), WithStorage(cfg.Storage))
	if err != nil {
		return nil, &ProvisionError{Step: "module", Err: err}
	}
	if rv := m.Initialize(nil); rv != CKR_OK {
		return nil, rvError("C_Initialize", rv)
	}
	defer m.Finalize()

	if err := ensureTokenInitialized(m, req); err != nil {
		return nil, err
	}

	session, rv := m.OpenSession(provisionSlot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if rv != CKR_OK {
		return nil, rvError("C_OpenSession", rv)
	}
	defer m.CloseSession(session)

	if rv := m.Login(session, CKU_USER, []byte(req.UserPIN)); rv != CKR_OK {
		return nil, rvError("C_Login(CKU_USER)", rv)
	}
	defer m.Logout(session)

	existing, err := findProvisionedKey(m, session, req, curve)
	if err != nil || existing != nil {
		return existing, err
	}

	pubTemplate := []Attribute{
		NewULongAttribute(CKA_CLASS, uint64(CKO_PUBLIC_KEY)),
		NewULongAttribute(CKA_KEY_TYPE, uint64(CKK_EC)),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_VERIFY, true),
		NewStringAttribute(CKA_LABEL, req.Label),
		NewAttribute(CKA_ID, req.ID),
		NewAttribute(CKA_EC_PARAMS, provisionCurves[curve].params),
	}
	privTemplate := []Attribute{
		NewULongAttribute(CKA_CLASS, uint64(CKO_PRIVATE_KEY)),
		NewULongAttribute(CKA_KEY_TYPE, uint64(CKK_EC)),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, true),
		NewBoolAttribute(CKA_SENSITIVE, true),
		NewBoolAttribute(CKA_EXTRACTABLE, false),
		NewBoolAttribute(CKA_SIGN, true),
		NewStringAttribute(CKA_LABEL, req.Label),
		NewAttribute(CKA_ID, req.ID),
	}
	_, privHandle, rv := m.GenerateKeyPair(session, &Mechanism{Type: CKM_EC_KEY_PAIR_GEN}, pubTemplate, privTemplate)
	if rv != CKR_OK {
		return nil, rvError("C_GenerateKeyPair", rv)
	}

	key, err := describeProvisionedKey(m, privHandle, curve)
	if err != nil {
		return nil, err
	}
	key.Created = true
	return key, nil
}

// validateProvisionRequest checks everything that can be checked before a
// module is built, and returns the canonical curve name.
func validateProvisionRequest(cfg ProvisionConfig, req KeyPairRequest) (string, error) {
	checks := []struct {
		failed bool
		err    error
	}{
		{cfg.Client == nil, ErrProvisionClientRequired},
		{cfg.Storage == nil, ErrProvisionStorageRequired},
		{req.Label == "", ErrProvisionLabelRequired},
		{len(req.ID) == 0, ErrProvisionIDRequired},
		{req.UserPIN == "", ErrProvisionUserPINRequired},
	}
	for _, check := range checks {
		if check.failed {
			return "", &ProvisionError{Step: "request", Err: check.err}
		}
	}
	if _, ok := provisionCurves[req.Curve]; !ok {
		return "", &ProvisionError{Step: "request", Err: ErrProvisionCurveUnsupported}
	}
	return req.Curve, nil
}

// ensureTokenInitialized initializes an uninitialized token with the SO PIN
// and sets the user PIN, exactly as an operator would with C_InitToken and
// C_InitPIN. An initialized token is left alone.
func ensureTokenInitialized(m *Module, req KeyPairRequest) error {
	info, rv := m.GetTokenInfo(provisionSlot)
	if rv != CKR_OK {
		return rvError("C_GetTokenInfo", rv)
	}
	if info.Flags&CKF_TOKEN_INITIALIZED != 0 {
		return nil
	}
	if req.SOPIN == "" {
		return &ProvisionError{Step: "C_InitToken", Err: ErrProvisionSOPINRequired}
	}
	if rv := m.InitToken(provisionSlot, []byte(req.SOPIN), req.TokenLabel); rv != CKR_OK {
		return rvError("C_InitToken", rv)
	}

	session, rv := m.OpenSession(provisionSlot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if rv != CKR_OK {
		return rvError("C_OpenSession", rv)
	}
	defer m.CloseSession(session)
	if rv := m.Login(session, CKU_SO, []byte(req.SOPIN)); rv != CKR_OK {
		return rvError("C_Login(CKU_SO)", rv)
	}
	defer m.Logout(session)
	if rv := m.InitPIN(session, []byte(req.UserPIN)); rv != CKR_OK {
		return rvError("C_InitPIN", rv)
	}
	return nil
}

// findProvisionedKey looks for private keys already carrying the requested
// label or id. It returns the key when exactly the requested key pair is
// present, nil when neither is in use, and ErrProvisionKeyConflict otherwise.
func findProvisionedKey(m *Module, session SessionHandle, req KeyPairRequest, curve string) (*ProvisionedKeyPair, error) {
	byLabel, err := findPrivateKeys(m, session, NewStringAttribute(CKA_LABEL, req.Label))
	if err != nil {
		return nil, err
	}
	byID, err := findPrivateKeys(m, session, NewAttribute(CKA_ID, req.ID))
	if err != nil {
		return nil, err
	}
	if len(byLabel) == 0 && len(byID) == 0 {
		return nil, nil
	}
	if len(byLabel) != 1 || len(byID) != 1 || byLabel[0] != byID[0] {
		return nil, &ProvisionError{Step: "C_FindObjects", Err: ErrProvisionKeyConflict}
	}
	key, err := describeProvisionedKey(m, byLabel[0], "")
	if err != nil {
		return nil, err
	}
	if key.Curve != curve {
		return nil, &ProvisionError{
			Step: "C_FindObjects",
			Err:  &provisionConflictDetail{err: ErrProvisionKeyConflict, detail: "existing key is on " + key.Curve},
		}
	}
	return key, nil
}

// provisionConflictDetail adds what differs to ErrProvisionKeyConflict.
type provisionConflictDetail struct {
	err    error
	detail string
}

func (e *provisionConflictDetail) Error() string { return e.err.Error() + ": " + e.detail }
func (e *provisionConflictDetail) Unwrap() error { return e.err }

// findPrivateKeys returns the private-key objects matching match.
func findPrivateKeys(m *Module, session SessionHandle, match Attribute) ([]ObjectHandle, error) {
	template := []Attribute{NewULongAttribute(CKA_CLASS, uint64(CKO_PRIVATE_KEY)), match}
	if rv := m.FindObjectsInit(session, template); rv != CKR_OK {
		return nil, rvError("C_FindObjectsInit", rv)
	}
	handles, rv := m.FindObjects(session, 16)
	if finalRV := m.FindObjectsFinal(session); rv == CKR_OK {
		rv = finalRV
	}
	if rv != CKR_OK {
		return nil, rvError("C_FindObjects", rv)
	}
	return handles, nil
}

// describeProvisionedKey reads a private key object back into a
// ProvisionedKeyPair. wantCurve, when set, is the curve the caller expects;
// it is compared by the caller, so an empty value reports whatever the key is.
func describeProvisionedKey(m *Module, handle ObjectHandle, wantCurve string) (*ProvisionedKeyPair, error) {
	m.mu.RLock()
	obj, err := m.objectManager.getObjectUnchecked(handle)
	m.mu.RUnlock()
	if err != nil {
		return nil, &ProvisionError{Step: "read key object", Err: err}
	}

	params := obj.GetAttribute(CKA_EC_PARAMS)
	curveName := ""
	for name, c := range provisionCurves {
		if bytes.Equal(params, c.params) {
			curveName = name
		}
	}
	if curveName == "" || (wantCurve != "" && curveName != wantCurve) {
		return nil, &ProvisionError{Step: "read key object", Err: &provisionConflictDetail{
			err: ErrProvisionKeyConflict, detail: "key object does not carry a P-256 or P-384 CKA_EC_PARAMS",
		}}
	}

	pub, err := ecPublicKeyFromPoint(provisionCurves[curveName].curve, obj.GetAttribute(CKA_EC_POINT))
	if err != nil {
		return nil, &ProvisionError{Step: "read key object", Err: err}
	}

	return &ProvisionedKeyPair{
		Label:     string(obj.GetAttribute(CKA_LABEL)),
		ID:        copyBytes(obj.GetAttribute(CKA_ID)),
		KeyID:     obj.KeyID,
		Backend:   obj.BackendName,
		Curve:     curveName,
		PublicKey: pub,
	}, nil
}

// ecPublicKeyFromPoint decodes a CKA_EC_POINT -- the DER OCTET STRING
// wrapping an uncompressed X9.62 point, PKCS#11 v3.2 §6.3.3 -- on curve.
func ecPublicKeyFromPoint(curve elliptic.Curve, ecPoint []byte) (*ecdsa.PublicKey, error) {
	var point []byte
	rest, err := asn1.Unmarshal(ecPoint, &point)
	if err != nil || len(rest) != 0 {
		return nil, &ProvisionError{Step: "decode CKA_EC_POINT", Err: ErrProvisionECPoint}
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, &ProvisionError{Step: "decode CKA_EC_POINT", Err: err}
	}
	return pub, nil
}

// rvError wraps a Cryptoki return value as the cause of step.
func rvError(step string, rv CK_RV) error {
	return &ProvisionError{Step: step, Err: NewPKCS11ErrorWithMessage(rv, fmt.Sprintf("returned %s", rv.String()))}
}
