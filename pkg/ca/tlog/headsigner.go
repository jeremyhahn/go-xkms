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

package tlog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ca/checkpoint"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// HeadSignerProvider is go-qrdb's HeadSignerProvider over the CA key: every
// log it serves is signed by the crypto.Signer the CA key provider exposes,
// through pkg/ca/checkpoint, so no head-signing key is ever generated or
// stored in go-qrdb. It is handed to the node with
// qrdbnode.WithHeadSignerProvider.
//
// go-qrdb records a head-signing key by its type, which RFC 9162 §2.1.4
// limits to Ed25519 and ECDSA P-256 with SHA-256, so a CA whose key is of
// another type is refused with ErrUnsupportedCAKey.
//
// The provider is node-wide: go-qrdb asks it for every log any tenant
// creates or signs. It serves only the one log it is bound to, so a tenant
// holding vlog:create and vlog:sign_head cannot obtain CA-signed
// checkpoints over a log of its own; any other log is refused with
// ErrLogOutOfScope before the CA key is reached.
type HeadSignerProvider struct {
	keys    qrdbsdk.CAKeyProvider
	keyName string
	scope   LogScope
}

var _ qrdbsdk.HeadSignerProvider = (*HeadSignerProvider)(nil)

// LogScope is the full identity of the one log a HeadSignerProvider signs
// for, as go-qrdb's key and signer requests name it.
type LogScope struct {
	TenantID string
	Database string
	Log      string
}

// ServiceLogScope is the scope of the log named name as the xkms service
// principal creates it through the node's embedded client: the reserved
// system tenant's own database, which go-qrdb names after the tenant.
func ServiceLogScope(name string) LogScope {
	return LogScope{TenantID: qrdbsdk.SystemTenantID, Database: qrdbsdk.SystemTenantID, Log: name}
}

// String renders the scope as tenant/database/log.
func (s LogScope) String() string {
	return s.TenantID + "/" + s.Database + "/" + s.Log
}

// NewHeadSignerProvider returns the provider signing through keys under
// keyName, the key name every checkpoint's signature line carries
// (signed-note §Signatures), for the log scope names and no other.
func NewHeadSignerProvider(keys qrdbsdk.CAKeyProvider, keyName string, scope LogScope) (*HeadSignerProvider, error) {
	if keys == nil {
		return nil, ErrNoKeyProvider
	}
	if keyName == "" {
		return nil, &errs.Detail{Err: checkpoint.ErrInvalidKeyName, Detail: "empty key name"}
	}
	if scope.TenantID == "" || scope.Database == "" || scope.Log == "" {
		return nil, &errs.Detail{Err: ErrInvalidConfig, Detail: "log scope needs a tenant, database and log name: " + scope.String()}
	}
	return &HeadSignerProvider{keys: keys, keyName: keyName, scope: scope}, nil
}

// checkScope refuses a request for any log but the provider's own.
func (p *HeadSignerProvider) checkScope(requested LogScope) error {
	if requested != p.scope {
		return &errs.Detail{Err: ErrLogOutOfScope, Detail: requested.String()}
	}
	return nil
}

// KeyName returns the key name the provider signs under.
func (p *HeadSignerProvider) KeyName() string {
	return p.keyName
}

// Verifier returns the checkpoint verifier of the CA key under the
// provider's key name: the key a client checks the log's checkpoints with.
func (p *HeadSignerProvider) Verifier(ctx context.Context) (*checkpoint.Verifier, error) {
	cp, _, err := p.checkpointSigner(ctx)
	if err != nil {
		return nil, err
	}
	return cp.Verifier(), nil
}

// CreateKey answers the CA key for a new log, or a rotation: req.Type must
// be the CA key's type. The reference is the hex SHA-256 of the key's
// SubjectPublicKeyInfo, and no key record is returned, so go-qrdb stores
// nothing but the public half.
func (p *HeadSignerProvider) CreateKey(ctx context.Context, req qrdbsdk.HeadSignerCreateKeyRequest) (qrdbsdk.HeadSignerCreatedKey, error) {
	if err := p.checkScope(LogScope{TenantID: req.TenantID, Database: req.Database, Log: req.Log}); err != nil {
		return qrdbsdk.HeadSignerCreatedKey{}, err
	}
	signer, sigType, err := p.caSigner(ctx)
	if err != nil {
		return qrdbsdk.HeadSignerCreatedKey{}, err
	}
	if req.Type != sigType {
		return qrdbsdk.HeadSignerCreatedKey{}, &errs.Detail{Err: ErrKeyTypeMismatch, Detail: string(req.Type) + " requested, CA key is " + string(sigType)}
	}
	ref, err := keyRef(signer.Public())
	if err != nil {
		return qrdbsdk.HeadSignerCreatedKey{}, err
	}
	return qrdbsdk.HeadSignerCreatedKey{Ref: ref, Public: signer.Public()}, nil
}

// HeadSigner returns the signer over the CA key, refusing with
// ErrKeyRefMismatch when the CA key is no longer the key req names.
func (p *HeadSignerProvider) HeadSigner(ctx context.Context, req qrdbsdk.HeadSignerRequest) (qrdbsdk.HeadSigner, error) {
	if err := p.checkScope(LogScope{TenantID: req.TenantID, Database: req.Database, Log: req.Log}); err != nil {
		return nil, err
	}
	cp, sigType, err := p.checkpointSigner(ctx)
	if err != nil {
		return nil, err
	}
	ref, err := keyRef(cp.Public())
	if err != nil {
		return nil, err
	}
	if req.KeyRef != ref {
		return nil, &errs.Detail{Err: ErrKeyRefMismatch, Detail: req.KeyRef}
	}
	return &headSigner{signer: cp, version: req.KeyVersion, sigType: sigType}, nil
}

// caSigner returns the CA key's signer and its head signature type.
func (p *HeadSignerProvider) caSigner(ctx context.Context) (crypto.Signer, qrdbsdk.HeadSignatureType, error) {
	signer, err := p.keys.Signer(ctx)
	if err != nil {
		return nil, "", &errs.Joined{Lead: ErrCAKeyUnavailable, Detail: "signer", Cause: err}
	}
	if signer == nil {
		return nil, "", &errs.Detail{Err: ErrCAKeyUnavailable, Detail: "nil signer"}
	}
	sigType, err := signatureType(signer.Public())
	if err != nil {
		return nil, "", err
	}
	return signer, sigType, nil
}

// checkpointSigner returns the CA key as a checkpoint signer.
func (p *HeadSignerProvider) checkpointSigner(ctx context.Context) (*caSignerNote, qrdbsdk.HeadSignatureType, error) {
	signer, sigType, err := p.caSigner(ctx)
	if err != nil {
		return nil, "", err
	}
	cp, err := checkpoint.NewSigner(p.keyName, signer)
	if err != nil {
		return nil, "", err
	}
	return &caSignerNote{Signer: cp, public: signer.Public()}, sigType, nil
}

// caSignerNote is a checkpoint signer with the public key it signs for.
type caSignerNote struct {
	*checkpoint.Signer
	public crypto.PublicKey
}

// Public returns the key the signer's signatures verify with.
func (s *caSignerNote) Public() crypto.PublicKey {
	return s.public
}

// headSigner is go-qrdb's HeadSigner over a checkpoint signer.
type headSigner struct {
	signer  *caSignerNote
	version uint32
	sigType qrdbsdk.HeadSignatureType
}

func (s *headSigner) Name() string                             { return s.signer.Name() }
func (s *headSigner) KeyHash() uint32                          { return s.signer.KeyID() }
func (s *headSigner) KeyVersion() uint32                       { return s.version }
func (s *headSigner) SignatureType() qrdbsdk.HeadSignatureType { return s.sigType }
func (s *headSigner) Public() crypto.PublicKey                 { return s.signer.Public() }

// Sign signs msg, the checkpoint body go-qrdb renders, as a signed note
// through pkg/ca/checkpoint and returns the signature line's signature
// without its key ID (signed-note §Signatures), the form go-qrdb puts back on
// the line it renders.
func (s *headSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signed, err := checkpoint.Sign(msg, s.signer.Signer)
	if err != nil {
		return nil, err
	}
	note, err := checkpoint.Open(signed, s.signer.Verifier())
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(note.Verified[0].Base64)
	if err != nil {
		return nil, &errs.Joined{Lead: checkpoint.ErrMalformedNote, Detail: "signature line", Cause: err}
	}
	return raw[4:], nil
}

// signatureType maps the CA public key to go-qrdb's head signature type.
func signatureType(pub crypto.PublicKey) (qrdbsdk.HeadSignatureType, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return qrdbsdk.HeadSignatureEd25519, nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return qrdbsdk.HeadSignatureECDSAP256SHA256, nil
		}
	}
	return "", ErrUnsupportedCAKey
}

// keyRef is the hex SHA-256 of pub's SubjectPublicKeyInfo.
func keyRef(pub crypto.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", &errs.Joined{Lead: ErrUnsupportedCAKey, Detail: "public key", Cause: err}
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:]), nil
}
