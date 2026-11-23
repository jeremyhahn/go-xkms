// Package tlog implements go-qrdb's verifiable-log head-signer seam over the
// go-xkms CA key: checkpoints of a transparency log are signed with the CA
// crypto.Signer, which never leaves the CA. go-xkms ships no log, Merkle or
// proof code; go-qrdb owns them.
package tlog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// KeyRef is the key reference the provider records in a log's descriptor:
// every log's key is the CA key.
const KeyRef = "xkms-ca"

// ErrCANotBound reports a head-signer request before the CA was bound.
var ErrCANotBound = errors.New("tlog: CA not bound to the head-signer provider")

// UnsupportedKeyError reports a CA key whose algorithm no signed tree head
// may use (RFC 9162 section 2.1.4 allows Ed25519 and ECDSA P-256).
type UnsupportedKeyError struct{ Key string }

func (e *UnsupportedKeyError) Error() string {
	return "tlog: CA key " + e.Key + " cannot sign a log checkpoint (Ed25519 or ECDSA P-256 required)"
}

// KeyTypeMismatchError reports a log asking for another signature type than
// the CA key has.
type KeyTypeMismatchError struct{ Want, Have qrdbsdk.HeadSignatureType }

func (e *KeyTypeMismatchError) Error() string {
	return fmt.Sprintf("tlog: log asks for a %s key, the CA key is %s", e.Want, e.Have)
}

// KeyRefError reports a key reference this provider did not create.
type KeyRefError struct{ Ref string }

func (e *KeyRefError) Error() string { return "tlog: key reference " + e.Ref + " is not the CA key" }

// SigningCA is the CA the provider signs with.
type SigningCA interface {
	Signer(ctx context.Context) (crypto.Signer, error)
}

type boundCA struct{ ca SigningCA }

// HeadSignerProvider is a qrdbsdk.HeadSignerProvider over the CA key. The
// node is built before the CA, whose stores live in it, so the CA is bound
// late with Bind.
type HeadSignerProvider struct {
	bound atomic.Pointer[boundCA]
}

var _ qrdbsdk.HeadSignerProvider = (*HeadSignerProvider)(nil)

// NewHeadSignerProvider returns an unbound provider.
func NewHeadSignerProvider() *HeadSignerProvider { return &HeadSignerProvider{} }

// Bind sets the CA whose key signs every log checkpoint.
func (p *HeadSignerProvider) Bind(ca SigningCA) error {
	if ca == nil {
		return ErrCANotBound
	}
	p.bound.Store(&boundCA{ca: ca})
	return nil
}

func (p *HeadSignerProvider) caSigner(ctx context.Context) (crypto.Signer, qrdbsdk.HeadSignatureType, error) {
	b := p.bound.Load()
	if b == nil {
		return nil, "", ErrCANotBound
	}
	signer, err := b.ca.Signer(ctx)
	if err != nil {
		return nil, "", err
	}
	typ, err := signatureType(signer.Public())
	if err != nil {
		return nil, "", err
	}
	return signer, typ, nil
}

func signatureType(pub crypto.PublicKey) (qrdbsdk.HeadSignatureType, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return qrdbsdk.HeadSignatureEd25519, nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return qrdbsdk.HeadSignatureECDSAP256SHA256, nil
		}
		return "", &UnsupportedKeyError{Key: "ECDSA " + k.Curve.Params().Name}
	default:
		return "", &UnsupportedKeyError{Key: fmt.Sprintf("%T", pub)}
	}
}

// CreateKey returns the CA public key as the log's key. No key record is
// written: the key stays in the CA.
func (p *HeadSignerProvider) CreateKey(ctx context.Context, req qrdbsdk.HeadSignerCreateKeyRequest) (qrdbsdk.HeadSignerCreatedKey, error) {
	signer, typ, err := p.caSigner(ctx)
	if err != nil {
		return qrdbsdk.HeadSignerCreatedKey{}, err
	}
	if typ != req.Type {
		return qrdbsdk.HeadSignerCreatedKey{}, &KeyTypeMismatchError{Want: req.Type, Have: typ}
	}
	return qrdbsdk.HeadSignerCreatedKey{Ref: KeyRef, Public: signer.Public()}, nil
}

// HeadSigner returns a signer over the CA key for the log req names.
func (p *HeadSignerProvider) HeadSigner(ctx context.Context, req qrdbsdk.HeadSignerRequest) (qrdbsdk.HeadSigner, error) {
	if req.KeyRef != KeyRef {
		return nil, &KeyRefError{Ref: req.KeyRef}
	}
	signer, typ, err := p.caSigner(ctx)
	if err != nil {
		return nil, err
	}
	name := req.TenantID + "/" + req.Database + "/" + req.Log
	hash, err := qrdbsdk.HeadKeyHash(name, signer.Public())
	if err != nil {
		return nil, err
	}
	return &caHeadSigner{name: name, hash: hash, version: req.KeyVersion, typ: typ, key: signer}, nil
}

type caHeadSigner struct {
	name    string
	hash    uint32
	version uint32
	typ     qrdbsdk.HeadSignatureType
	key     crypto.Signer
}

func (s *caHeadSigner) Name() string                             { return s.name }
func (s *caHeadSigner) KeyHash() uint32                          { return s.hash }
func (s *caHeadSigner) KeyVersion() uint32                       { return s.version }
func (s *caHeadSigner) SignatureType() qrdbsdk.HeadSignatureType { return s.typ }
func (s *caHeadSigner) Public() crypto.PublicKey                 { return s.key.Public() }

// Sign signs the checkpoint body: Ed25519 over the message, ECDSA over its
// SHA-256, as go-qrdb's software signer does.
func (s *caHeadSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.typ == qrdbsdk.HeadSignatureEd25519 {
		return s.key.Sign(nil, msg, crypto.Hash(0))
	}
	digest := sha256.Sum256(msg)
	return s.key.Sign(rand.Reader, digest[:], crypto.SHA256)
}
