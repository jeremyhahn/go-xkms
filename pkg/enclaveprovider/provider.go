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

package enclaveprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strconv"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var (
	_ enclave.KeyProtector   = (*KeyProtector)(nil)
	_ enclave.HealthReporter = (*KeyProtector)(nil)
	_ enclave.RootUnsealer   = (*RootUnsealer)(nil)
)

// KeyProtector is an enclave.KeyProtector over a go-xkms types.Sealer, for
// enclave.ModePerOperation: every Protect seals the data key under the
// sealing key and every Unprotect unseals it, so the long-lived key never
// leaves the backend.
//
// It is safe for concurrent use as far as its sealer is.
type KeyProtector struct {
	box sealBox
}

// NewKeyProtector returns a KeyProtector sealing under the key attrs names on
// sealer. attrs is copied; later changes to it have no effect.
//
// It returns ErrNilSealer, ErrNilKeyAttributes, or ErrSealerUnavailable when
// sealer.CanSeal reports false.
func NewKeyProtector(sealer types.Sealer, attrs *types.KeyAttributes) (*KeyProtector, error) {
	box, err := newSealBox(sealer, attrs)
	if err != nil {
		return nil, err
	}
	if !sealer.CanSeal() {
		return nil, ErrSealerUnavailable
	}
	return &KeyProtector{box: box}, nil
}

// Protect seals key, which must be enclave.RootKeyBytes long, and returns the
// envelope. It does not retain key.
//
// An ended context fails with an error matching ctx.Err() before the backend
// is called. Every failure matches ErrProtectFailed, except a wrong-length key,
// which is ErrInvalidKeyLength.
func (p *KeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if len(key) != enclave.RootKeyBytes {
		return nil, &errs.Detail{Err: ErrInvalidKeyLength, Detail: strconv.Itoa(len(key)) + " bytes"}
	}
	return p.box.seal(ctx, purposeKey, key, ErrProtectFailed)
}

// Unprotect recovers the key blob protects into key, which must be exactly
// the length Protect received. It neither retains nor modifies blob, and wipes
// the backend's plaintext on every path.
//
// A blob this provider did not produce, a wrong-length key, or a backend
// verdict that the sealed data is not authentic returns an error matching
// enclave.ErrSealedAuthentication. An ended context, before or during the
// call, and every other backend failure return an error matching
// ErrUnprotectFailed and the cause. On any failure key is left untouched.
func (p *KeyProtector) Unprotect(ctx context.Context, blob, key []byte) error {
	return p.box.open(ctx, purposeKey, blob, key, ErrUnprotectFailed)
}

// Health reports nil: the sealing key lives in the backend, beyond the reach
// of enclave.WipeAll and Sealer.Destroy, so a sweep never makes a protected
// key unrecoverable. It is not a device liveness probe.
func (p *KeyProtector) Health() error {
	return nil
}

// RootUnsealer is an enclave.RootUnsealer over a go-xkms types.Sealer, for
// enclave.ModeRootKey: it unseals a root key that ProvisionRoot sealed.
// UnsealRoot can be called any number of times and always yields the same
// root.
type RootUnsealer struct {
	box        sealBox
	sealedRoot []byte
}

// NewRootUnsealer returns a RootUnsealer for sealedRoot, a blob ProvisionRoot
// returned for the same sealer and key. sealedRoot and attrs are copied.
//
// It returns ErrNilSealer or ErrNilKeyAttributes, and an error matching
// enclave.ErrSealedAuthentication when sealedRoot is not a sealed root this
// package wrote. Whether the backend can unseal it is known only at
// UnsealRoot.
func NewRootUnsealer(sealer types.Sealer, attrs *types.KeyAttributes, sealedRoot []byte) (*RootUnsealer, error) {
	box, err := newSealBox(sealer, attrs)
	if err != nil {
		return nil, err
	}
	if _, err := decodeEnvelope(sealedRoot, purposeRoot); err != nil {
		return nil, err
	}
	return &RootUnsealer{box: box, sealedRoot: bytes.Clone(sealedRoot)}, nil
}

// UnsealRoot writes the root key into dst, which must be enclave.RootKeyBytes
// long. Errors are as for KeyProtector.Unprotect, with ErrUnsealRootFailed in
// place of ErrUnprotectFailed. A refused call consumes nothing, so a later
// call can succeed.
func (u *RootUnsealer) UnsealRoot(ctx context.Context, dst []byte) error {
	return u.box.open(ctx, purposeRoot, u.sealedRoot, dst, ErrUnsealRootFailed)
}

// ProvisionRoot generates a fresh root key in locked memory, from the process
// allocator, seals it under the key attrs names on sealer, and returns the
// sealed root for NewRootUnsealer. The root itself never reaches the ordinary
// heap on this side of the sealer, and its locked pages are destroyed before
// ProvisionRoot returns.
//
// It returns ErrNilSealer, ErrNilKeyAttributes or ErrSealerUnavailable, and
// otherwise an error matching ErrProvisionRootFailed and its cause.
func ProvisionRoot(ctx context.Context, sealer types.Sealer, attrs *types.KeyAttributes) (sealedRoot []byte, err error) {
	box, err := newSealBox(sealer, attrs)
	if err != nil {
		return nil, err
	}
	if !sealer.CanSeal() {
		return nil, ErrSealerUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, &errs.Joined{Lead: ErrProvisionRootFailed, Cause: err}
	}
	allocator, err := enclave.ProcessAllocator()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrProvisionRootFailed, Cause: err}
	}
	root, err := allocator.NewSized(enclave.RootKeyBytes)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrProvisionRootFailed, Cause: err}
	}
	defer func() {
		if destroyErr := root.Destroy(); destroyErr != nil && err == nil {
			sealedRoot, err = nil, &errs.Joined{Lead: ErrProvisionRootFailed, Cause: destroyErr}
		}
	}()
	err = root.WithBytes(func(key []byte) error {
		if _, readErr := rand.Read(key); readErr != nil {
			return readErr
		}
		blob, sealErr := box.seal(ctx, purposeRoot, key, ErrProvisionRootFailed)
		sealedRoot = blob
		return sealErr
	})
	if errors.Is(err, ErrProvisionRootFailed) {
		return nil, err
	}
	if err != nil {
		return nil, &errs.Joined{Lead: ErrProvisionRootFailed, Cause: err}
	}
	return sealedRoot, nil
}

// sealBox seals keys under one sealing key and opens the envelopes it made.
type sealBox struct {
	sealer types.Sealer
	attrs  types.KeyAttributes
}

// newSealBox validates sealer and attrs and copies attrs.
func newSealBox(sealer types.Sealer, attrs *types.KeyAttributes) (sealBox, error) {
	if sealer == nil {
		return sealBox{}, ErrNilSealer
	}
	if attrs == nil {
		return sealBox{}, ErrNilKeyAttributes
	}
	return sealBox{sealer: sealer, attrs: *copyKeyAttributes(attrs)}, nil
}

// keyAttributes returns a copy of the sealing key's attributes for one call.
// A sealer may write into the attributes it is handed (the TPM 2.0 sealer
// stages the sealed secret there), so concurrent calls never share them.
func (b sealBox) keyAttributes() *types.KeyAttributes {
	return copyKeyAttributes(&b.attrs)
}

// copyKeyAttributes copies attrs and the TPM attributes it points to, the
// part of the attributes a sealer writes into, and does the same for each
// parent up the hierarchy: a sealer reads the parent's TPM handle as the
// SRK, so a parent shared with the caller would let the caller's later
// changes move the SRK.
func copyKeyAttributes(attrs *types.KeyAttributes) *types.KeyAttributes {
	copied := *attrs
	if copied.TPMAttributes != nil {
		tpmAttrs := *copied.TPMAttributes
		copied.TPMAttributes = &tpmAttrs
	}
	if copied.Parent != nil {
		copied.Parent = copyKeyAttributes(copied.Parent)
	}
	return &copied
}

// seal seals key for p and returns the envelope. lead is the caller's
// operation error.
func (b sealBox) seal(ctx context.Context, p purpose, key []byte, lead error) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, &errs.Joined{Lead: lead, Cause: err}
	}
	sealed, err := b.sealer.Seal(ctx, key, &types.SealOptions{KeyAttributes: b.keyAttributes(), AAD: p.aad()})
	if err != nil {
		return nil, &errs.Joined{Lead: lead, Cause: err}
	}
	if sealed == nil {
		return nil, &errs.Detail{Err: lead, Detail: "sealer returned no sealed data"}
	}
	blob, err := encodeEnvelope(p, sealed, key)
	if err != nil {
		return nil, &errs.Joined{Lead: lead, Cause: err}
	}
	return blob, nil
}

// open recovers the key blob protects for p into dst. lead is the caller's
// operation error for failures that are not authentication failures.
func (b sealBox) open(ctx context.Context, p purpose, blob, dst []byte, lead error) error {
	if err := ctx.Err(); err != nil {
		return &errs.Joined{Lead: lead, Cause: err}
	}
	if len(dst) != enclave.RootKeyBytes {
		return authenticationError(ErrKeyLengthMismatch, "destination is "+strconv.Itoa(len(dst))+" bytes")
	}
	env, err := decodeEnvelope(blob, p)
	if err != nil {
		return err
	}
	plaintext, err := b.sealer.Unseal(ctx, env.sealed, &types.UnsealOptions{KeyAttributes: b.keyAttributes(), AAD: p.aad()})
	defer enclave.Wipe(plaintext)
	if err != nil {
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			return authenticationError(err, "")
		}
		return &errs.Joined{Lead: lead, Cause: err}
	}
	if len(plaintext) != len(dst) {
		return authenticationError(ErrKeyLengthMismatch, "sealed key is "+strconv.Itoa(len(plaintext))+" bytes")
	}
	if err := env.verify(plaintext); err != nil {
		if errors.Is(err, enclave.ErrSealedAuthentication) {
			return err
		}
		return &errs.Joined{Lead: lead, Cause: err}
	}
	copy(dst, plaintext)
	return nil
}
