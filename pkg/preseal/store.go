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

// Package preseal keeps the secrets a process needs before its barrier can
// open, such as the PKCS#11 token PIN a PKCS#11 barrier logs in with.
//
// It is not a second sealed store: a Store is the platform store
// (seal.PlatformStore, go-xkms#718) composed over a go-qrdb file engine in a
// directory beside, never inside, the barriered datastore, and every record
// is sealed by seal.PlatformPolicySealer (go-xkms#997) under the Platform
// SRK and the built-in platform TPM policy. A record is therefore released
// only by the TPM that sealed it, and only while the platform PCRs match
// the state it was sealed under; no PIN or operator is involved.
package preseal

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	sealedstorage "github.com/jeremyhahn/go-xkms/pkg/storage/sealed"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SealCN is the common name of the TPM sealed object every record is sealed
// as. It is distinct from the barrier's and the platform store's objects so
// the three never collide on one TPM.
const SealCN = "xkms-preseal"

// PKCS11PIN is the name the PKCS#11 token user PIN is sealed under, shared
// by xkmsd's node seal and xkey's barrier.
const PKCS11PIN = seal.SecretPKCS11PIN

// VaultToken is the name the Vault token a vault node seal authenticates
// with is sealed under.
const VaultToken = seal.SecretVaultToken

// TPM is the TPM a Store seals through: a sealer that can report the
// enrolled Platform SRK. pkg/tpm2's TrustedPlatformModule satisfies it.
type TPM interface {
	types.Sealer

	// PlatformSRKAttributes returns the enrolled Platform SRK, or an error
	// when it has not been enrolled.
	PlatformSRKAttributes() (*types.KeyAttributes, error)
}

// Store holds pre-barrier secrets sealed under the platform policy.
type Store struct {
	records storage.Backend
	secrets seal.PlatformStore
}

// Open opens the Store whose records live in dir, sealing through tpm.
// The caller keeps ownership of tpm; Close releases only the records.
func Open(tpm TPM, dir string, logger *slog.Logger) (*Store, error) {
	if dir == "" {
		return nil, ErrDirRequired
	}
	records, err := storage.NewFile(dir)
	if err != nil {
		return nil, &OpenError{Dir: dir, Err: err}
	}
	store, err := New(tpm, records, logger)
	if err != nil {
		return nil, errors.Join(err, records.Close())
	}
	return store, nil
}

// New builds a Store over records, sealing through tpm. It fails when tpm
// is nil or its Platform SRK is not enrolled: go-xkms never seals under any
// other parent. Close closes records.
func New(tpm TPM, records storage.Backend, logger *slog.Logger) (*Store, error) {
	if tpm == nil {
		return nil, ErrTPMRequired
	}
	if records == nil {
		return nil, ErrRecordsRequired
	}
	psrk, err := tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, &PlatformSRKError{Err: err}
	}
	sealed, err := sealedstorage.New(records, seal.NewPlatformPolicySealer(tpm, SealCN, psrk), nil)
	if err != nil {
		return nil, &OpenError{Err: err}
	}
	secrets, err := seal.NewPlatformStore(sealed, logger)
	if err != nil {
		return nil, &OpenError{Err: err}
	}
	return &Store{records: records, secrets: secrets}, nil
}

// Put seals secret under name, replacing any secret already stored there.
func (s *Store) Put(ctx context.Context, name string, secret []byte) error {
	if len(secret) == 0 {
		return &EmptySecretError{Name: name}
	}
	if err := s.secrets.Put(ctx, name, secret); err != nil {
		return &SealError{Name: name, Err: err}
	}
	return nil
}

// Get unseals the secret stored under name. A missing secret is a
// *NotFoundError; a secret the TPM refuses to release, because the platform
// PCRs or the TPM differ from the ones it was sealed under, is a
// *RefusedError.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	secret, err := s.secrets.Get(ctx, name)
	switch {
	case err == nil:
		return secret, nil
	case errors.Is(err, seal.ErrSecretNotFound):
		return nil, &NotFoundError{Name: name}
	case errors.Is(err, sealedstorage.ErrUnsealFailed):
		return nil, &RefusedError{Name: name, Err: err}
	default:
		return nil, &UnsealError{Name: name, Err: err}
	}
}

// Close closes the record storage. The TPM is the caller's to close.
func (s *Store) Close() error {
	return s.records.Close()
}
