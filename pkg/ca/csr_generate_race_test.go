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

package ca

import (
	"context"
	"crypto"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// raceLosingKeyStore reproduces a lost get-or-generate race (go-xkms#1599):
// every caller misses the key, the first to generate wins, and each later
// generate reports existsErr, the backend's own "already exists" error.
type raceLosingKeyStore struct {
	xkms.Backend
	existsErr error

	// misses releases the callers' first Signer lookups together, so every
	// caller misses the key before any of them generates it.
	misses sync.WaitGroup

	mu        sync.Mutex
	generated bool
}

func (s *raceLosingKeyStore) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	s.mu.Lock()
	generated := s.generated
	s.mu.Unlock()
	if !generated {
		s.misses.Done()
		s.misses.Wait()
		return nil, backend.ErrKeyNotFound
	}
	return s.Backend.Signer(ctx, attrs)
}

func (s *raceLosingKeyStore) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.generated {
		return nil, s.existsErr
	}
	key, err := s.Backend.GenerateECDSA(ctx, attrs)
	if err != nil {
		return nil, err
	}
	s.generated = true
	return key, nil
}

// TestGetOrGenerateKey_LostRaceReturnsWinnersKey proves the caller that loses
// a concurrent generate gets the winner's key whichever backend reported the
// collision. The build-tagged backends add their rows in
// csr_generate_race_<backend>_test.go.
func TestGetOrGenerateKey_LostRaceReturnsWinnersKey(t *testing.T) {
	t.Parallel()
	const cn = "lost-generate-race.example.com"

	tests := []struct {
		name      string
		existsErr error
	}{
		{"software", &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: cn}},
		{"pkcs8", &errs.Detail{Err: pkcs8.ErrKeyAlreadyExists, Detail: cn}},
		{"keystore", &xkms.ErrOperationWrap{Sentinel: xkms.ErrKeyAlreadyExists, Err: xkms.ErrOperationFailed}},
		{"keystore rotated", &xkms.KeyExistsError{KeyID: cn}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertLostRaceReturnsWinnersKey(t, tt.existsErr)
		})
	}
}

// TestGetOrGenerateKey_OtherGenerateErrorFails proves only an "already
// exists" error is recovered: any other generate failure reaches the caller.
func TestGetOrGenerateKey_OtherGenerateErrorFails(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.keyStore = &failGenerateECDSAKeyStore{Backend: ca.keyStore}

	req := &CertificateRequest{TenantID: testTenant, Subject: Subject{CommonName: "generate-fails.example.com"}}
	_, err := ca.getOrGenerateKey(context.Background(), req)
	require.ErrorIs(t, err, backend.ErrFileAlreadyExists)
}

// failGenerateECDSAKeyStore fails every ECDSA generate with
// backend.ErrFileAlreadyExists, an error that is not "key already exists".
type failGenerateECDSAKeyStore struct {
	xkms.Backend
}

func (s *failGenerateECDSAKeyStore) GenerateECDSA(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrFileAlreadyExists
}

// assertLostRaceReturnsWinnersKey races two get-or-generate callers for one
// key, the loser's generate reporting existsErr, and requires both callers
// to get the winner's key.
func assertLostRaceReturnsWinnersKey(t *testing.T, existsErr error) {
	t.Helper()
	const cn = "lost-generate-race.example.com"
	ca := setupTestCA(t)
	store := &raceLosingKeyStore{Backend: ca.keyStore, existsErr: existsErr}
	store.misses.Add(2)
	ca.keyStore = store

	signers := make([]crypto.Signer, 2)
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i := range signers {
		wg.Go(func() {
			req := &CertificateRequest{TenantID: testTenant, Subject: Subject{CommonName: cn}}
			signers[i], results[i] = ca.getOrGenerateKey(context.Background(), req)
		})
	}
	wg.Wait()

	for i, err := range results {
		require.NoError(t, err, "caller %d", i)
	}
	winner, ok := signers[0].Public().(interface{ Equal(crypto.PublicKey) bool })
	require.True(t, ok, "public key %T has no Equal method", signers[0].Public())
	assert.True(t, winner.Equal(signers[1].Public()), "both callers must get the winner's key")
}
