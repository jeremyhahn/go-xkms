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

package seal

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

var sealAuthAAD = []byte("tenant=acme,purpose=node-keystore")

func cloneEnvelope(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Nonce = bytes.Clone(sealed.Nonce)
	c.Metadata = make(map[string][]byte, len(sealed.Metadata))
	for k, v := range sealed.Metadata {
		c.Metadata[k] = bytes.Clone(v)
	}
	return &c
}

func newTestSecretSealer(t *testing.T, secret string) *SecretSealer {
	t.Helper()
	s, err := NewSecretSealer([]byte(secret))
	require.NoError(t, err)
	return s
}

// secretSealerTamperCases are the ways sealed data can be wrong, each paired
// with the unseal options that present it.
func secretSealerTamperCases() []struct {
	name   string
	mutate func(s *types.SealedData) *types.UnsealOptions
	native bool
} {
	return []struct {
		name   string
		mutate func(s *types.SealedData) *types.UnsealOptions
		native bool
	}{
		{"bit flipped", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[0] ^= 0x01
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, true},
		{"tag bit flipped", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[len(s.Ciphertext)-1] ^= 0x80
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, true},
		{"truncated", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, true},
		{"extended", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, true},
		{"AAD mismatch", func(s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{AAD: []byte("tenant=evil")}
		}, true},
		{"AAD omitted", func(s *types.SealedData) *types.UnsealOptions {
			return nil
		}, true},
		{"wrong backend", func(s *types.SealedData) *types.UnsealOptions {
			s.Backend = types.BackendTypeTPM2
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, false},
		{"malformed: nonce missing", func(s *types.SealedData) *types.UnsealOptions {
			s.Nonce = nil
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, false},
		{"malformed: ciphertext missing", func(s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = nil
			return &types.UnsealOptions{AAD: sealAuthAAD}
		}, true},
	}
}

// TestSecretSealer_SealedDataAuthentication proves Unseal and UnsealInto
// report every way the sealed data can be wrong -- including a value sealed
// under a different secret -- as types.ErrSealedDataAuthentication.
func TestSecretSealer_SealedDataAuthentication(t *testing.T) {
	s := newTestSecretSealer(t, "node-keystore-secret")
	sealed, err := s.Seal(context.Background(), []byte("node key material"), &types.SealOptions{AAD: sealAuthAAD})
	require.NoError(t, err)

	for _, tc := range secretSealerTamperCases() {
		t.Run(tc.name, func(t *testing.T) {
			mutated := cloneEnvelope(sealed)
			opts := tc.mutate(mutated)

			out, err := s.Unseal(context.Background(), mutated, opts)
			require.Nil(t, out)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)

			buf := make([]byte, 0, 64)
			out, err = s.UnsealInto(context.Background(), buf, mutated, opts)
			require.Nil(t, out)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		})
	}

	t.Run("foreign secret", func(t *testing.T) {
		other := newTestSecretSealer(t, "another-node-secret")
		out, err := other.Unseal(context.Background(), cloneEnvelope(sealed), &types.UnsealOptions{AAD: sealAuthAAD})
		require.Nil(t, out)
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("matching AAD unseals into caller memory", func(t *testing.T) {
		n, err := s.PlaintextLen(sealed)
		require.NoError(t, err)
		buf := make([]byte, 0, n)
		out, err := s.UnsealInto(context.Background(), buf, sealed, &types.UnsealOptions{AAD: sealAuthAAD})
		require.NoError(t, err)
		require.Equal(t, []byte("node key material"), out)
		require.Same(t, &buf[:1][0], &out[0], "the plaintext must land in the caller's buffer")
	})
}

// TestSecretSealer_SealWithoutAADUnchanged proves a value sealed without AAD
// still unseals with nil options -- the shape every earlier build produced.
func TestSecretSealer_SealWithoutAADUnchanged(t *testing.T) {
	s := newTestSecretSealer(t, "node-keystore-secret")
	sealed, err := s.Seal(context.Background(), []byte("legacy"), nil)
	require.NoError(t, err)
	got, err := s.Unseal(context.Background(), sealed, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("legacy"), got)

	_, err = s.Unseal(context.Background(), sealed, &types.UnsealOptions{AAD: sealAuthAAD})
	require.ErrorIs(t, err, types.ErrSealedDataAuthentication, "AAD the value was not sealed under must not authenticate")
}

// TestSecretSealer_PlaintextLenMalformed proves PlaintextLen classifies a
// malformed envelope as sealed-data authentication.
func TestSecretSealer_PlaintextLenMalformed(t *testing.T) {
	s := newTestSecretSealer(t, "node-keystore-secret")
	cases := map[string]*types.SealedData{
		"wrong backend":              {Backend: types.BackendTypePKCS11, Nonce: make([]byte, 12), Ciphertext: make([]byte, 32)},
		"nonce short":                {Backend: types.BackendTypeSoftware, Nonce: make([]byte, 4), Ciphertext: make([]byte, 32)},
		"shorter than AEAD overhead": {Backend: types.BackendTypeSoftware, Nonce: make([]byte, 12), Ciphertext: make([]byte, 3)},
	}
	for name, sealed := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.PlaintextLen(sealed)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		})
	}
}

// TestSecretSealer_EnvironmentFailuresAreNotAuthentication proves a cancelled
// context and a sealer without a usable key are not sealed-data
// authentication, even for sealed data that would fail it.
func TestSecretSealer_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	s := newTestSecretSealer(t, "node-keystore-secret")
	sealed, err := s.Seal(context.Background(), []byte("x"), nil)
	require.NoError(t, err)
	tampered := cloneEnvelope(sealed)
	tampered.Backend = types.BackendTypeVault

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Unseal(ctx, tampered, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)

	_, err = s.UnsealInto(ctx, make([]byte, 0, 8), tampered, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)

	var unkeyed SecretSealer
	_, err = unkeyed.Unseal(context.Background(), tampered, nil)
	require.ErrorIs(t, err, ErrSecretSealerEmptySecret)
	require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)

	_, err = s.Unseal(context.Background(), nil, nil)
	require.ErrorIs(t, err, ErrSecretSealerNilSealedData)
	require.NotErrorIs(t, err, types.ErrSealedDataAuthentication, "a nil envelope is a caller bug, not sealed data")
}

// TestPlatformSealer_SealedDataAuthentication proves the platform sealer
// reports sealed data it did not produce -- no strategy tag, or a tag naming
// a strategy it does not hold -- as sealed-data authentication, keeps the
// existing sentinels reachable, and passes its delegate's classification
// through unchanged in both directions.
func TestPlatformSealer_SealedDataAuthentication(t *testing.T) {
	newSealer := func(t *testing.T, delegate types.Sealer) *PlatformSealer {
		t.Helper()
		ps, err := NewPlatformSealer(testLogger(), SealerConfig{PreferenceOrder: []StrategyID{StrategyPassphrase}},
			map[StrategyID]types.Sealer{StrategyPassphrase: delegate})
		require.NoError(t, err)
		return ps
	}
	ps := newSealer(t, newTestSecretSealer(t, "platform-secret"))
	sealed, err := ps.Seal(context.Background(), []byte("platform value"), &types.SealOptions{AAD: sealAuthAAD})
	require.NoError(t, err)

	t.Run("no strategy tag", func(t *testing.T) {
		mutated := cloneEnvelope(sealed)
		delete(mutated.Metadata, strategyMetadataKey)
		_, err := ps.Unseal(context.Background(), mutated, &types.UnsealOptions{AAD: sealAuthAAD})
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		require.ErrorIs(t, err, ErrStrategyMismatch)
	})

	t.Run("strategy not held", func(t *testing.T) {
		mutated := cloneEnvelope(sealed)
		mutated.Metadata[strategyMetadataKey] = []byte(StrategyTPM2)
		_, err := ps.Unseal(context.Background(), mutated, &types.UnsealOptions{AAD: sealAuthAAD})
		require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		require.ErrorIs(t, err, ErrStrategyNotFound)
	})

	for _, tc := range secretSealerTamperCases() {
		t.Run("delegate: "+tc.name, func(t *testing.T) {
			mutated := cloneEnvelope(sealed)
			opts := tc.mutate(mutated)
			_, err := ps.Unseal(context.Background(), mutated, opts)
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
		})
	}

	t.Run("delegate environment failure passes through", func(t *testing.T) {
		outage := errors.New("hsm: device removed")
		failing := newSealer(t, &mockSealer{canSeal: true, unsealErr: outage})
		mutated := cloneEnvelope(sealed)
		_, err := failing.Unseal(context.Background(), mutated, nil)
		require.ErrorIs(t, err, outage)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("cancelled context with an untagged envelope", func(t *testing.T) {
		mutated := cloneEnvelope(sealed)
		delete(mutated.Metadata, strategyMetadataKey)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := ps.Unseal(ctx, mutated, nil)
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("untouched value unseals", func(t *testing.T) {
		got, err := ps.Unseal(context.Background(), sealed, &types.UnsealOptions{AAD: sealAuthAAD})
		require.NoError(t, err)
		require.Equal(t, []byte("platform value"), got)
	})
}
