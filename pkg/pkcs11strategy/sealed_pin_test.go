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

package pkcs11strategy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// pinSource releases the secrets it holds, or err.
type pinSource struct {
	secrets  map[string][]byte
	err      error
	released []byte
}

func (s *pinSource) Get(_ context.Context, name string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.released = s.secrets[name]
	return s.released, nil
}

func TestBuildWithSealedPIN_RequiresASource(t *testing.T) {
	_, _, err := BuildWithSealedPIN(context.Background(), nil, "test", "/usr/lib/libpkcs11.so", "token")
	require.ErrorIs(t, err, ErrPINSourceRequired)
}

// TestBuildWithSealedPIN_ReportsARefusedRelease proves a PIN the source
// cannot release fails the build with the cause intact, so a caller still
// sees a policy refusal for what it is.
func TestBuildWithSealedPIN_ReportsARefusedRelease(t *testing.T) {
	cause := errors.New("policy refused")
	_, _, err := BuildWithSealedPIN(context.Background(), &pinSource{err: cause}, "test", "/usr/lib/libpkcs11.so", "token")
	var buildErr *BuildError
	require.ErrorAs(t, err, &buildErr)
	require.ErrorIs(t, err, cause)
}

// TestBuildWithSealedPIN_WipesTheReleasedPIN proves the PIN is read under
// its well-known name, handed on to Build and wiped from the released copy.
func TestBuildWithSealedPIN_WipesTheReleasedPIN(t *testing.T) {
	source := &pinSource{secrets: map[string][]byte{seal.SecretPKCS11PIN: []byte("1234")}}
	_, _, err := BuildWithSealedPIN(context.Background(), source, "test", "", "token")
	require.ErrorIs(t, err, ErrLibraryRequired)
	require.Equal(t, []byte{0, 0, 0, 0}, source.released)
}
