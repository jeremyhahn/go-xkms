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

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// literalPIN seals pin into a SecretValue, as callers releasing a PIN do.
func literalPIN(t *testing.T, pin string) *types.SecretValue {
	t.Helper()
	sv, err := types.NewLiteralSecretValue(context.Background(), []byte(pin))
	require.NoError(t, err)
	return sv
}

func validParams(t *testing.T) Params {
	return Params{CN: "test", Library: "/usr/lib/libpkcs11.so", TokenLabel: "token", PIN: literalPIN(t, "1234")}
}

func TestBuild_RejectsIncompleteParams(t *testing.T) {
	cases := map[error]func(*Params){
		ErrLibraryRequired: func(p *Params) { p.Library = "" },
		ErrTokenRequired:   func(p *Params) { p.TokenLabel = "" },
		ErrPINRequired:     func(p *Params) { p.PIN = nil },
	}
	for want, mutate := range cases {
		p := validParams(t)
		mutate(&p)
		strategy, closer, err := Build(context.Background(), p)
		require.ErrorIs(t, err, want)
		require.Nil(t, strategy)
		require.Nil(t, closer)
	}
}

func TestBuildError_NamesTheStep(t *testing.T) {
	cause := errors.New("CKR_PIN_INCORRECT")
	err := &BuildError{Step: "opening the token", Err: cause}
	require.EqualError(t, err, "pkcs11strategy: opening the token: CKR_PIN_INCORRECT")
	require.ErrorIs(t, err, cause)
}
