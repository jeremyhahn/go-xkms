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
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrPINSourceRequired is returned by BuildWithSealedPIN when it is given no
// store to release the PIN from.
var ErrPINSourceRequired = errors.New("pkcs11strategy: a sealed PIN source is required")

// PINSource releases a secret sealed before any barrier is unsealed. A
// *preseal.Store is one.
type PINSource interface {
	Get(ctx context.Context, name string) ([]byte, error)
}

// BuildWithSealedPIN releases the token PIN sealed in pins under
// seal.SecretPKCS11PIN and builds the strategy for the token library and
// tokenLabel name, as Build does. The released PIN is wiped once the
// strategy's backend holds it.
func BuildWithSealedPIN(ctx context.Context, pins PINSource, cn, library, tokenLabel string) (seal.SealingStrategy, io.Closer, error) {
	sealedPIN, err := ReleaseSealedPIN(ctx, pins)
	if err != nil {
		return nil, nil, err
	}
	return Build(ctx, Params{CN: cn, Library: library, TokenLabel: tokenLabel, PIN: sealedPIN})
}

// ReleaseSealedPIN releases the token PIN sealed in the pre-barrier store
// and holds it in a sealed SecretValue, for a token that must open before
// the barrier (and so the credential service) exists.
func ReleaseSealedPIN(ctx context.Context, pins PINSource) (*types.SecretValue, error) {
	if pins == nil {
		return nil, ErrPINSourceRequired
	}
	pin, err := pins.Get(ctx, seal.SecretPKCS11PIN)
	if err != nil {
		return nil, &BuildError{Step: "releasing the sealed token PIN", Err: err}
	}
	sealedPIN, err := types.NewLiteralSecretValue(ctx, pin)
	clear(pin)
	if err != nil {
		return nil, &BuildError{Step: "holding the released token PIN", Err: err}
	}
	return sealedPIN, nil
}
