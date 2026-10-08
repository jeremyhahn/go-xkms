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

//go:build pkcs11

package pkcs11strategy

import (
	"context"
	"errors"
	"io"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Build logs in to the token p names, provisions the wrapping key if the
// token does not hold it yet, and returns the PKCS#11 seal strategy with
// the closer that logs out of the token. The wrapping key lives on the
// token; its metadata needs no storage of its own.
func Build(ctx context.Context, p Params) (seal.SealingStrategy, io.Closer, error) {
	if err := p.validate(); err != nil {
		return nil, nil, err
	}
	backend, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		CN:          p.CN,
		Library:     p.Library,
		TokenLabel:  p.TokenLabel,
		PIN:         p.PIN,
		KeyStorage:  storage.NewMemory(),
		CertStorage: storage.NewMemory(),
	})
	if err != nil {
		return nil, nil, &BuildError{Step: "opening the token", Err: err}
	}

	keyAttrs := seal.SealKeyAttributes(types.StorePKCS11)
	if err := seal.EnsureSealKey(ctx, seal.StrategyPKCS11, backend, keyAttrs); err != nil {
		return nil, nil, &BuildError{Step: "provisioning the wrapping key", Err: errors.Join(err, backend.Close())}
	}
	return seal.NewPKCS11Strategy(backend, keyAttrs, nil), backend, nil
}
