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

//go:build !pkcs11

package pkcs11strategy

import (
	"context"
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// Build fails closed: this binary was built without the pkcs11 tag. The
// parameters are still validated, so a misconfiguration is reported as such.
func Build(_ context.Context, p Params) (seal.SealingStrategy, io.Closer, error) {
	if err := p.validate(); err != nil {
		return nil, nil, err
	}
	return nil, nil, ErrNotCompiledIn
}
