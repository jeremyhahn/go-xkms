// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package pkcs11

import (
	"context"
	"errors"
	"testing"
)

// TestEmbeddedTransport_EveryServiceOperation_NilRequest covers the guard
// callService puts in front of every delegated operation: a nil request is
// refused with ErrNilRequest before the xkms service is looked up, so the
// refusal does not depend on the service being initialized.
func TestEmbeddedTransport_EveryServiceOperation_NilRequest(t *testing.T) {
	var tr EmbeddedTransport
	ctx := context.Background()

	ops := map[string]func() error{
		"GenerateKey":         func() error { _, err := tr.GenerateKey(ctx, nil); return err },
		"Sign":                func() error { _, err := tr.Sign(ctx, nil); return err },
		"Verify":              func() error { _, err := tr.Verify(ctx, nil); return err },
		"Encrypt":             func() error { _, err := tr.Encrypt(ctx, nil); return err },
		"EncryptAsym":         func() error { _, err := tr.EncryptAsym(ctx, nil); return err },
		"Decrypt":             func() error { _, err := tr.Decrypt(ctx, nil); return err },
		"DeriveKey":           func() error { _, err := tr.DeriveKey(ctx, nil); return err },
		"DeriveKeyECDH":       func() error { _, err := tr.DeriveKeyECDH(ctx, nil); return err },
		"WrapKeyByID":         func() error { _, err := tr.WrapKeyByID(ctx, nil); return err },
		"UnwrapKeyByID":       func() error { _, err := tr.UnwrapKeyByID(ctx, nil); return err },
		"ExportKeyMaterial":   func() error { _, err := tr.ExportKeyMaterial(ctx, nil); return err },
		"GetImportParameters": func() error { _, err := tr.GetImportParameters(ctx, nil); return err },
		"ImportKey":           func() error { _, err := tr.ImportKey(ctx, nil); return err },
	}
	for name, op := range ops {
		if err := op(); !errors.Is(err, ErrNilRequest) {
			t.Errorf("%s(nil) = %v, want ErrNilRequest", name, err)
		}
	}
}
