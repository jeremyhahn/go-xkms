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

package known_hosts

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Verify looks up a pin for (sc, owner, host) and compares its
// fingerprint against received. Returns:
//
//   - *NotFoundError when no pin exists — the caller decides whether to
//     treat that as reject-by-default (recommended) or prompt for TOFU.
//   - *MismatchError when the pin exists but the received fingerprint
//     differs (MITM indicator).
//   - nil on a match.
//
// received must be a non-nil ssh.PublicKey. Fingerprinting is delegated
// to keys.Fingerprint so the format matches whatever is persisted in
// the pin store.
func Verify(ctx context.Context, store Store, sc scope.Scope, owner, host string, received ssh.PublicKey) error {
	if store == nil {
		return &NilInputError{Field: "store"}
	}
	if received == nil {
		return &NilInputError{Field: "received"}
	}
	pin, err := store.Get(ctx, sc, owner, host)
	if err != nil {
		return err
	}
	got := keys.Fingerprint(received)
	if got != pin.Fingerprint {
		return &MismatchError{
			Host:     host,
			Expected: pin.Fingerprint,
			Received: got,
		}
	}
	return nil
}
