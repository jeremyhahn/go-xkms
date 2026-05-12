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

package authorized

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Verify scans every Entry under (scope, owner) in store and returns
// the first one whose key fingerprint matches received. Returns
// *NotFoundError if no Entry matches — the caller treats that as
// authorization denied.
//
// Matching is by SHA256 fingerprint; a caller that passes a received
// key differing only in options/comment will still match.
func Verify(ctx context.Context, store Store, sc scope.Scope, owner string, received ssh.PublicKey) (*Entry, error) {
	if store == nil {
		return nil, &NilInputError{Field: "store"}
	}
	if received == nil {
		return nil, &NilInputError{Field: "received"}
	}
	entries, err := store.List(ctx, sc, owner)
	if err != nil {
		return nil, err
	}
	want := keys.Fingerprint(received)
	for _, entry := range entries {
		if entry == nil || entry.Key == nil {
			continue
		}
		if entry.Key.Fingerprint == want {
			return entry, nil
		}
	}
	return nil, &NotFoundError{Scope: string(sc), Owner: owner, Name: ""}
}
