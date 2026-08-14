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

// Verify scans every Record under (scope, owner) in store and returns
// the first one whose key fingerprint matches received. Returns
// *NotFoundError if nothing matches — the caller treats that as
// authorization denied.
//
// The returned Record names the entry that granted access, so the
// caller can log or revoke it; matching is by SHA256 fingerprint, so a
// received key differing only in options/comment still matches.
func Verify(ctx context.Context, store Store, sc scope.Scope, owner string, received ssh.PublicKey) (*Record, error) {
	if store == nil {
		return nil, &NilInputError{Field: "store"}
	}
	if received == nil {
		return nil, &NilInputError{Field: "received"}
	}
	records, err := store.List(ctx, sc, owner)
	if err != nil {
		return nil, err
	}
	want := keys.Fingerprint(received)
	for _, rec := range records {
		if rec == nil || rec.Entry == nil || rec.Entry.Key == nil {
			continue
		}
		if rec.Entry.Key.Fingerprint == want {
			return rec, nil
		}
	}
	return nil, &NotFoundError{Scope: string(sc), Owner: owner, Name: ""}
}
