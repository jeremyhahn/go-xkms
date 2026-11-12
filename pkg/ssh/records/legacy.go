// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package records

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// legacyHeader is the identity every pre-DAO SSH record stored beside its
// body fields. Known-hosts records named the record by host, the others by
// name.
type legacyHeader struct {
	Scope scope.Scope `json:"scope"`
	Owner string      `json:"owner"`
	Name  string      `json:"name"`
	Host  string      `json:"host"`
}

// Import upserts a record written by the pre-DAO sealed-KV store. rel is the
// record's old key below the tenant root, which is its Kind.RecordPath, and
// data is its JSON. The old JSON holds the scope, owner and name beside the
// body fields, and T keeps the old field names, so data decodes into both.
// check validates the decoded entity before it is written.
//
// Import overwrites a record the same owner already holds, so importing a
// record twice is harmless. It returns *LegacyRecordError when data does not
// decode or fails check, *LegacyPathError when data names a record other
// than rel, *LegacyOwnerConflictError when another owner holds the record,
// and the Put error when the write fails.
func (t *Table[T]) Import(ctx context.Context, rel string, data []byte, check func(*Entity[T]) error) error {
	var h legacyHeader
	if err := json.Unmarshal(data, &h); err != nil {
		return &LegacyRecordError{Path: rel, Err: err}
	}
	name := h.Name
	if name == "" {
		name = h.Host
	}
	var body T
	e, err := t.entity(h.Scope, h.Owner, name, body)
	if err != nil {
		return &LegacyRecordError{Path: rel, Err: err}
	}
	if record := e.Path[len(t.root):]; record != rel {
		return &LegacyPathError{Path: rel, Record: record}
	}
	defer discard(e)
	if err := json.Unmarshal(data, &e.Body); err != nil {
		return &LegacyRecordError{Path: rel, Err: err}
	}
	if err := check(e); err != nil {
		return &LegacyRecordError{Path: rel, Err: err}
	}
	stored, err := t.Put(ctx, e.Scope, e.Owner, e.Name, e.Body)
	if err != nil {
		return err
	}
	if !stored {
		return &LegacyOwnerConflictError{Path: rel}
	}
	return nil
}
