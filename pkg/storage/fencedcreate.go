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

package storage

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// As for CompareAndDeleter, qrdb.Backend's claim is asserted on this side of
// the pkg/storage -> pkg/storage/qrdb import edge.
var _ FencedCreator = (*qrdb.Backend)(nil)

// FencedCreator is an OPTIONAL capability a Backend may implement: creating a
// key only while it AND a set of other keys -- its fences -- are all absent,
// decided together with the write as one atomic step. It has the method set of
// go-qrdb's kvstore.FencedCreator, which go-qrdb's tenant service asks of its
// metadata store: a tenant id is retired by a tombstone written beside its
// metadata record, so a create has to see the tombstone and write the record
// in one step, or a create racing a delete commits a live record for an id
// retired forever (go-qrdb#484).
//
// As with CompareAndDeleter there is no safe degradation: checking the fences
// and then writing leaves open exactly the window the operation exists to
// close. A backend that cannot evaluate every absence where its writes
// serialize does not implement it, and a wrapper over one reports
// ErrFencedCreateUnsupported.
//
// Backends that implement it: engineBackend (OpenEngine's file, pebble and
// memory engines, and NewMemory), which decides under the same lock as its
// other guarded verbs; qrdb.Backend, as one consensus transaction comparing
// every key's version with zero, the precondition its PutIfAbsent already
// uses -- so, like PutIfAbsent, the embedded NewFile and NewPebble, whose
// transport carries no transaction service, report it unavailable rather
// than perform it; and the wrappers PrefixBackend,
// file.FileStorage, luks.Backend and sealed.Backend, which forward. All of them
// are held to the shared suite in pkg/storage/storagetest.
type FencedCreator interface {
	// PutIfAllAbsent stores value under key only when key and every key in
	// fences are absent. It reports created=true when this call wrote the
	// key, and created=false with a nil error when any of them was present --
	// in which case the store is unchanged. A non-nil error means the outcome
	// is unknown and the caller must not assume either way.
	PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (created bool, err error)
}
