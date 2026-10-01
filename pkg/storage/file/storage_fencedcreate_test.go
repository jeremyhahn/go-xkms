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

package file

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

func TestFileStorage_FencedCreateContract(t *testing.T) {
	storagetest.RunFencedCreateContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			fs, err := New(t.TempDir())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = fs.Close() })
			return fs
		},
		Key: "keys/contract-subject",
	})
}

// Every key is validated before the fenced create is evaluated: a traversal
// fence is refused like a traversal key.
func TestFileStorage_FencedCreateValidatesEveryKey(t *testing.T) {
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	fc, ok := fs.(storage.FencedCreator)
	if !ok {
		t.Fatalf("%T does not implement storage.FencedCreator", fs)
	}
	_, err = fc.PutIfAllAbsent(context.Background(), "keys/ok", []byte("v"), "../escape")
	assert.Error(t, err)
	exists, err := fs.Exists(context.Background(), "keys/ok")
	assert.NoError(t, err)
	assert.False(t, exists, "nothing is written past an invalid fence")
}
