// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"crypto"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSignerOpts_HashFunc(t *testing.T) {
	t.Run("with key attributes", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				Hash: crypto.SHA256,
			},
		}

		result := opts.HashFunc()
		assert.Equal(t, crypto.SHA256, result)
	})

	t.Run("without key attributes", func(t *testing.T) {
		opts := &SignerOpts{}

		result := opts.HashFunc()
		assert.Equal(t, crypto.Hash(0), result)
	})
}
