//go:build !with_quantum

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuantumStub_GenerateQuantumKey(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)
	backend, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	attrs := &types.KeyAttributes{
		CN: "test-quantum",
		QuantumAttributes: &types.QuantumAttributes{
			Algorithm: types.QuantumAlgorithmMLDSA44,
		},
	}

	_, err = backend.generateQuantumKey(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantum support not enabled")
}

func TestQuantumStub_MarshalQuantumKey(t *testing.T) {
	_, err := marshalQuantumKey(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantum support not enabled")
}

func TestQuantumStub_UnmarshalQuantumKey(t *testing.T) {
	_, err := unmarshalQuantumKey([]byte("test"), "ML-DSA-44")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantum support not enabled")
}

func TestQuantumStub_SupportsQuantum(t *testing.T) {
	assert.False(t, supportsQuantum())
}
