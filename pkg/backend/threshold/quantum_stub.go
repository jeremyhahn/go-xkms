//go:build !with_quantum
// +build !with_quantum

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// generateQuantumKey is a stub when quantum support is not enabled.
func (b *ThresholdBackend) generateQuantumKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("quantum support not enabled: rebuild with WITH_QUANTUM=1")
}

// marshalQuantumKey is a stub when quantum support is not enabled.
func marshalQuantumKey(privateKey crypto.PrivateKey) ([]byte, error) {
	return nil, fmt.Errorf("quantum support not enabled: rebuild with WITH_QUANTUM=1")
}

// unmarshalQuantumKey is a stub when quantum support is not enabled.
func unmarshalQuantumKey(keyBytes []byte, algorithm string) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("quantum support not enabled: rebuild with WITH_QUANTUM=1")
}

// supportsQuantum returns false when quantum support is not compiled in.
func supportsQuantum() bool {
	return false
}
