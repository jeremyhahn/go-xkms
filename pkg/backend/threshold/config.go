// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config configures the threshold backend for distributed key operations.
type Config struct {
	// KeyStorage is the backend storage for key shares
	KeyStorage storage.Backend

	// ShareStorage is optional separate storage for threshold shares
	// If not provided, KeyStorage will be used
	ShareStorage storage.Backend

	// LocalShareID is this node's share identifier (1 to N)
	// Required for signing/decryption operations
	LocalShareID int

	// DefaultThreshold is the default M value for new threshold keys
	// Must be >= 2
	DefaultThreshold int

	// DefaultTotal is the default N value for new threshold keys
	// Must be >= DefaultThreshold
	DefaultTotal int

	// DefaultAlgorithm is the default threshold algorithm to use
	DefaultAlgorithm types.ThresholdAlgorithm

	// Participants is the list of participant identifiers for distributed operations
	// Should have length equal to DefaultTotal
	Participants []string
}

// Validate validates the threshold backend configuration.
func (c *Config) Validate() error {
	if c.KeyStorage == nil {
		return fmt.Errorf("key storage is required")
	}

	// Use KeyStorage for shares if ShareStorage not specified
	if c.ShareStorage == nil {
		c.ShareStorage = c.KeyStorage
	}

	if c.DefaultThreshold < 2 {
		return fmt.Errorf("default threshold must be at least 2, got %d", c.DefaultThreshold)
	}

	if c.DefaultTotal < c.DefaultThreshold {
		return fmt.Errorf("default total (%d) must be >= default threshold (%d)",
			c.DefaultTotal, c.DefaultThreshold)
	}

	if c.DefaultThreshold > 255 {
		return fmt.Errorf("default threshold cannot exceed 255, got %d", c.DefaultThreshold)
	}

	if c.DefaultTotal > 255 {
		return fmt.Errorf("default total cannot exceed 255, got %d", c.DefaultTotal)
	}

	if len(c.Participants) > 0 && len(c.Participants) != c.DefaultTotal {
		return fmt.Errorf("participants length (%d) must match default total (%d)",
			len(c.Participants), c.DefaultTotal)
	}

	if c.LocalShareID != 0 && (c.LocalShareID < 1 || c.LocalShareID > c.DefaultTotal) {
		return fmt.Errorf("local share ID (%d) must be between 1 and total (%d)",
			c.LocalShareID, c.DefaultTotal)
	}

	if c.DefaultAlgorithm == "" {
		c.DefaultAlgorithm = types.ThresholdAlgorithmShamir
	}

	return nil
}

// DefaultConfig returns a reasonable default configuration for testing.
// This should be customized for production use.
func DefaultConfig(storage storage.Backend) *Config {
	return &Config{
		KeyStorage:       storage,
		ShareStorage:     storage,
		LocalShareID:     1,
		DefaultThreshold: 3,
		DefaultTotal:     5,
		DefaultAlgorithm: types.ThresholdAlgorithmShamir,
		Participants:     []string{"node1", "node2", "node3", "node4", "node5"},
	}
}
