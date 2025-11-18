// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package shamir

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Share represents a single piece of a secret split using Shamir's Secret Sharing.
// Each share contains the data needed to reconstruct the secret when combined with
// M-1 other shares.
type Share struct {
	// Index is the share number (1 to N)
	Index int `json:"index"`

	// Threshold is the minimum number of shares required to reconstruct (M)
	Threshold int `json:"threshold"`

	// Total is the total number of shares created (N)
	Total int `json:"total"`

	// Value is the actual share data (base64 encoded for JSON serialization)
	Value string `json:"value"`

	// Metadata contains optional information about the share
	Metadata map[string]string `json:"metadata,omitempty"`
}

// MarshalJSON implements json.Marshaler for Share
func (s *Share) MarshalJSON() ([]byte, error) {
	type Alias Share
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

// UnmarshalJSON implements json.Unmarshaler for Share
func (s *Share) UnmarshalJSON(data []byte) error {
	type Alias Share
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	return nil
}

// Bytes returns the raw share value as bytes
func (s *Share) Bytes() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.Value)
}

// String returns a string representation of the share (for debugging)
func (s *Share) String() string {
	return fmt.Sprintf("Share{Index: %d, Threshold: %d/%d, Value: %s...}",
		s.Index, s.Threshold, s.Total, s.Value[:min(len(s.Value), 16)])
}

// Validate checks if the share has valid parameters
func (s *Share) Validate() error {
	if s.Index < 1 {
		return fmt.Errorf("invalid share index: %d (must be >= 1)", s.Index)
	}
	if s.Threshold < 2 {
		return fmt.Errorf("invalid threshold: %d (must be >= 2)", s.Threshold)
	}
	if s.Total < s.Threshold {
		return fmt.Errorf("invalid total: %d (must be >= threshold %d)", s.Total, s.Threshold)
	}
	if s.Index > s.Total {
		return fmt.Errorf("invalid share index: %d (must be <= total %d)", s.Index, s.Total)
	}
	if s.Value == "" {
		return fmt.Errorf("share value is empty")
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
