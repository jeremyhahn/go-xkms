// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build !smartcardhsm

package smartcardhsm

import "errors"

// Stub types for when SmartCard-HSM support is not compiled in.

// Config holds the configuration for the SmartCard-HSM backend.
type Config struct {
	DKEKShares    int
	DKEKThreshold int
}

// NewConfig creates a new SmartCard-HSM configuration.
func NewConfig() *Config {
	return &Config{}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	return errors.New("smartcardhsm: support not compiled in")
}

// DKEKStatus represents the current DKEK initialization status.
type DKEKStatus struct {
	Initialized     bool
	TotalShares     int
	Threshold       int
	SharesImported  int
	SharesRemaining int
}

// DKEKShare represents a single DKEK share for M-of-N reconstruction.
type DKEKShare struct {
	Index int
	Data  []byte
}

// GenerateDKEKShares is a stub that returns an error.
func GenerateDKEKShares(n, m int) ([]DKEKShare, error) {
	return nil, errors.New("smartcardhsm: support not compiled in")
}

// ReconstructDKEK is a stub that returns an error.
func ReconstructDKEK(shares []DKEKShare, threshold int) ([]byte, error) {
	return nil, errors.New("smartcardhsm: support not compiled in")
}
