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

//go:build !linux

package truststore

import (
	"crypto/x509"
	"errors"
)

// ErrUnsupportedOS indicates that OS trust store management is not
// supported on the current platform.
var ErrUnsupportedOS = errors.New("truststore: OS trust store not supported on this platform")

// DistroConfig holds exported distribution-specific certificate paths and commands.
type DistroConfig struct {
	CertDir    string
	CertExt    string
	UpdateCmd  string
	UpdateArgs []string
}

// GetDistroConfig returns ErrUnsupportedOS on non-Linux platforms.
func GetDistroConfig() (*DistroConfig, error) {
	return nil, ErrUnsupportedOS
}

// OSCertStore manages certificates in the operating system's trust store.
type OSCertStore interface {
	// Install installs a certificate into the OS trust store.
	// The label is used for the filename. Requires root/sudo privileges.
	Install(cert *x509.Certificate, label string) error

	// Remove removes a certificate from the OS trust store by label.
	Remove(label string) error

	// IsInstalled checks if a certificate with the given label is installed.
	IsInstalled(label string) (bool, error)

	// RefreshSystemStore runs the OS-specific command to rebuild the trust store.
	RefreshSystemStore() error
}

// StubCertStore is a no-op implementation of OSCertStore for platforms
// that do not support OS trust store management.
type StubCertStore struct{}

// NewOSCertStore returns ErrUnsupportedOS on non-Linux platforms.
func NewOSCertStore() (OSCertStore, error) {
	return nil, ErrUnsupportedOS
}

// Install returns ErrUnsupportedOS.
func (s *StubCertStore) Install(_ *x509.Certificate, _ string) error {
	return ErrUnsupportedOS
}

// Remove returns ErrUnsupportedOS.
func (s *StubCertStore) Remove(_ string) error {
	return ErrUnsupportedOS
}

// IsInstalled returns ErrUnsupportedOS.
func (s *StubCertStore) IsInstalled(_ string) (bool, error) {
	return false, ErrUnsupportedOS
}

// RefreshSystemStore returns ErrUnsupportedOS.
func (s *StubCertStore) RefreshSystemStore() error {
	return ErrUnsupportedOS
}
