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

package main

import (
	"crypto/x509"
	"errors"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	acmesdk "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	evidencesdk "github.com/jeremyhahn/go-xkms/sdk/go/evidence"
)

var (
	// ErrACMEDeviceAttestAnchorRead is returned when a configured
	// device-attest-01 trust anchor file cannot be read.
	ErrACMEDeviceAttestAnchorRead = errors.New("acme: cannot read a device-attest-01 trust anchor file")

	// ErrACMEDeviceAttestAnchorParse is returned when a configured
	// device-attest-01 trust anchor file holds no parseable PEM certificate.
	ErrACMEDeviceAttestAnchorParse = errors.New("acme: a device-attest-01 trust anchor file holds no parseable PEM certificate")
)

// deviceAttestAnchorError reports which configured trust anchor file could not
// be loaded, and why. Sentinel classifies it (ErrACMEDeviceAttestAnchorRead or
// ErrACMEDeviceAttestAnchorParse) for errors.Is.
type deviceAttestAnchorError struct {
	Path     string
	Sentinel error
	Err      error
}

func (e *deviceAttestAnchorError) Error() string {
	return e.Sentinel.Error() + ": " + e.Path + ": " + e.Err.Error()
}

// Unwrap exposes both the classifying sentinel and the underlying cause.
func (e *deviceAttestAnchorError) Unwrap() []error { return []error{e.Sentinel, e.Err} }

// buildDeviceAttestVerifier returns the production device-attest-01 trust
// policy for cfg: an acmesdk.ACMETrustAnchorVerifier over the TPM and DICE
// roots the operator configured. It returns nil, nil when device-attest-01 is
// not enabled.
//
// With the challenge enabled it fails closed: a configured file that cannot be
// read or holds no certificate is an error, and so is a configuration with no
// root at all (acmesdk.ACMEErrNoTrustAnchors), so the daemon refuses to start
// instead of offering a challenge that would verify nothing.
func buildDeviceAttestVerifier(cfg config.ACMEChallengesConfig) (acmesdk.ACMEDeviceAttest01Verifier, error) {
	if !cfg.DeviceAttest01 {
		return nil, nil
	}
	tpmRoots, err := loadAnchorFiles(cfg.DeviceAttest.TPMRoots)
	if err != nil {
		return nil, err
	}
	diceRoots, err := loadAnchorFiles(cfg.DeviceAttest.DICERoots)
	if err != nil {
		return nil, err
	}
	verifier, err := acmesdk.ACMENewTrustAnchorVerifier(acmesdk.ACMETrustAnchors{
		TPMRoots:  tpmRoots,
		DICERoots: diceRoots,
		DICE: acmesdk.ACMEDICEPolicy{
			RequireDeviceSignedLeaf:     cfg.DeviceAttest.DICERequireDeviceSignedLeaf,
			RequireMeasurement:          cfg.DeviceAttest.DICERequireMeasurement,
			RequireTcbInfo:              cfg.DeviceAttest.DICERequireTCBInfo,
			RequireApplicationReference: cfg.DeviceAttest.DICERequireApplicationReference,
		},
	})
	if err != nil {
		return nil, err
	}
	return verifier, nil
}

// loadAnchorFiles reads every PEM file in paths and returns all the
// certificates they hold.
func loadAnchorFiles(paths []string) ([]*x509.Certificate, error) {
	var anchors []*x509.Certificate
	for _, path := range paths {
		data, err := os.ReadFile(path) // #nosec G304 - path from trusted config
		if err != nil {
			return nil, &deviceAttestAnchorError{Path: path, Sentinel: ErrACMEDeviceAttestAnchorRead, Err: err}
		}
		leaf, rest, err := evidencesdk.ParseCertificatesPEM(data)
		if err != nil {
			return nil, &deviceAttestAnchorError{Path: path, Sentinel: ErrACMEDeviceAttestAnchorParse, Err: err}
		}
		anchors = append(anchors, leaf)
		anchors = append(anchors, rest...)
	}
	return anchors, nil
}
