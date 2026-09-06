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

//go:build ble

package cmd

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrollmentCertProfileIsRegistered pins enrollmentCertProfile to a name
// the default profile registry -- the same registry the CA constructs when no
// override is supplied -- actually resolves. The command previously requested
// "idevid", which no registry entry matched, so every enrolment failed at
// SignCSR with ErrProfileNotFound (#241). Nothing before this test checked
// that a requested profile exists until runtime.
func TestEnrollmentCertProfileIsRegistered(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()

	profile, err := registry.Get(enrollmentCertProfile)
	require.NoError(t, err,
		"enrollmentCertProfile %q must resolve in the default profile registry", enrollmentCertProfile)
	require.NotNil(t, profile)
	assert.Equal(t, enrollmentCertProfile, profile.Name())
}

// TestEnrollmentCertProfileSemantics asserts the resolved profile carries what
// the phone's LDevID needs: a signing key usage and the ClientAuth EKU, since
// the credential authenticates the phone as a client of the enterprise CA. The
// device identity travels in the CSR subject and the re-attestation cadence in
// the request's ValidityDays, so usages are all the profile must supply.
func TestEnrollmentCertProfileSemantics(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()

	profile, err := registry.Get(enrollmentCertProfile)
	require.NoError(t, err)

	assert.NotZero(t, profile.KeyUsage()&x509.KeyUsageDigitalSignature,
		"the phone's identity key signs, so the profile must grant DigitalSignature")
	assert.Contains(t, profile.ExtKeyUsage(), x509.ExtKeyUsageClientAuth,
		"the credential authenticates the phone as a client, so the profile must grant ClientAuth")

	template := &x509.Certificate{}
	require.NoError(t, profile.Apply(template, &ca.CertificateRequest{}))
	assert.False(t, template.IsCA, "a device credential must never be a CA certificate")
}

// TestEnrollmentCertProfileFormerNameFailsClosed documents the defect this
// package shipped with: "idevid" is not a registered profile, and the registry
// refuses it rather than falling back to a default. If a profile by that name
// is ever registered, this test failing is the prompt to revisit whether
// enrollmentCertProfile should point at it.
func TestEnrollmentCertProfileFormerNameFailsClosed(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()

	profile, err := registry.Get("idevid")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ca.ErrProfileNotFound))
	assert.Nil(t, profile)
}
