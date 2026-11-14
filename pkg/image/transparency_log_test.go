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

//go:build qrdb_vlog

package image

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
)

// loggingSigner returns a Signer of f's registry that records its
// signatures in log.
func (f *signerFixture) loggingSigner(t *testing.T, key crypto.Signer, log TransparencyLog) *Signer {
	t.Helper()
	signer, err := NewSigner(&SignerConfig{
		Signer:          key,
		Certificate:     f.pki.codeSigning(t, key.Public()),
		Chain:           []*x509.Certificate{f.pki.certificate},
		Registry:        f.client,
		TransparencyLog: log,
	})
	require.NoError(t, err)
	return signer
}

func TestSigner_SignImage_AppendsImageSigned(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	logs := tlogtest.New(t, f.pki.key, f.pki.certificate)
	signer := f.loggingSigner(t, newECDSAKey(t), logs.Log)

	before := logs.Size(t)
	result, err := signer.SignImage(logs.Ctx, f.ref, nil)
	require.NoError(t, err)

	sum := sha256.Sum256(result.Envelope)
	logs.RequireOneEntry(t, before, tlog.ImageSigned{
		ImageDigest:    f.digest,
		EnvelopeDigest: "sha256:" + hex.EncodeToString(sum[:]),
		Signer:         signer.certificate.Subject.String(),
	})
	_, err = f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err, "the logged signature is pushed")
}

func TestSigner_SignImage_AppendFailureFailsSigning(t *testing.T) {
	f := newSignerFixture(t, registryConfig{referrers: true})
	logs := tlogtest.New(t, f.pki.key, f.pki.certificate)
	signer := f.loggingSigner(t, newECDSAKey(t), logs.Missing)

	result, err := signer.SignImage(logs.Ctx, f.ref, nil)
	require.ErrorIs(t, err, ErrTransparencyLogAppend)
	require.ErrorIs(t, err, tlog.ErrLogRequest)
	assert.Nil(t, result, "no signature is returned")

	_, err = f.verifier(t, VerifierConfig[purpose]{}).VerifyImage(t.Context(), f.ref)
	require.ErrorIs(t, err, ErrNoAttestation, "no signature is pushed")
}
