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

package tpm2

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

// TestDevIDCertifyScheme_RepeatsTheTemplateScheme proves devidCertifyScheme
// reads the TPMT_SIG_SCHEME back off an IAK template rather than assembling
// one independently: for both key types this package issues IAK templates
// for, the returned scheme's algorithm and hash must equal what the
// template's own Scheme parameter names (TCG TPM 2.0 Library Part 3,
// section 12.1 requires TPM2_CertifyCreation's inScheme to repeat a
// restricted signing key's fixed scheme exactly).
func TestDevIDCertifyScheme_RepeatsTheTemplateScheme(t *testing.T) {
	t.Run("RSA RSASSA", func(t *testing.T) {
		template := rsaPublicArea(t, mustRSAKey(t), tpm2.TPMAlgRSASSA)

		scheme, err := devidCertifyScheme(template)
		require.NoError(t, err)
		require.Equal(t, tpm2.TPMAlgRSASSA, scheme.Scheme)
		details, err := scheme.Details.RSASSA()
		require.NoError(t, err)
		require.Equal(t, tpm2.TPMAlgSHA256, details.HashAlg)
	})

	t.Run("ECC ECDSA", func(t *testing.T) {
		template := eccPublicArea(t, mustECDSAKey(t), true)

		scheme, err := devidCertifyScheme(template)
		require.NoError(t, err)
		require.Equal(t, tpm2.TPMAlgECDSA, scheme.Scheme)
		details, err := scheme.Details.ECDSA()
		require.NoError(t, err)
		require.Equal(t, tpm2.TPMAlgSHA256, details.HashAlg)
	})
}

// TestDevIDCertifyScheme_RejectsEveryNonConformantTemplate table-tests
// every failure devidCertifyScheme must surface rather than paper over: a
// public area whose Parameters union does not match its declared Type (the
// two cannot disagree without corrupting the wire encoding), a scheme this
// package's TPM2_Sign path cannot issue for that key type, and a key type
// an IAK/IDevID template can never name in the first place. Each must fail
// closed instead of returning a zero-value scheme that TPM2_CertifyCreation
// would silently send as TPM_ALG_NULL.
func TestDevIDCertifyScheme_RejectsEveryNonConformantTemplate(t *testing.T) {
	eccParms := tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
		&tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
		})
	rsaParms := tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
		&tpm2.TPMSRSAParms{
			Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgRSASSA},
			KeyBits: 2048,
		})

	tests := []struct {
		name     string
		template tpm2.TPMTPublic
		wantErr  error
	}{
		{
			name: "RSA type with an ECC parameters union",
			template: tpm2.TPMTPublic{
				Type:       tpm2.TPMAlgRSA,
				Parameters: eccParms,
			},
			// RSADetail() rejects the mismatched union selector; the
			// concrete error is go-tpm's, not one of this package's
			// sentinels, so only failure is asserted here.
			wantErr: nil,
		},
		{
			name: "RSA type with an unsignable scheme",
			template: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgOAEP},
						KeyBits: 2048,
					}),
			},
			wantErr: ErrSignSchemeMismatch,
		},
		{
			name: "ECC type with an RSA parameters union",
			template: tpm2.TPMTPublic{
				Type:       tpm2.TPMAlgECC,
				Parameters: rsaParms,
			},
			wantErr: nil,
		},
		{
			name: "ECC type with a key-agreement scheme",
			template: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
						Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDH},
					}),
			},
			wantErr: ErrSignSchemeMismatch,
		},
		{
			name: "keyedHash type cannot certify",
			template: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash,
			},
			wantErr: ErrDevIDTemplateNonConformant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, err := devidCertifyScheme(tt.template)
			require.Error(t, err)
			require.Equal(t, tpm2.TPMTSigScheme{}, scheme)
			if tt.wantErr != nil {
				require.True(t, errors.Is(err, tt.wantErr), "got %v", err)
			}
		})
	}
}
