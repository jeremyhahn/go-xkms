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

package appraisal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
)

// android-root and ek-root anchor certificate chains, so each is stored as
// a CA certificate and never as a pinned public key.
func TestValidateEndorsement_DeviceRoots(t *testing.T) {
	ca, err := appraisaltest.NewAuthority("device root")
	require.NoError(t, err)
	pub, err := ca.PublicKeyPEM()
	require.NoError(t, err)

	for _, kind := range []EndorsementKind{EndorsementAndroidRoot, EndorsementEKRoot} {
		t.Run(string(kind), func(t *testing.T) {
			require.NoError(t, validateEndorsement(&PutEndorsementRequest{Name: "root", Kind: kind, CertificatePEM: ca.CertificatePEM()}))
			err := validateEndorsement(&PutEndorsementRequest{Name: "root", Kind: kind, PublicKeyPEM: pub})
			require.ErrorIs(t, err, ErrEndorsementInvalid)
			assert.Contains(t, err.Error(), string(kind))
		})
	}
}

func TestEvidenceRefusedError(t *testing.T) {
	cause := errors.New("chain does not anchor")
	err := error(&EvidenceRefusedError{Check: AppraisalCheckEKCertificate, Cause: cause})
	assert.ErrorIs(t, err, ErrEvidenceRefused)
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, "attestation: ek-certificate refused: chain does not anchor", err.Error())
}
