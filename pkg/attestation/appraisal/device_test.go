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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// androidAppraiser is an Appraiser for tenant acme, whose android-root
// endorsement is the returned authority, under the application policies.
func androidAppraiser(t *testing.T, opts ...Option) (*Appraiser, *appraisaltest.Authority) {
	t.Helper()
	store, err := NewStore(StoreConfig{DAOs: dao.NewStoreFactory(newFaultKV())})
	require.NoError(t, err)
	app, err := NewAppraiser(store, opts...)
	require.NoError(t, err)
	root, err := appraisaltest.NewAuthority("handset-root")
	require.NoError(t, err)
	_, err = app.PutEndorsement(context.Background(), "acme", &PutEndorsementRequest{
		Name: "handset-root", Kind: EndorsementAndroidRoot, CertificatePEM: root.CertificatePEM(),
	})
	require.NoError(t, err)
	return app, root
}

func TestAppraiseAndroidKeyAttestation_ApplicationAllowList(t *testing.T) {
	ctx := context.Background()
	policies := AndroidApplicationPolicies{"acme": {
		appraisaltest.FixtureApplicationPackage: {appraisaltest.FixtureApplicationDigest},
	}}
	app, root := androidAppraiser(t, WithAndroidApplications(policies))
	appraise := func(t *testing.T, a *Appraiser, appID *android.AttestationApplicationID) (*AttestationResult, error) {
		t.Helper()
		chain, err := appraisaltest.AndroidKeyAttestationFor(root, appraisaltest.LockedVerifiedBoot(), appID)
		require.NoError(t, err)
		return a.AppraiseAndroidKeyAttestation(ctx, "acme", &AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
	}
	refused := func(t *testing.T, result *AttestationResult, err error, cause error) {
		t.Helper()
		assert.Nil(t, result)
		var refusal *EvidenceRefusedError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, AppraisalCheckAndroidKey, refusal.Check)
		assert.ErrorIs(t, err, cause)
	}

	t.Run("allow-listed application verifies", func(t *testing.T) {
		result, err := appraise(t, app, appraisaltest.FixtureApplication())
		require.NoError(t, err)
		assert.True(t, result.Verified)
	})

	t.Run("unlisted application is refused", func(t *testing.T) {
		other := appraisaltest.FixtureApplication()
		other.Packages[0].Name = "com.example.unlisted"
		result, err := appraise(t, app, other)
		refused(t, result, err, ErrApplicationNotAllowed)
		assert.ErrorIs(t, err, android.ErrApplicationRefused)
	})

	t.Run("listed package with another signing digest is refused", func(t *testing.T) {
		resigned := appraisaltest.FixtureApplication()
		resigned.SignatureDigests = [][]byte{make([]byte, 32)}
		result, err := appraise(t, app, resigned)
		refused(t, result, err, ErrApplicationNotAllowed)
	})

	t.Run("no attested application identity is refused", func(t *testing.T) {
		result, err := appraise(t, app, nil)
		refused(t, result, err, ErrNoAttestedApplication)
	})

	t.Run("tenant without an allow-list is refused", func(t *testing.T) {
		chain, err := appraisaltest.AndroidKeyAttestation(root, appraisaltest.LockedVerifiedBoot())
		require.NoError(t, err)
		_, err = app.PutEndorsement(ctx, "globex", &PutEndorsementRequest{
			Name: "handset-root", Kind: EndorsementAndroidRoot, CertificatePEM: root.CertificatePEM(),
		})
		require.NoError(t, err)
		result, err := app.AppraiseAndroidKeyAttestation(ctx, "globex", &AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
		refused(t, result, err, ErrNoApplicationAllowList)
	})

	t.Run("appraiser without an application source is refused", func(t *testing.T) {
		bare, bareRoot := androidAppraiser(t)
		chain, err := appraisaltest.AndroidKeyAttestation(bareRoot, appraisaltest.LockedVerifiedBoot())
		require.NoError(t, err)
		result, err := bare.AppraiseAndroidKeyAttestation(ctx, "acme", &AppraiseAndroidKeyAttestationRequest{ChainDER: chain})
		refused(t, result, err, ErrNoApplicationAllowList)
	})
}

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
