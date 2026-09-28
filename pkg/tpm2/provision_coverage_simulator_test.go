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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// MinimalInstallOptions
// ---------------------------------------------------------------------------

// TestMinimalInstallOptions_EnablesOnlyEKAndSSRK proves MinimalInstallOptions
// returns the documented TCG-minimum set (EK + SSRK only) used for early
// boot, and nothing else -- a regression here would silently pull
// PlatformPolicy/IAK/IDevID provisioning into a caller that asked for the
// minimal path specifically because PCR values aren't stable yet.
func TestMinimalInstallOptions_EnablesOnlyEKAndSSRK(t *testing.T) {
	opts := MinimalInstallOptions()
	require.NotNil(t, opts)
	assert.True(t, opts.EK)
	assert.True(t, opts.SSRK)
	assert.False(t, opts.PlatformPolicy)
	assert.False(t, opts.IAK)
	assert.False(t, opts.IDevID)
}

// ---------------------------------------------------------------------------
// FactoryResetWithClear
// ---------------------------------------------------------------------------

// TestFactoryResetWithClear_EmptyLockout_ClearSucceeds proves
// FactoryResetWithClear's TPM2_Clear pre-pass succeeds against a fresh
// simulator (empty Lockout auth, matching createSim's Provision(nil)) and
// still preserves the TCG-standard EK afterward.
func TestFactoryResetWithClear_EmptyLockout_ClearSucceeds(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	err := tpmImpl.FactoryResetWithClear(nil)
	require.NoError(t, err)

	_, err = tpmImpl.EKAttributes()
	require.NoError(t, err, "EK must survive FactoryResetWithClear per TCG EK-preservation guidance")
}

// TestFactoryResetWithClear_LockoutSet_FallsThroughToEvictControl proves
// that when the TPM2_Clear pre-pass fails (Lockout auth is set, so the
// empty-lockout Clear attempt is rejected), FactoryResetWithClear falls
// through to the regular EvictControl pass using the caller-supplied owner
// auth -- exactly as its doc comment promises -- rather than aborting.
func TestFactoryResetWithClear_LockoutSet_FallsThroughToEvictControl(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)
	soPIN := mustPassword([]byte("factory-reset-so-pin-0123"))
	require.NoError(t, h.TPM.Provision(soPIN))

	_, err := h.TPM.SSRKAttributes()
	require.NoError(t, err, "provisioning must leave an SSRK behind to evict")

	err = h.TPM.FactoryResetWithClear(soPIN.Bytes())
	require.NoError(t, err, "eviction must still succeed using the caller-supplied owner auth once the empty-lockout Clear pre-pass fails")

	_, err = h.TPM.SSRKAttributes()
	assert.Error(t, err, "SSRK must be evicted by the EvictControl pass reached after the Clear pre-pass fails")
}

// ---------------------------------------------------------------------------
// SetHierarchyAuth reinstall recovery
// ---------------------------------------------------------------------------

// TestSetHierarchyAuth_ReinstallRecovery_IdempotentRetrySucceeds proves the
// "reinstall recovery" branch. isTPMBadAuth deliberately matches only the
// non-DA TPM_RC_BAD_AUTH form (see TestIsTPMBadAuth_ClassifiesRealTPMResponses):
// Owner/Endorsement/Lockout hierarchy auth is DA-protected on a real TPM and
// a wrong password there comes back TPM_RC_AUTH_FAIL, which the retry gate
// intentionally does not treat as recoverable. The Platform hierarchy is the
// one TCG exempts from DA (TPM 2.0 Part 1, DA section), so a wrong Platform
// hierarchy auth is the one real case that actually reaches TPM_RC_BAD_AUTH
// and this retry path -- calling SetHierarchyAuth(nil, soPIN, &Platform) a
// second time, as a fresh install that doesn't know the TPM already has
// soPIN, must recover instead of failing.
func TestSetHierarchyAuth_ReinstallRecovery_IdempotentRetrySucceeds(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)
	soPIN := mustPassword([]byte("reinstall-recovery-pin-01"))
	platform := tpm2.TPMRHPlatform

	require.NoError(t, h.TPM.SetHierarchyAuth(nil, soPIN, &platform))
	// Second call: old=nil no longer matches the live Platform auth (soPIN),
	// so this must hit TPM_RC_BAD_AUTH, retry with soPIN as its own old
	// auth, and recover -- HierarchyChangeAuth with old==new is idempotent.
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, soPIN, &platform))
}

// TestSetHierarchyAuth_ReinstallRecovery_MismatchedRetryFails proves that
// when the retry's own assumption doesn't hold -- the live Platform auth is
// some other value the caller doesn't know -- the retry itself fails
// TPM_RC_BAD_AUTH too, and that second failure, not the first, is what
// SetHierarchyAuth returns.
func TestSetHierarchyAuth_ReinstallRecovery_MismatchedRetryFails(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)
	original := mustPassword([]byte("original-hierarchy-pin-01"))
	different := mustPassword([]byte("a-different-pin-entirely1"))
	platform := tpm2.TPMRHPlatform

	require.NoError(t, h.TPM.SetHierarchyAuth(nil, original, &platform))

	err := h.TPM.SetHierarchyAuth(nil, different, &platform)
	require.Error(t, err, "old=nil against a live non-empty Platform auth must fail, and the reinstall-recovery retry (old=new=different) must fail too since the live auth is neither")
}

// ---------------------------------------------------------------------------
// BackupEKCertificates
// ---------------------------------------------------------------------------

func TestBackupEKCertificates_NoCertStoreReturnsEarly(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	tpmImpl.config.EK.CertHandle = ekCertIndexRSA2048
	certDER := createTestCertDER(t)
	require.NoError(t, tpmImpl.ProvisionEKCert(nil, certDER))
	t.Cleanup(func() { _ = tpmImpl.deleteCertFromNVRAM(tpm2.TPMHandle(ekCertIndexRSA2048)) })

	tpmImpl.certStore = nil
	assert.NotPanics(t, func() { tpmImpl.BackupEKCertificates() })
}

func TestBackupEKCertificates_ImportSucceeds(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	tpmImpl.config.EK.CertHandle = ekCertIndexRSA2048
	certDER := createTestCertDER(t)
	require.NoError(t, tpmImpl.ProvisionEKCert(nil, certDER))
	t.Cleanup(func() { _ = tpmImpl.deleteCertFromNVRAM(tpm2.TPMHandle(ekCertIndexRSA2048)) })

	memStore := store.NewMemoryCertStore(slog.Default())
	tpmImpl.certStore = memStore

	tpmImpl.BackupEKCertificates()

	got, err := memStore.Get(&types.KeyAttributes{CN: "ek-cert-rsa-backup"})
	require.NoError(t, err, "a readable EK certificate must be imported into the cert store under its documented backup label")
	require.NotNil(t, got)
	assert.Equal(t, certDER, got.Raw)
}

func TestBackupEKCertificates_ImportFailureIsLoggedNotPanicked(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	tpmImpl.config.EK.CertHandle = ekCertIndexRSA2048
	certDER := createTestCertDER(t)
	require.NoError(t, tpmImpl.ProvisionEKCert(nil, certDER))
	t.Cleanup(func() { _ = tpmImpl.deleteCertFromNVRAM(tpm2.TPMHandle(ekCertIndexRSA2048)) })

	tpmImpl.certStore = &alwaysFailCertStore{err: errors.New("cert store: synthetic import failure")}

	assert.NotPanics(t, func() { tpmImpl.BackupEKCertificates() })
}

// alwaysFailCertStore implements store.CertificateStorer and fails every
// operation, to exercise BackupEKCertificates' best-effort warn-and-continue
// branch when the configured cert store itself is unusable.
type alwaysFailCertStore struct{ err error }

func (a *alwaysFailCertStore) Get(attrs *types.KeyAttributes) (*x509.Certificate, error) {
	return nil, a.err
}
func (a *alwaysFailCertStore) Save(attrs *types.KeyAttributes, cert *x509.Certificate) error {
	return a.err
}
func (a *alwaysFailCertStore) Delete(attrs *types.KeyAttributes) error { return a.err }
func (a *alwaysFailCertStore) ImportCertificate(attrs *types.KeyAttributes, certPEM []byte) (*x509.Certificate, error) {
	return nil, a.err
}
