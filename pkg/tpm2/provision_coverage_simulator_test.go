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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"

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
// simulator (empty Lockout auth, matching createSim's Provision(nil)).
// TPM2_Clear evicts the persistent EK with the rest of the Endorsement
// hierarchy (TCG TPM 2.0 Part 3, section 24.6), so EKAttributes reports it
// missing instead of answering from its pre-clear cache.
func TestFactoryResetWithClear_EmptyLockout_ClearSucceeds(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)

	err := tpmImpl.FactoryResetWithClear(nil)
	require.NoError(t, err)

	_, err = tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(tpmImpl.config.EK.Handle)}.Execute(tpmImpl.transport)
	require.Error(t, err, "TPM2_Clear evicts the persistent EK")

	_, err = tpmImpl.EKAttributes()
	assert.Error(t, err, "without an EK or a manufacturer certificate there is nothing to describe")
}

// TestFactoryResetWithClear_LockoutSet_FallsThroughToEvictControl proves
// that when the TPM2_Clear pre-pass fails (Lockout auth is set, so the
// empty-lockout Clear attempt is rejected), FactoryResetWithClear falls
// through to the regular EvictControl pass using the caller-supplied owner
// auth -- exactly as its doc comment promises -- rather than aborting.
func TestFactoryResetWithClear_LockoutSet_FallsThroughToEvictControl(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)
	soPIN := mustPassword(t, []byte("factory-reset-so-pin-0123"))
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
	soPIN := mustPassword(t, []byte("reinstall-recovery-pin-01"))
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
	original := mustPassword(t, []byte("original-hierarchy-pin-01"))
	different := mustPassword(t, []byte("a-different-pin-entirely1"))
	platform := tpm2.TPMRHPlatform

	require.NoError(t, h.TPM.SetHierarchyAuth(nil, original, &platform))

	err := h.TPM.SetHierarchyAuth(nil, different, &platform)
	require.Error(t, err, "old=nil against a live non-empty Platform auth must fail, and the reinstall-recovery retry (old=new=different) must fail too since the live auth is neither")
}

// TestInstall_ReleasesConfiguredHierarchyAuth pins that Install releases the
// enclave it builds from config.EK.HierarchyAuth to present the current
// hierarchy auth. The harness config carries store.DEFAULT_PASSWORD while the
// fresh simulator's hierarchies are still empty, so Install fails right at
// SetHierarchyAuth; before the fix that left the copy mlocked until exit.
func TestInstall_ReleasesConfiguredHierarchyAuth(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)
	soPIN := mustPassword(t, []byte("install-release-pin-012345"))

	inUse := lockedBytesInUse(t)
	require.Error(t, h.TPM.Install(soPIN, nil), "a configured auth the TPM does not hold must fail")
	assert.Equal(t, inUse, lockedBytesInUse(t), "Install must release the configured hierarchy auth")
}

// ---------------------------------------------------------------------------
// BackupEKCertificates
// ---------------------------------------------------------------------------

func TestBackupEKCertificates_NoCertStoreReturnsEarly(t *testing.T) {
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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

// newEKCertSim returns a simulator TPM whose EK certificate lives in NV at
// the TCG RSA-2048 index, with that index undefined again at cleanup.
func newEKCertSim(t *testing.T) *TPM2 {
	t.Helper()
	_, tpm := createSim(t, false)
	t.Cleanup(func() { _ = tpm.Close() })
	tpmImpl, ok := tpm.(*TPM2)
	require.True(t, ok)
	tpmImpl.config.EK.CertHandle = ekCertIndexRSA2048
	t.Cleanup(func() { _ = tpmImpl.deleteCertFromNVRAM(tpm2.TPMHandle(ekCertIndexRSA2048)) })
	return tpmImpl
}

func TestProvisionEKCert_StoredCertificateIsErrEKCertExists(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	first := createTestCertDER(t)
	require.NoError(t, tpmImpl.ProvisionEKCert(nil, first))

	err := tpmImpl.ProvisionEKCert(nil, createTestCertDER(t))
	require.ErrorIs(t, err, ErrEKCertExists)
	assert.ErrorIs(t, err, tpmRCNVDefined, "the TPM response code stays reachable")

	stored, err := tpmImpl.EKCertificateRSA()
	require.NoError(t, err)
	assert.Equal(t, first, stored.Raw, "a refused write leaves the stored certificate in place")
}

func TestReplaceEKCert_ReplacesOnEveryRun(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	ekBefore, err := tpmImpl.EKRSA()
	require.NoError(t, err)

	// The first run finds no index; later runs replace what is stored.
	for i := 0; i < 3; i++ {
		certDER := createTestCertDER(t)
		require.NoError(t, tpmImpl.ReplaceEKCert(nil, certDER), "run %d", i)
		stored, err := tpmImpl.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, certDER, stored.Raw, "run %d", i)
	}

	ekAfter, err := tpmImpl.EKRSA()
	require.NoError(t, err)
	assert.True(t, ekBefore.Equal(ekAfter), "only the certificate is replaced, never the EK")
}

func TestReplaceEKCert_RejectedInputKeepsStoredOne(t *testing.T) {
	tooLarge := func(t *testing.T, tpmImpl *TPM2) []byte {
		indexMax, err := nvIndexMaxSize(tpmImpl.transport)
		require.NoError(t, err)
		return make([]byte, int(indexMax)+1)
	}
	tests := []struct {
		name    string
		auth    []byte
		certDER func(t *testing.T, tpmImpl *TPM2) []byte
		wantErr error
	}{
		{
			name:    "empty certificate",
			certDER: func(*testing.T, *TPM2) []byte { return nil },
			wantErr: ErrNVCertEmpty,
		},
		{
			name:    "unparseable certificate",
			certDER: func(*testing.T, *TPM2) []byte { return []byte("this is not a DER certificate") },
			wantErr: ErrInvalidEKCertFormat,
		},
		{
			name:    "certificate larger than the NV index maximum",
			certDER: tooLarge,
			wantErr: ErrNVCertTooLarge,
		},
		{
			name:    "wrong hierarchy authorization",
			auth:    []byte("not-the-hierarchy-auth"),
			certDER: func(t *testing.T, _ *TPM2) []byte { return createTestCertDER(t) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpmImpl := newEKCertSim(t)
			first := createTestCertDER(t)
			require.NoError(t, tpmImpl.ProvisionEKCert(nil, first))

			err := tpmImpl.ReplaceEKCert(tt.auth, tt.certDER(t, tpmImpl))
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}

			stored, err := tpmImpl.EKCertificateRSA()
			require.NoError(t, err)
			assert.Equal(t, first, stored.Raw, "a rejected call never undefines the stored certificate")
		})
	}
}

func TestReplaceEKCert_RefusesAnIndexThatIsNotACertificate(t *testing.T) {
	t.Run("cert-handle outside the NV index range", func(t *testing.T) {
		tpmImpl := newEKCertSim(t)
		tpmImpl.config.EK.CertHandle = 0x81010001
		assert.ErrorIs(t, tpmImpl.ReplaceEKCert(nil, createTestCertDER(t)), ErrEKCertIndexInvalid)
		assert.ErrorIs(t, tpmImpl.ProvisionEKCert(nil, createTestCertDER(t)), ErrEKCertIndexInvalid)
	})

	t.Run("cert-handle naming a counter index", func(t *testing.T) {
		tpmImpl := newEKCertSim(t)
		counterIndex := tpm2.TPMHandle(0x01C10100)
		_, err := tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
				NVIndex: counterIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					NoDA:       true,
					NT:         tpm2.TPMNTCounter,
				},
				DataSize: 8,
			}),
		}.Execute(tpmImpl.transport)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, tpmImpl.deleteCertFromNVRAM(counterIndex)) })

		tpmImpl.config.EK.CertHandle = uint32(counterIndex)
		assert.ErrorIs(t, tpmImpl.ReplaceEKCert(nil, createTestCertDER(t)), ErrEKCertIndexInvalid)

		_, err = tpm2.NVReadPublic{NVIndex: counterIndex}.Execute(tpmImpl.transport)
		assert.NoError(t, err, "the counter index is never undefined")
	})
}

func TestReplaceEKCert_WritesOnlyTheConfiguredIndex(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	rsaCert := createTestCertDER(t)
	require.NoError(t, tpmImpl.ProvisionEKCert(nil, rsaCert))

	tpmImpl.config.EK.CertHandle = ekCertIndexECCP256
	t.Cleanup(func() { assert.NoError(t, tpmImpl.deleteCertFromNVRAM(tpm2.TPMHandle(ekCertIndexECCP256))) })

	// The first run defines the EC index; the second replaces it.
	for i := 0; i < 2; i++ {
		ecCert := createTestCertDER(t)
		require.NoError(t, tpmImpl.ReplaceEKCert(nil, ecCert), "run %d", i)

		stored, err := tpmImpl.EKCertificateEC()
		require.NoError(t, err)
		assert.Equal(t, ecCert, stored.Raw, "run %d", i)
	}
	assert.ErrorIs(t, tpmImpl.ProvisionEKCert(nil, createTestCertDER(t)), ErrEKCertExists)

	stored, err := tpmImpl.EKCertificateRSA()
	require.NoError(t, err)
	assert.Equal(t, rsaCert, stored.Raw, "the RSA certificate survives byte for byte")
}

func TestReplaceEKCert_CertificateLargerThanNVBufferMax(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	bufMax := int(nvWriteChunkSize(tpmImpl.transport))
	indexMax, err := nvIndexMaxSize(tpmImpl.transport)
	require.NoError(t, err)
	require.Greater(t, int(indexMax), bufMax, "the simulator must allow an index larger than one NV write")

	require.NoError(t, tpmImpl.ProvisionEKCert(nil, createTestCertDER(t)))

	large := createPaddedCertDER(t, (bufMax+int(indexMax))/2)
	require.Greater(t, len(large), bufMax)
	require.LessOrEqual(t, len(large), int(indexMax))

	require.NoError(t, tpmImpl.ReplaceEKCert(nil, large))
	stored, err := tpmImpl.EKCertificateRSA()
	require.NoError(t, err)
	assert.Equal(t, large, stored.Raw)
}

// setOwnerAuth changes the owner hierarchy's empty authorization to auth.
func setOwnerAuth(t *testing.T, tpmImpl *TPM2, auth []byte) {
	t.Helper()
	_, err := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NewAuth:    tpm2.TPM2BAuth{Buffer: auth},
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)
}

// largeEKCertDER returns a certificate that takes more than one NV write.
func largeEKCertDER(t *testing.T, tpmImpl *TPM2) []byte {
	t.Helper()
	bufMax := int(nvWriteChunkSize(tpmImpl.transport))
	indexMax, err := nvIndexMaxSize(tpmImpl.transport)
	require.NoError(t, err)
	large := createPaddedCertDER(t, (bufMax+int(indexMax))/2)
	require.Greater(t, len(large), bufMax)
	return large
}

func TestReplaceEKCert_MultiChunkCertificateUnderOwnerAuth(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	ownerAuth := []byte("owner-hierarchy-auth")
	setOwnerAuth(t, tpmImpl, ownerAuth)
	require.NoError(t, tpmImpl.ProvisionEKCert(ownerAuth, createTestCertDER(t)))

	// Every chunk after the first authorizes over the index's written Name.
	for i := 0; i < 2; i++ {
		large := largeEKCertDER(t, tpmImpl)
		require.NoError(t, tpmImpl.ReplaceEKCert(ownerAuth, large), "run %d", i)

		stored, err := tpmImpl.EKCertificateRSA()
		require.NoError(t, err)
		assert.Equal(t, large, stored.Raw, "run %d", i)
	}
}

func TestReplaceEKCert_WithoutPersistentEK(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	require.NoError(t, tpmImpl.ProvisionEKCert(nil, createTestCertDER(t)))

	ekHandle := tpm2.TPMHandle(tpmImpl.config.EK.Handle)
	readPub, err := tpm2.ReadPublic{ObjectHandle: ekHandle}.Execute(tpmImpl.transport)
	require.NoError(t, err)
	require.NoError(t, tpmImpl.evictControl(tpm2.TPMRHOwner, nil,
		tpm2.NamedHandle{Handle: ekHandle, Name: readPub.Name}, ekHandle))
	tpmImpl.ekAttrs = nil

	// Without a persistent EK the EK attributes come from the config, whose
	// endorsement hierarchy cannot undefine or define an NV index.
	ekAttrs, err := tpmImpl.EKAttributes()
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMRHEndorsement, ekAttrs.TPMAttributes.Hierarchy)

	certDER := createTestCertDER(t)
	require.NoError(t, tpmImpl.ReplaceEKCert(nil, certDER))
	stored, err := tpmImpl.EKCertificateRSA()
	require.NoError(t, err)
	assert.Equal(t, certDER, stored.Raw)
}

func TestReplaceEKCert_RefusesAPlatformCreatedIndex(t *testing.T) {
	tpmImpl := newEKCertSim(t)
	nvIndex := tpm2.TPMHandle(ekCertIndexRSA2048)
	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHPlatform, Auth: tpm2.PasswordAuth(nil)},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: nvIndex,
			NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{
				PPWrite:        true,
				PPRead:         true,
				OwnerRead:      true,
				AuthRead:       true,
				NoDA:           true,
				PlatformCreate: true,
				NT:             tpm2.TPMNTOrdinary,
			},
			DataSize: 1024,
		}),
	}.Execute(tpmImpl.transport)
	require.NoError(t, err)

	err = tpmImpl.ReplaceEKCert(nil, createTestCertDER(t))
	require.ErrorIs(t, err, ErrEKCertPlatformIndex)

	_, err = tpm2.NVReadPublic{NVIndex: nvIndex}.Execute(tpmImpl.transport)
	assert.NoError(t, err, "the platform index is never undefined")
}

// createPaddedCertDER returns a self-signed certificate of about size bytes,
// padded with a private, non-critical extension.
func createPaddedCertDER(t *testing.T, size int) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	build := func(padding int) []byte {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Padded EK Certificate"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1},
				Value: make([]byte, padding),
			}},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		return certDER
	}
	return build(size - len(build(0)))
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
