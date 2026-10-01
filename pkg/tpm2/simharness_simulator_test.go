//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// simHarness bundles a provisioned TPM2 backed by an in-process TPM simulator
// together with the per-test storage it was built on. Every field is owned by
// a single test; nothing is shared between tests and everything is released by
// the t.Cleanup registered in newSimHarness, so test order never matters.
type simHarness struct {
	TPM     *TPM2
	Backend store.KeyBackend
	Logger  *slog.Logger
}

// newSimHarness opens a fresh TPM simulator, provisions it (EK, SSRK, Platform
// SRK, IAK) and returns the resulting TPM2 together with a key backend rooted
// in the test's own temporary directory.
//
// The simulator is an in-process software TPM from go-tpm-tools; no host TPM
// character device is opened at any point. Passing an explicit Transport to
// NewTPM2 short-circuits every device-open branch in NewTPM2, so Config.Device
// is deliberately left empty.
//
// mutate, when non-nil, is applied to the Config immediately before NewTPM2 so
// individual tests can vary session encryption, PCR selection, key algorithms
// and so on without duplicating the whole configuration.
func newSimHarness(t *testing.T, mutate func(*Config)) *simHarness {
	t.Helper()
	return newSimHarnessWithHTTPClient(t, mutate, nil)
}

// newSimHarnessWithHTTPClient is newSimHarness with an additional hook for
// the HTTP client used by the manufacturer EK certificate service request
// (see Params.HTTPClient). httpClient is nil in every ordinary caller, which
// leaves EKCertificate's outbound download on the default client; tests of
// that download path pass an httptest server's client, or one that fails the
// test if it is ever invoked.
func newSimHarnessWithHTTPClient(t *testing.T, mutate func(*Config), httpClient *http.Client) *simHarness {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sim, err := OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	// Registered before anything below can fail: go-tpm-tools allows one
	// simulator per process and hands the next caller a lock that only
	// Close releases, so a harness that failed in Provision without this
	// left every later test in the package blocked in simulator.Get until
	// the -timeout fired, reporting a hang instead of the failure (#467).
	t.Cleanup(func() { _ = sim.Close() })

	storageFactory, err := store.NewStorageFactory(logger, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageFactory.Close() })

	config := newSimConfig(t)
	if mutate != nil {
		mutate(config)
	}

	params := &Params{
		Logger:       logger,
		DebugSecrets: false,
		Config:       config,
		BlobStore:    storageFactory.BlobStore(),
		Backend:      storageFactory.KeyBackend(),
		Transport:    sim.Transport(),
		FQDN:         "node1.example.com",
		HTTPClient:   httpClient,
	}

	tpmIface, err := NewTPM2(params)
	if err == ErrNotInitialized {
		require.NotNil(t, tpmIface)
		require.NoError(t, tpmIface.Provision(nil), "provisioning the simulator must succeed")
	} else {
		require.NoError(t, err)
	}

	tpmImpl, ok := tpmIface.(*TPM2)
	require.True(t, ok, "NewTPM2 must return *TPM2")

	// Cleanups run last-registered first: the TPM releases its state, then
	// the simulator and the on-disk store registered above are torn down.
	t.Cleanup(func() { _ = tpmIface.Close() })

	return &simHarness{
		TPM:     tpmImpl,
		Backend: storageFactory.KeyBackend(),
		Logger:  logger,
	}
}

// newSimConfig returns the baseline simulator configuration shared by the
// harness. It mirrors the long-standing createSim configuration in tpm_test.go
// so behaviour observed here matches the rest of the package's simulator tests.
func newSimConfig(t testing.TB) *Config {
	t.Helper()
	return &Config{
		UseEntropy:   false,
		UseSimulator: false, // Transport is supplied explicitly.
		Hash:         "SHA-256",
		EK: &EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		IdentityProvisioningStrategy: string(EnrollmentStrategyIAK),
		FileIntegrity:                []string{"./"},
		IAK: &IAKConfig{
			CN:           "device-id-001",
			Debug:        true,
			Hash:         crypto.SHA256.String(),
			Handle:       uint32(0x81010002),
			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		PlatformPCR:     debugPCR,
		PlatformPCRBank: debugPCRBank,
		GoldenPCRs:      []uint{0, 7},
		SSRK: &SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: secrettest.Literal(t, []byte(store.DEFAULT_PASSWORD)),

			KeyAlgorithm: x509.RSA.String(),
			RSAConfig: &store.RSAConfig{
				KeySize: 2048,
			},
		},
		PlatformSRK: &PlatformSRKConfig{
			SRKHandle:      0x81000002,
			PlatformPolicy: true,
		},
	}
}

// extendPlatformPCR extends the harness's configured platform PCR with the
// supplied measurement, invalidating any policy previously satisfied by the
// old PCR value. This is the "the machine booted different software" event
// that PCR-sealed data is supposed to detect.
func (h *simHarness) extendPlatformPCR(t *testing.T, measurement []byte) {
	t.Helper()

	digest := make([]byte, 32)
	copy(digest, measurement)

	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(h.TPM.config.PlatformPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{
				HashAlg: tpm2.TPMAlgSHA256,
				Digest:  digest,
			}},
		},
	}.Execute(h.TPM.transport)
	require.NoError(t, err, "extending the platform PCR must succeed")
}
