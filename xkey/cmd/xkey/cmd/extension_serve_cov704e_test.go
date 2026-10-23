package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// relabelledStrategy presents a software strategy under an external
// strategy ID, standing in for the PKCS#11 or cloud KMS backend serve builds
// for those barriers.
type relabelledStrategy struct {
	xkms.SealingStrategy
	id xkms.StrategyID
}

func (s relabelledStrategy) ID() xkms.StrategyID { return s.id }

// SealRootKey records the external ID on the sealed root key, as the real
// backend does, so the barrier unseals it through the external strategy.
func (s relabelledStrategy) SealRootKey(ctx context.Context, rootKey []byte, creds xkms.SealCredentials) (*xkms.SealedRootKey, error) {
	sealed, err := s.SealingStrategy.SealRootKey(ctx, rootKey, creds)
	if err != nil {
		return nil, err
	}
	sealed.Strategy = s.id
	return sealed, nil
}

// UnsealRootKey hands the software strategy the sealed key under its own ID.
func (s relabelledStrategy) UnsealRootKey(ctx context.Context, sealed *xkms.SealedRootKey, creds xkms.SealCredentials) ([]byte, error) {
	inner := *sealed
	inner.Strategy = s.SealingStrategy.ID()
	return s.SealingStrategy.UnsealRootKey(ctx, &inner, creds)
}

// errBackendRefused is the unseal failure refusingStrategy reports.
var errBackendRefused = errors.New("backend refused to unwrap the root key")

// refusingStrategy is an external strategy whose backend refuses to unwrap
// the root key, as an HSM or KMS does for a key it no longer holds.
type refusingStrategy struct{ relabelledStrategy }

func (refusingStrategy) UnsealRootKey(context.Context, *xkms.SealedRootKey, xkms.SealCredentials) ([]byte, error) {
	return nil, errBackendRefused
}

// countingCloser records how often the strategy backend was released.
type countingCloser struct{ closed int }

func (c *countingCloser) Close() error {
	c.closed++
	return nil
}

// externalStrategy returns a strategy under id whose root key is bound to
// passphrase.
func externalStrategy(t *testing.T, id xkms.StrategyID, passphrase string) xkms.SealingStrategy {
	t.Helper()
	software, err := qrdbsdk.NewSoftwareStrategy(context.Background(), []byte(passphrase))
	require.NoError(t, err)
	return relabelledStrategy{SealingStrategy: software, id: id}
}

// sealedExternalBarrier initializes a barrier under an external strategy, as
// `xkey barrier init` leaves it, and returns a fresh service over the same
// directory, as the next serve starts with.
func sealedExternalBarrier(t *testing.T, id xkms.StrategyID) *services.BarrierService {
	t.Helper()
	dir := t.TempDir()
	initExternalBarrier(t, dir, id)
	svc := services.NewBarrierService(t.TempDir(), slog.New(slog.DiscardHandler))
	svc.SetDataDir(dir)
	require.False(t, svc.IsUnsealed())
	return svc
}

// initExternalBarrier initializes and seals a barrier in dataDir under an
// external strategy whose root key is bound to "backend-key".
func initExternalBarrier(t *testing.T, dataDir string, id xkms.StrategyID) {
	t.Helper()
	initSvc := services.NewBarrierService(t.TempDir(), slog.New(slog.DiscardHandler))
	initSvc.SetDataDir(dataDir)
	initSvc.SetExternalStrategyFunc(func(string) (xkms.SealingStrategy, error) {
		return externalStrategy(t, id, "backend-key"), nil
	})
	require.NoError(t, initSvc.Initialize("", string(id)))
	require.NoError(t, initSvc.Seal())
}

// TestUnsealWithExternalStrategy_UnsealsAndKeepsTheBackendOpen checks the
// PKCS#11 and cloud KMS unseal: the barrier opens with the built strategy and
// the backend's closer is handed back, still open, for serve to release on
// exit.
func TestUnsealWithExternalStrategy_UnsealsAndKeepsTheBackendOpen(t *testing.T) {
	for _, id := range []xkms.StrategyID{xkms.StrategyPKCS11, xkms.StrategyAWSKMS} {
		t.Run(string(id), func(t *testing.T) {
			svc := sealedExternalBarrier(t, id)
			backend := &countingCloser{}

			closer, err := unsealWithExternalStrategy(svc, id, func() (xkms.SealingStrategy, io.Closer, error) {
				return externalStrategy(t, id, "backend-key"), backend, nil
			})
			require.NoError(t, err)
			assert.Same(t, backend, closer)
			assert.Zero(t, backend.closed, "the backend stays open while serve runs")
			assert.True(t, svc.IsUnsealed())
		})
	}
}

// TestUnsealWithExternalStrategy_BuildFailureIsTyped checks that a backend
// that cannot be built leaves the barrier sealed and reports the typed
// unseal failure with the cause.
func TestUnsealWithExternalStrategy_BuildFailureIsTyped(t *testing.T) {
	svc := sealedExternalBarrier(t, xkms.StrategyPKCS11)
	buildErr := errors.New("token not present")

	closer, err := unsealWithExternalStrategy(svc, xkms.StrategyPKCS11, func() (xkms.SealingStrategy, io.Closer, error) {
		return nil, nil, buildErr
	})
	require.ErrorIs(t, err, ErrServeBarrierUnsealFailed)
	require.ErrorIs(t, err, buildErr)
	assert.Nil(t, closer)
	assert.False(t, svc.IsUnsealed())
}

// TestUnsealWithExternalStrategy_RefusedUnsealReleasesTheBackend checks that
// when the backend refuses to unseal the root key the barrier stays sealed,
// the error is typed and keeps the backend's reason, and the backend the
// build opened is closed rather than leaked.
func TestUnsealWithExternalStrategy_RefusedUnsealReleasesTheBackend(t *testing.T) {
	tests := []struct {
		name    string
		backend *countingCloser
	}{
		{name: "with a backend", backend: &countingCloser{}},
		{name: "without a backend"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := sealedExternalBarrier(t, xkms.StrategyAWSKMS)
			refusing := refusingStrategy{relabelledStrategy{
				SealingStrategy: externalStrategy(t, xkms.StrategyAWSKMS, "backend-key"),
				id:              xkms.StrategyAWSKMS,
			}}

			closer, err := unsealWithExternalStrategy(svc, xkms.StrategyAWSKMS, func() (xkms.SealingStrategy, io.Closer, error) {
				if tt.backend == nil {
					return refusing, nil, nil
				}
				return refusing, tt.backend, nil
			})
			require.ErrorIs(t, err, ErrServeBarrierUnsealFailed)
			require.ErrorIs(t, err, errBackendRefused)
			assert.Nil(t, closer)
			assert.False(t, svc.IsUnsealed())
			if tt.backend != nil {
				assert.Equal(t, 1, tt.backend.closed)
			}
		})
	}
}

// withExternalBarrierBuilders points serve's PKCS#11 and cloud KMS strategy
// builders at an in-process strategy bound to "backend-key", whose backend
// is the returned closer.
func withExternalBarrierBuilders(t *testing.T) *countingCloser {
	t.Helper()
	backend := &countingCloser{}
	previousPKCS11, previousCloud := pkcs11BarrierStrategy, cloudKMSBarrierStrategy
	pkcs11BarrierStrategy = func(context.Context, string, string, bool) (xkms.SealingStrategy, io.Closer, error) {
		return externalStrategy(t, xkms.StrategyPKCS11, "backend-key"), backend, nil
	}
	cloudKMSBarrierStrategy = func(_ context.Context, id xkms.StrategyID, _ string) (xkms.SealingStrategy, io.Closer, error) {
		return externalStrategy(t, id, "backend-key"), backend, nil
	}
	t.Cleanup(func() { pkcs11BarrierStrategy, cloudKMSBarrierStrategy = previousPKCS11, previousCloud })
	return backend
}

// TestExtensionServe_ExternalBarrierUnsealsAndReleasesItsBackend runs serve
// over a pkcs11 and a cloud KMS barrier: serve unseals with the built
// strategy, needing no password, comes up listening, and releases the
// strategy's backend exactly once when it stops.
func TestExtensionServe_ExternalBarrierUnsealsAndReleasesItsBackend(t *testing.T) {
	for _, id := range []xkms.StrategyID{xkms.StrategyPKCS11, xkms.StrategyGCPKMS} {
		t.Run(string(id), func(t *testing.T) {
			dataDir := isolateServeHome(t)
			initExternalBarrier(t, dataDir, id)
			backend := withExternalBarrierBuilders(t)
			socketPath := filepath.Join(privateTempDir(t), "serve.sock")

			_, stop := startServe(t, serveRunCmd(t, socketPath, false), socketPath)
			assert.Zero(t, backend.closed, "the backend stays open while serve runs")
			stop()
			assert.Equal(t, 1, backend.closed)
		})
	}
}

// TestExtensionServe_ExternalBarrierBuildFailureRefusesToStart checks that
// serve refuses to start, with the typed unseal error, when the pkcs11
// strategy cannot be built.
func TestExtensionServe_ExternalBarrierBuildFailureRefusesToStart(t *testing.T) {
	dataDir := isolateServeHome(t)
	initExternalBarrier(t, dataDir, xkms.StrategyPKCS11)
	withExternalBarrierBuilders(t)
	tokenErr := errors.New("token not present")
	pkcs11BarrierStrategy = func(context.Context, string, string, bool) (xkms.SealingStrategy, io.Closer, error) {
		return nil, nil, tokenErr
	}
	socketPath := filepath.Join(privateTempDir(t), "serve.sock")

	err := serveRunCmd(t, socketPath, false).Execute()
	require.ErrorIs(t, err, ErrServeBarrierUnsealFailed)
	require.ErrorIs(t, err, tokenErr)
	assert.NoFileExists(t, socketPath)
}
