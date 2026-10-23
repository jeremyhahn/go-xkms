package cmd

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// c704cOSStore stands in for the operating system's certificate store.
type c704cOSStore struct {
	installed  map[string]*x509.Certificate // label -> certificate
	installErr error
	removeErr  error
}

func (s *c704cOSStore) Install(cert *x509.Certificate, label string) error {
	if s.installErr != nil {
		return s.installErr
	}
	s.installed[label] = cert
	return nil
}

func (s *c704cOSStore) Remove(label string) error {
	if s.removeErr != nil {
		return s.removeErr
	}
	delete(s.installed, label)
	return nil
}

func (s *c704cOSStore) IsInstalled(label string) (bool, error) {
	_, ok := s.installed[label]
	return ok, nil
}

func (s *c704cOSStore) RefreshSystemStore() error { return nil }

// c704cOS installs a fake OS store; a non-nil openErr makes opening it fail
// as on a host without a supported trust store.
func c704cOS(t *testing.T, openErr error) *c704cOSStore {
	t.Helper()
	store := &c704cOSStore{installed: map[string]*x509.Certificate{}}
	saved := newOSCertStore
	newOSCertStore = func() (truststore.OSCertStore, error) {
		if openErr != nil {
			return nil, openErr
		}
		return store, nil
	}
	t.Cleanup(func() { newOSCertStore = saved })
	return store
}

// c704cTrustedCA puts a CA certificate into a fresh xkey trust store and
// returns its fingerprint and the store directory.
func c704cTrustedCA(t *testing.T) (*x509.Certificate, string, string) {
	t.Helper()
	resetViperForTest(t)
	storeDir := configureTrustStorePath(t)
	cert, _ := makeFetchCA(t)
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: storeDir})
	require.NoError(t, err)
	require.NoError(t, store.AddCertificate(cert))
	require.NoError(t, store.Close())
	return cert, truststore.Fingerprint(cert), storeDir
}

// c704cSystemInstalled reports the trust store's system-installed flag.
func c704cSystemInstalled(t *testing.T, storeDir, fp string) bool {
	t.Helper()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: storeDir})
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	meta, err := store.Metadata(fp)
	require.NoError(t, err)
	require.NotNil(t, meta)
	return meta.SystemInstalled
}

func TestC704cTrustInstall_InstallsAndRecordsIt(t *testing.T) {
	cert, fp, storeDir := c704cTrustedCA(t)
	osStore := c704cOS(t, nil)

	cmd, out := trustTestCmd(t)
	require.NoError(t, runTrustInstall(cmd, []string{fp}))
	label := "xkey-" + fp[:16]
	assert.Equal(t, cert.Raw, osStore.installed[label].Raw)
	assert.True(t, c704cSystemInstalled(t, storeDir, fp))
	assert.Contains(t, out.String(), "installed to OS trust store as "+label)
}

func TestC704cTrustInstall_OSStoreFailures(t *testing.T) {
	for name, tt := range map[string]struct{ openErr, installErr error }{
		"open":    {openErr: errC704cHost},
		"install": {installErr: truststore.ErrPermissionDenied},
	} {
		t.Run(name, func(t *testing.T) {
			_, fp, storeDir := c704cTrustedCA(t)
			osStore := c704cOS(t, tt.openErr)
			osStore.installErr = tt.installErr

			cmd, _ := trustTestCmd(t)
			err := runTrustInstall(cmd, []string{fp})
			require.ErrorIs(t, err, ErrTrustInstallFailed)
			require.ErrorIs(t, err, c704cFirstErr(tt.openErr, tt.installErr))
			assert.Empty(t, osStore.installed)
			assert.False(t, c704cSystemInstalled(t, storeDir, fp))
		})
	}
}

func TestC704cTrustUninstall_RemovesAndRecordsIt(t *testing.T) {
	_, fp, storeDir := c704cTrustedCA(t)
	osStore := c704cOS(t, nil)
	cmd, _ := trustTestCmd(t)
	require.NoError(t, runTrustInstall(cmd, []string{fp}))

	cmd, out := trustTestCmd(t)
	require.NoError(t, runTrustUninstall(cmd, []string{fp}))
	assert.Empty(t, osStore.installed)
	assert.False(t, c704cSystemInstalled(t, storeDir, fp))
	assert.Contains(t, out.String(), "Certificate "+fp+" removed from OS trust store")
}

func TestC704cTrustUninstall_OSStoreFailures(t *testing.T) {
	for name, tt := range map[string]struct{ openErr, removeErr error }{
		"open":   {openErr: errC704cHost},
		"remove": {removeErr: truststore.ErrRemoveFailed},
	} {
		t.Run(name, func(t *testing.T) {
			_, fp, _ := c704cTrustedCA(t)
			osStore := c704cOS(t, tt.openErr)
			osStore.removeErr = tt.removeErr

			cmd, out := trustTestCmd(t)
			err := runTrustUninstall(cmd, []string{fp})
			require.ErrorIs(t, err, ErrTrustUninstallFailed)
			require.ErrorIs(t, err, c704cFirstErr(tt.openErr, tt.removeErr))
			assert.NotContains(t, out.String(), "removed")
		})
	}
}

// c704cFirstErr returns a when it is set, else b.
func c704cFirstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// c704cFetchInstall runs `trust fetch --install-system` of a one-CA bundle
// from a pinned loopback server.
func c704cFetchInstall(t *testing.T, openErr, installErr error) (*c704cOSStore, *x509.Certificate, string, string, string, error) {
	t.Helper()
	resetViperForTest(t)
	cert, bundlePEM := makeFetchCA(t)
	srv := startFetchServer(t, bundlePEM)
	storeDir := configureTrustStorePath(t)
	osStore := c704cOS(t, openErr)
	osStore.installErr = installErr

	fcmd := newFetchTestCmd()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	fcmd.SetOut(out)
	fcmd.SetErr(errOut)
	require.NoError(t, setFlagForTest(t, fcmd.Flags(), "spki-pin", tlsServerPin(t, srv)))
	require.NoError(t, setFlagForTest(t, fcmd.Flags(), "install-system", "true"))
	err := runTrustFetch(fcmd, []string{srv.URL + xkms.TrustFetcherDefaultBundlePath})
	return osStore, cert, storeDir, out.String(), errOut.String(), err
}

func TestC704cTrustFetch_InstallSystemInstallsTheRoot(t *testing.T) {
	osStore, cert, storeDir, out, errOut, err := c704cFetchInstall(t, nil, nil)
	require.NoError(t, err, "stderr=%s", errOut)

	fp := truststore.Fingerprint(cert)
	label := "xkey-" + fp[:16]
	require.Contains(t, osStore.installed, label)
	assert.Equal(t, cert.Raw, osStore.installed[label].Raw)
	assert.True(t, c704cSystemInstalled(t, storeDir, fp))
	assert.Contains(t, out, "installed to OS trust store: "+label+" (Trust Fetch CA)")
}

func TestC704cTrustFetch_InstallSystemOSStoreFailures(t *testing.T) {
	t.Run("no OS store", func(t *testing.T) {
		_, _, _, out, _, err := c704cFetchInstall(t, errC704cHost, nil)
		require.ErrorIs(t, err, ErrTrustFetchFailed)
		assert.Contains(t, err.Error(), "OS trust store unavailable")
		assert.Contains(t, out, "Bundle fetched from", "the bundle is kept in the xkey store")
	})
	t.Run("install refused", func(t *testing.T) {
		_, cert, storeDir, _, _, err := c704cFetchInstall(t, nil, truststore.ErrPermissionDenied)
		require.ErrorIs(t, err, ErrTrustFetchFailed)
		assert.Contains(t, err.Error(), "OS install failed")
		assert.False(t, c704cSystemInstalled(t, storeDir, truststore.Fingerprint(cert)))
	})
}
