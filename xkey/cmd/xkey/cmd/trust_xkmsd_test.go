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

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sdkxkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	sdktruststore "github.com/jeremyhahn/go-xkms/sdk/go/truststore"
)

// selfSignedTrustPEM returns a PEM-encoded self-signed P-256 CA certificate
// with the given common name.
func selfSignedTrustPEM(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"xkey"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// trustPEMFingerprint returns the trust-store fingerprint of a PEM certificate.
func trustPEMFingerprint(t *testing.T, pemData []byte) string {
	t.Helper()

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return sdktruststore.Fingerprint(cert)
}

// newTrustRootTestStore builds a DAO-backed trust-root store on in-memory
// storage through sdk/go.
func newTrustRootTestStore(t *testing.T) *sdktruststore.DAOStore {
	t.Helper()

	factory, err := sdkxkms.NewBackendDAOFactory(sdkxkms.NewStorageMemory())
	require.NoError(t, err)
	store, err := sdktruststore.NewDAOStore(factory)
	require.NoError(t, err)
	return store
}

// isolateLocalTrustStore points the local FileStore at a temp dir holding one
// root with the given common name.
func isolateLocalTrustStore(t *testing.T, cn string) {
	t.Helper()

	previous := viper.Get("trust.store_path")
	viper.Set("trust.store_path", t.TempDir())
	t.Cleanup(func() { viper.Set("trust.store_path", previous) })

	store, err := openTrustStore()
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	_, err = store.ImportPEM(selfSignedTrustPEM(t, cn), &sdktruststore.AddCertificateOptions{})
	require.NoError(t, err)
}

// startTrustXKMSd starts a harness xkmsd whose trust-root store holds one
// root (CN "strotb server root") and returns that root's fingerprint.
func startTrustXKMSd(t *testing.T) string {
	t.Helper()

	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotb local root")

	svc := newTestXKMSService(t)
	store := newTrustRootTestStore(t)
	rootPEM := selfSignedTrustPEM(t, "strotb server root")
	_, err := store.ImportPEM(context.Background(), rootPEM, &sdktruststore.AddCertificateOptions{})
	require.NoError(t, err)
	svc.SetTrustRootStore(store)

	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address
	return trustPEMFingerprint(t, rootPEM)
}

func TestTrustListXKMSd_ShowsServerRoots(t *testing.T) {
	startTrustXKMSd(t)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runTrustList(cmd, nil))

	out := buf.String()
	require.Contains(t, out, "strotb server root")
	require.NotContains(t, out, "strotb local root")
}

func TestTrustShowXKMSd_ByFingerprint(t *testing.T) {
	fingerprint := startTrustXKMSd(t)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runTrustShow(cmd, []string{fingerprint}))

	out := buf.String()
	require.Contains(t, out, fingerprint)
	require.Contains(t, out, "strotb server root")
}

func TestTrustListXKMSd_NotConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotb local root")

	svc := newTestXKMSService(t)
	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.Error(t, runTrustList(cmd, nil))
	require.Empty(t, buf.String())
}

// newTrustAddTestCommand returns a command carrying the trust add flags,
// writing its output to buf.
func newTrustAddTestCommand(t *testing.T, buf *bytes.Buffer, purpose, source string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.Flags().String("purpose", "", "")
	cmd.Flags().String("source", "", "")
	if purpose != "" {
		require.NoError(t, cmd.Flags().Set("purpose", purpose))
	}
	if source != "" {
		require.NoError(t, cmd.Flags().Set("source", source))
	}
	return cmd
}

// writeTrustPEMFile writes a fresh self-signed root to a temp file and
// returns its path and fingerprint.
func writeTrustPEMFile(t *testing.T, cn string) (string, string) {
	t.Helper()

	pemData := selfSignedTrustPEM(t, cn)
	path := filepath.Join(t.TempDir(), "root.pem")
	require.NoError(t, os.WriteFile(path, pemData, 0o600))
	return path, trustPEMFingerprint(t, pemData)
}

// getServerTrustRoot fetches a root from the running xkmsd.
func getServerTrustRoot(t *testing.T, fingerprint string) (*transport.TrustRoot, error) {
	t.Helper()

	client, err := connectXKMSdClient(&cobra.Command{})
	require.NoError(t, err)
	defer func() { require.NoError(t, client.Close()) }()
	return client.TrustRootGet(context.Background(), &transport.TrustRootRequest{Fingerprint: fingerprint})
}

// requireLocalTrustStoreUntouched checks the local store holds only the
// root isolateLocalTrustStore seeded.
func requireLocalTrustStoreUntouched(t *testing.T) {
	t.Helper()

	store, err := openTrustStore()
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	certs, err := store.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestTrustAddXKMSd_ImportsToServer(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, fingerprint := writeTrustPEMFile(t, "strotc added root")

	var buf bytes.Buffer
	cmd := newTrustAddTestCommand(t, &buf, "user-ca", "test")
	require.NoError(t, runTrustAdd(cmd, []string{pemFile}))
	require.Contains(t, buf.String(), "Certificates added: 1")

	root, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)
	require.Equal(t, "user-ca", string(root.Purpose))
	require.Equal(t, "test", root.Source)

	requireLocalTrustStoreUntouched(t)
}

func TestTrustAddXKMSd_SkipsExisting(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, _ := writeTrustPEMFile(t, "strotc twice root")

	var first bytes.Buffer
	require.NoError(t, runTrustAdd(newTrustAddTestCommand(t, &first, "", ""), []string{pemFile}))
	require.Contains(t, first.String(), "Certificates added: 1")

	var second bytes.Buffer
	require.NoError(t, runTrustAdd(newTrustAddTestCommand(t, &second, "", ""), []string{pemFile}))
	require.Contains(t, second.String(), "Certificates skipped (already present): 1")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustAddXKMSd_BadPurpose(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, fingerprint := writeTrustPEMFile(t, "strotc bad purpose root")

	var buf bytes.Buffer
	err := runTrustAdd(newTrustAddTestCommand(t, &buf, "nope", ""), []string{pemFile})
	require.ErrorIs(t, err, ErrTrustAddFailed)
	require.Empty(t, buf.String())

	_, err = getServerTrustRoot(t, fingerprint)
	require.Error(t, err)
	requireLocalTrustStoreUntouched(t)
}

func TestTrustRemoveXKMSd_RemovesServerRoot(t *testing.T) {
	fingerprint := startTrustXKMSd(t)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	require.NoError(t, runTrustRemove(cmd, []string{fingerprint}))
	require.Contains(t, buf.String(), "Certificate removed: "+fingerprint)

	_, err := getServerTrustRoot(t, fingerprint)
	require.Error(t, err)

	err = runTrustRemove(cmd, []string{strings.Repeat("ab", 32)})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTrustRemoveFailed)
	require.Contains(t, err.Error(), "TrustRootRemove")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustAddXKMSd_NotConfigured(t *testing.T) {
	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotc local root")

	svc := newTestXKMSService(t)
	address, _ := startTestXKMSdService(t, svc)
	xkmsdURL = address

	pemFile, _ := writeTrustPEMFile(t, "strotc unconfigured root")

	var buf bytes.Buffer
	require.Error(t, runTrustAdd(newTrustAddTestCommand(t, &buf, "", ""), []string{pemFile}))
	require.Empty(t, buf.String())

	requireLocalTrustStoreUntouched(t)
}

func TestTrustClassifyXKMSd_QuarantinesServerRoot(t *testing.T) {
	fingerprint := startTrustXKMSd(t)

	var buf bytes.Buffer
	cmd := newTrustAddTestCommand(t, &buf, "synced", "")
	require.NoError(t, runTrustClassify(cmd, []string{"  " + strings.ToUpper(fingerprint) + " "}))
	require.Contains(t, buf.String(), "Certificate "+fingerprint+" classified as synced")

	root, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)
	require.Equal(t, "synced", string(root.Purpose))

	requireLocalTrustStoreUntouched(t)
}

func TestTrustClassifyXKMSd_RefusesOtherPurpose(t *testing.T) {
	fingerprint := startTrustXKMSd(t)
	before, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = runTrustClassify(newTrustAddTestCommand(t, &buf, "user-ca", ""), []string{fingerprint})
	require.ErrorIs(t, err, ErrTrustClassifyFailed)
	require.Contains(t, err.Error(), "synced")
	require.Empty(t, buf.String())

	after, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)
	require.Equal(t, before.Purpose, after.Purpose)

	requireLocalTrustStoreUntouched(t)
}

func TestTrustClassifyXKMSd_UnknownFingerprint(t *testing.T) {
	startTrustXKMSd(t)

	var buf bytes.Buffer
	err := runTrustClassify(newTrustAddTestCommand(t, &buf, "synced", ""), []string{strings.Repeat("ab", 32)})
	require.ErrorIs(t, err, ErrTrustClassifyFailed)
	require.Contains(t, err.Error(), "TrustRootQuarantine")
	require.Empty(t, buf.String())

	requireLocalTrustStoreUntouched(t)
}

func TestTrustClassifyXKMSd_BadPurpose(t *testing.T) {
	fingerprint := startTrustXKMSd(t)
	before, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = runTrustClassify(newTrustAddTestCommand(t, &buf, "nope", ""), []string{fingerprint})
	require.ErrorIs(t, err, ErrTrustClassifyFailed)
	require.Empty(t, buf.String())

	after, err := getServerTrustRoot(t, fingerprint)
	require.NoError(t, err)
	require.Equal(t, before.Purpose, after.Purpose)

	requireLocalTrustStoreUntouched(t)
}

func TestTrustInstallXKMSd_InstallsServerRoot(t *testing.T) {
	fake := c704cOS(t, nil)
	fingerprint := startTrustXKMSd(t)
	label := "xkey-" + fingerprint[:16]

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	require.NoError(t, runTrustInstall(cmd, []string{"  " + strings.ToUpper(fingerprint) + " "}))

	cert, ok := fake.installed[label]
	require.True(t, ok, "no OS store entry under %s", label)
	require.Equal(t, fingerprint, sdktruststore.Fingerprint(cert))
	require.Equal(t, "strotb server root", cert.Subject.CommonName)
	require.Contains(t, buf.String(), "Certificate "+fingerprint+" installed to OS trust store as "+label)

	requireLocalTrustStoreUntouched(t)
}

func TestTrustInstallXKMSd_UnknownFingerprint(t *testing.T) {
	fake := c704cOS(t, nil)
	startTrustXKMSd(t)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	err := runTrustInstall(cmd, []string{strings.Repeat("ab", 32)})
	require.ErrorIs(t, err, ErrTrustInstallFailed)
	require.Contains(t, err.Error(), "TrustRootGet")
	require.Empty(t, fake.installed)
	require.Empty(t, buf.String())

	requireLocalTrustStoreUntouched(t)
}

func TestTrustInstallXKMSd_OSStoreFails(t *testing.T) {
	fake := c704cOS(t, nil)
	fake.installErr = sdktruststore.ErrPermissionDenied
	fingerprint := startTrustXKMSd(t)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	err := runTrustInstall(cmd, []string{fingerprint})
	require.ErrorIs(t, err, ErrTrustInstallFailed)
	require.ErrorIs(t, err, sdktruststore.ErrPermissionDenied)
	require.Empty(t, fake.installed)
	require.Empty(t, buf.String())

	requireLocalTrustStoreUntouched(t)
}

func TestTrustUninstallXKMSd_RemovesOSEntry(t *testing.T) {
	fake := c704cOS(t, nil)
	fingerprint := startTrustXKMSd(t)

	var installOut bytes.Buffer
	installCmd := &cobra.Command{}
	installCmd.SetOut(&installOut)
	require.NoError(t, runTrustInstall(installCmd, []string{fingerprint}))
	require.Contains(t, fake.installed, "xkey-"+fingerprint[:16])

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	require.NoError(t, runTrustUninstall(cmd, []string{fingerprint}))
	require.Empty(t, fake.installed)
	require.Contains(t, buf.String(), "Certificate "+fingerprint+" removed from OS trust store")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustUninstallXKMSd_RootGoneFromServer(t *testing.T) {
	fake := c704cOS(t, nil)
	fingerprint := startTrustXKMSd(t)

	var installOut bytes.Buffer
	installCmd := &cobra.Command{}
	installCmd.SetOut(&installOut)
	require.NoError(t, runTrustInstall(installCmd, []string{fingerprint}))

	var removeOut bytes.Buffer
	removeCmd := &cobra.Command{}
	removeCmd.SetOut(&removeOut)
	require.NoError(t, runTrustRemove(removeCmd, []string{fingerprint}))
	_, err := getServerTrustRoot(t, fingerprint)
	require.Error(t, err)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	require.NoError(t, runTrustUninstall(cmd, []string{fingerprint}))
	require.Empty(t, fake.installed)
	require.Contains(t, buf.String(), "Certificate "+fingerprint+" removed from OS trust store")

	requireLocalTrustStoreUntouched(t)
}

// startTrustBootstrapServer serves bundlePEM on /v1/ca/bootstrap and points
// the direct bootstrap method at it. It returns the server's host.
func startTrustBootstrapServer(t *testing.T, bundlePEM []byte) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ca/bootstrap" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(bundlePEM)
	}))
	t.Cleanup(srv.Close)

	for _, key := range []string{"trust.bootstrap.server_url", "trust.bootstrap.direct.server_url"} {
		previous := viper.Get(key)
		viper.Set(key, srv.URL)
		t.Cleanup(func() { viper.Set(key, previous) })
	}

	parsed, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return parsed.Host
}

func newTrustBootstrapTestCommand(t *testing.T, buf *bytes.Buffer) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.Flags().StringSlice("method", nil, "")
	cmd.Flags().Duration("timeout", 5*time.Second, "")
	require.NoError(t, cmd.Flags().Set("method", "direct"))
	return cmd
}

func newTrustListTestCommand(t *testing.T, buf *bytes.Buffer, purpose string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.Flags().String("purpose", "", "")
	if purpose != "" {
		require.NoError(t, cmd.Flags().Set("purpose", purpose))
	}
	return cmd
}

func TestTrustBootstrapXKMSd_ImportsToServer(t *testing.T) {
	startTrustXKMSd(t)
	bundlePEM := newTestCertificatePEM(t, "strotf bootstrap CA")
	host := startTrustBootstrapServer(t, bundlePEM)

	var buf bytes.Buffer
	require.NoError(t, runTrustBootstrap(newTrustBootstrapTestCommand(t, &buf), nil))
	require.Contains(t, buf.String(), "Certificates imported: 1")

	root, err := getServerTrustRoot(t, trustPEMFingerprint(t, bundlePEM))
	require.NoError(t, err)
	require.Equal(t, "bootstrap-ca", string(root.Purpose))
	require.Equal(t, "platform:"+host, root.Source)

	requireLocalTrustStoreUntouched(t)
}

// TestTrustFetchXKMSd_ImportsToServer: with an xkmsd endpoint configured,
// trust fetch imports the pinned bundle into the server's trust-root store
// (docs/SPEC.md trust-roots) and never writes the local FileStore.
func TestTrustFetchXKMSd_ImportsToServer(t *testing.T) {
	startTrustXKMSd(t)
	_, bundlePEM := makeFetchCA(t)
	srv := startFetchServer(t, bundlePEM)
	pin := tlsServerPin(t, srv)

	fcmd := newFetchTestCmd()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	fcmd.SetOut(out)
	fcmd.SetErr(errOut)
	require.NoError(t, setFlagForTest(t, fcmd.Flags(), "spki-pin", pin))
	require.NoError(t, runTrustFetch(fcmd, []string{srv.URL + sdkxkms.TrustFetcherDefaultBundlePath}), "stderr=%s", errOut.String())
	require.Contains(t, out.String(), "added: 1")

	root, err := getServerTrustRoot(t, trustPEMFingerprint(t, bundlePEM))
	require.NoError(t, err)
	require.Equal(t, "bootstrap-ca", string(root.Purpose))

	var buf bytes.Buffer
	require.NoError(t, runTrustList(newTrustListTestCommand(t, &buf, ""), nil))
	require.Contains(t, buf.String(), "Trust Fetch CA")

	requireLocalTrustStoreUntouched(t)
}

// TestTrustBootstrapXKMSd_ImportHonoursTimeout: the server import runs under
// the bootstrap --timeout context, so an expired deadline stops it and files
// nothing on the server.
func TestTrustBootstrapXKMSd_ImportHonoursTimeout(t *testing.T) {
	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotf local root")

	// The connect succeeds; the server then holds TrustRootImport until the
	// caller's deadline cancels it, so only the bootstrap context can end it.
	reached := make(chan struct{})
	serverErr := make(chan error, 1)
	serverDeadline := make(chan time.Time, 1)
	release := make(chan struct{})
	stall := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !strings.HasSuffix(info.FullMethod, "/TrustRootImport") {
			return handler(ctx, req)
		}
		if dl, ok := ctx.Deadline(); ok {
			serverDeadline <- dl
		}
		close(reached)
		select {
		case <-ctx.Done():
			serverErr <- ctx.Err()
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-release:
			return nil, status.Error(codes.Aborted, "test released a stalled import")
		}
	}
	svc := newTestXKMSService(t)
	svc.SetTrustRootStore(newTrustRootTestStore(t))
	address, _ := startTestXKMSdService(t, svc, stall)
	xkmsdURL = address
	// Registered after the server so it runs first: a stalled handler would
	// otherwise block the server's GracefulStop.
	t.Cleanup(func() { close(release) })

	bundlePEM := newTestCertificatePEM(t, "strotf stalled bootstrap CA")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		done <- runTrustBootstrapXKMSd(ctx, newTrustBootstrapTestCommand(t, &buf), bundlePEM, "stalled.example")
	}()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled import outlived the bootstrap deadline")
	}
	select {
	case <-reached:
	default:
		t.Fatal("the bootstrap never reached TrustRootImport")
	}
	require.ErrorIs(t, err, ErrTrustBootstrapFailed, "the import, not the connect, fails")
	require.ErrorContains(t, err, "TrustRootImport", "the import ends at the bootstrap deadline")
	select {
	case cause := <-serverErr:
		// The server sees DeadlineExceeded when its propagated deadline
		// fires first, Canceled when the client's RST_STREAM wins the race.
		require.True(t, errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, context.Canceled),
			"the deadline cancels the server-side import, got %v", cause)
	case <-time.After(5 * time.Second):
		t.Fatal("the server-side import was never cancelled")
	}

	select {
	case dl := <-serverDeadline:
		want, _ := ctx.Deadline()
		require.False(t, dl.After(want.Add(time.Second)), "the import carries the bootstrap deadline")
	default:
		t.Fatal("the server-side import had no deadline: --timeout was not passed to TrustRootImport")
	}

	_, err = getServerTrustRoot(t, trustPEMFingerprint(t, bundlePEM))
	require.Error(t, err, "an import past its deadline files nothing")
}

func TestTrustBootstrapXKMSd_ReportsSkipped(t *testing.T) {
	startTrustXKMSd(t)
	startTrustBootstrapServer(t, newTestCertificatePEM(t, "strotf bootstrap CA"))

	var first bytes.Buffer
	require.NoError(t, runTrustBootstrap(newTrustBootstrapTestCommand(t, &first), nil))
	require.Contains(t, first.String(), "Certificates imported: 1")

	var second bytes.Buffer
	require.NoError(t, runTrustBootstrap(newTrustBootstrapTestCommand(t, &second), nil))
	require.Contains(t, second.String(), "Certificates imported: 0")
	require.Contains(t, second.String(), "Certificates skipped (already present): 1")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustListXKMSd_PurposeFilter(t *testing.T) {
	startTrustXKMSd(t)
	pemFile, _ := writeTrustPEMFile(t, "strotf image signer")
	var addBuf bytes.Buffer
	require.NoError(t, runTrustAdd(newTrustAddTestCommand(t, &addBuf, "image-signer", "test"), []string{pemFile}))

	var buf bytes.Buffer
	require.NoError(t, runTrustList(newTrustListTestCommand(t, &buf, "image-signer"), nil))
	require.Contains(t, buf.String(), "strotf image signer")
	require.NotContains(t, buf.String(), "strotb server root")

	var empty bytes.Buffer
	require.NoError(t, runTrustList(newTrustListTestCommand(t, &empty, "tpm-manufacturer"), nil))
	require.Contains(t, empty.String(), "No trusted certificates found.")

	requireLocalTrustStoreUntouched(t)
}

func TestTrustList_PurposeFilterLocal(t *testing.T) {
	isolateXKMSdEndpoint(t)
	isolateLocalTrustStore(t, "strotf other root")
	pemFile, _ := writeTrustPEMFile(t, "strotf image signer")
	var addBuf bytes.Buffer
	require.NoError(t, runTrustAdd(newTrustAddTestCommand(t, &addBuf, "image-signer", "test"), []string{pemFile}))

	var buf bytes.Buffer
	require.NoError(t, runTrustList(newTrustListTestCommand(t, &buf, "image-signer"), nil))
	require.Contains(t, buf.String(), "strotf image signer")
	require.NotContains(t, buf.String(), "strotf other root")

	var empty bytes.Buffer
	require.NoError(t, runTrustList(newTrustListTestCommand(t, &empty, "tpm-manufacturer"), nil))
	require.Contains(t, empty.String(), "No trusted certificates found.")
}

func TestTrustList_BadPurpose(t *testing.T) {
	t.Run("server", func(t *testing.T) {
		fingerprint := startTrustXKMSd(t)

		var buf bytes.Buffer
		err := runTrustList(newTrustListTestCommand(t, &buf, "nope"), nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrTrustListFailed), "got %v", err)
		require.Empty(t, buf.String())

		_, err = getServerTrustRoot(t, fingerprint)
		require.NoError(t, err)
		requireLocalTrustStoreUntouched(t)
	})
	t.Run("local", func(t *testing.T) {
		isolateXKMSdEndpoint(t)
		isolateLocalTrustStore(t, "strotf general root")

		var buf bytes.Buffer
		err := runTrustList(newTrustListTestCommand(t, &buf, "nope"), nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrTrustListFailed), "got %v", err)
		require.Empty(t, buf.String())
	})
}
