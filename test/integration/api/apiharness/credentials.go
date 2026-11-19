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

package apiharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// The admin mTLS credential `xkmsd init --admin-factor mtls` writes into the
// server's data volume, which docker-compose.yml mounts read-only into the
// integration-tests service at /xkms-data. The server requires a verified
// client certificate (config.test.yaml: client_auth verify, auth enabled),
// so every CLI invocation in the suite presents this credential.
const (
	adminCertEnv     = "XKMS_ADMIN_CERT"
	defaultAdminCert = "/xkms-data/xkms/admin-cert.pem"
	adminKeyEnv      = "XKMS_ADMIN_KEY"
	defaultAdminKey  = "/xkms-data/xkms/admin-key.pem"

	// ceremonyCAEnv names the ceremony root init writes beside the admin
	// credential; it issues the admin certificate and the server's CA-backed
	// serving certificates.
	ceremonyCAEnv     = "XKMS_CEREMONY_CA"
	defaultCeremonyCA = "/xkms-data/xkms/ca-bundle.pem"

	// unifiedCAEnv names the bundle the server persists beside its unified
	// listener's certificate once the CA-issued certificate replaces the
	// bootstrap one (pkg/server/unified_tls.go). The Unix socket is that
	// listener. The file exists only after the server has unsealed, so it is
	// added when present.
	unifiedCAEnv     = "XKMS_UNIFIED_CA"
	defaultUnifiedCA = "/xkms-data/xkms/unified-tls/ca-bundle.pem"
)

// ErrAdminCredential reports that the admin credential or a trust anchor the
// suite needs is missing or unreadable.
var ErrAdminCredential = errors.New("apiharness: admin mTLS credential unavailable")

// AdminCertFile is the admin client certificate's path.
func AdminCertFile() string { return envOr(adminCertEnv, defaultAdminCert) }

// AdminKeyFile is the admin client key's path.
func AdminKeyFile() string { return envOr(adminKeyEnv, defaultAdminKey) }

// TrustBundleFile writes one PEM bundle holding every CA that can sign a
// certificate the server presents -- the suite CA that signs the operator
// certificate (KEYSTORE_TLS_CA), the init ceremony root, and the unified
// listener's persisted bundle when the server has written it -- and returns
// its path. It re-reads the CAs and rewrites the bundle on every call, so a
// serving CA the server persists at unseal is trusted by the next caller.
// Verification stays on: the CLI checks the server's chain against this
// bundle on every transport.
func TrustBundleFile() (string, error) {
	bundle, err := trustBundlePEM()
	if err != nil {
		return "", err
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("xkms-api-trust-%d.pem", os.Getpid()))
	// A rename replaces the bundle atomically, so a concurrent CLI run reads
	// either the old or the new bundle, never a partial one.
	tmp, err := os.CreateTemp(os.TempDir(), "xkms-api-trust-*.tmp")
	if err != nil {
		return "", fmt.Errorf("%w: write trust bundle: %w", ErrAdminCredential, err)
	}
	_, werr := tmp.Write(bundle)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp.Name()) // best effort; the write error is the one reported
		return "", fmt.Errorf("%w: write trust bundle: %w", ErrAdminCredential, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name()) // best effort; the rename error is the one reported
		return "", fmt.Errorf("%w: write trust bundle: %w", ErrAdminCredential, err)
	}
	return path, nil
}

// trustBundlePEM concatenates the suite CA, the ceremony root and, when the
// server has written it, the unified-TLS CA bundle.
func trustBundlePEM() ([]byte, error) {
	return readBundle(
		[]string{envOr(caFileEnv, defaultCAFile), envOr(ceremonyCAEnv, defaultCeremonyCA)},
		[]string{envOr(unifiedCAEnv, defaultUnifiedCA)},
	)
}

// serverTrustPEM is the bundle that verifies the server across its unseal:
// the suite CA, which signs the sealed window's bootstrap certificate, is
// required; the ceremony root and the unified-TLS CA bundle, which the
// serving certificate chains to once the server has unsealed, are added when
// present. Unlike trustBundlePEM it needs no ceremony root, so it serves
// before the admin credential exists.
func serverTrustPEM() ([]byte, error) {
	return readBundle(
		[]string{envOr(caFileEnv, defaultCAFile)},
		[]string{envOr(ceremonyCAEnv, defaultCeremonyCA), envOr(unifiedCAEnv, defaultUnifiedCA)},
	)
}

// readBundle concatenates the required CA files, failing on any it cannot
// read, and the optional ones that exist.
func readBundle(required, optional []string) ([]byte, error) {
	var bundle bytes.Buffer
	for _, path := range required {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read CA %s: %w", ErrAdminCredential, path, err)
		}
		bundle.Write(pem)
		bundle.WriteByte('\n')
	}
	for _, path := range optional {
		pem, err := os.ReadFile(path)
		switch {
		case err == nil:
			bundle.Write(pem)
			bundle.WriteByte('\n')
		case !errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("%w: read CA %s: %w", ErrAdminCredential, path, err)
		}
	}
	return bundle.Bytes(), nil
}

// TrustPool reads the server trust bundle (the suite CA, plus the ceremony
// root and the unified-TLS CA when present) from disk now. A caller that
// outlives the server's unseal re-reads it, or uses TrustedHTTPClient.
func TrustPool() (*x509.CertPool, error) {
	bundle, err := serverTrustPEM()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, fmt.Errorf("%w: trust bundle holds no certificate", ErrAdminCredential)
	}
	return pool, nil
}

// TrustedHTTPClient returns a client that verifies the server against
// TrustPool re-read on every TLS dial, so it keeps verifying the server when
// unsealing switches it from the bootstrap certificate to the one the
// serving CA issued.
func TrustedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialTLSContext: dialTrusted},
	}
}

func dialTrusted(ctx context.Context, network, addr string) (net.Conn, error) {
	pool, err := TrustPool()
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13}}
	return dialer.DialContext(ctx, network, addr)
}

// ClientTLSConfig is the in-process form of ClientTLSArgs, for the tests that
// build their own HTTP, HTTP/3 or MCP client: it trusts the suite CA, the
// ceremony root and the unified-TLS CA, and presents the init-ceremony admin
// certificate, because every listener now requires a client certificate.
func ClientTLSConfig() (*tls.Config, error) {
	bundle, err := trustBundlePEM()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return nil, fmt.Errorf("%w: trust bundle holds no certificate", ErrAdminCredential)
	}
	cert, err := tls.LoadX509KeyPair(AdminCertFile(), AdminKeyFile())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAdminCredential, err)
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSArgs returns the xkmsctl global flags that authenticate as the
// admin and verify the server: --tls-ca with the trust bundle, --tls-cert and
// --tls-key with the admin credential. Callers pass them on every transport
// that dials the server (unix, rest, grpc, quic).
func ClientTLSArgs() ([]string, error) {
	ca, err := TrustBundleFile()
	if err != nil {
		return nil, err
	}
	cert, key := AdminCertFile(), AdminKeyFile()
	for _, path := range []string{cert, key} {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrAdminCredential, path, err)
		}
	}
	return []string{"--tls-ca", ca, "--tls-cert", cert, "--tls-key", key}, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
