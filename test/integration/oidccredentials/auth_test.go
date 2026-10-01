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

//go:build integration

package oidccredentials

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// errNoAdminCredential is returned when first-boot left no admin credential
// in the data directory.
var errNoAdminCredential = errors.New("no first-boot admin credential in the data directory")

// trustServer fetches the server's CA bundle the way a first-contact client
// does, trust-on-first-use over the public GET /v1/ca/bootstrap
// (pkg/trust/bootstrap), retrying until the embedded CA has composed, and
// writes it to path for every client of the suite.
func trustServer(serverURL, path string) error {
	pins := truststrap.NewMemoryPinStore()
	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
			Mode:      bootstrap.ModeTOFU,
			ServerURL: serverURL,
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			TOFU: &bootstrap.TOFUConfig{
				PinStore:    pins,
				ConfirmFunc: func(context.Context, *truststrap.Pin) error { return nil },
			},
		})
		cancel()
		if err == nil {
			env.caFile = path
			return os.WriteFile(path, bundle.PEM, 0o600)
		}
		if time.Now().After(deadline) {
			return err
		}
		timer := time.NewTimer(time.Second)
		<-timer.C
	}
}

// authBootstrap authenticates the suite the way an operator does on a fresh
// deployment: it SPKI-binds the first-boot admin credential to the admin
// user and logs in over mTLS for a session token xkey presents
// (XKMSD_TOKEN). xkmsctl presents the admin certificate itself.
func authBootstrap(dataDir, restURL string) error {
	certPath, keyPath, err := findAdminCredential(dataDir)
	if err != nil {
		return err
	}
	env.adminCert, env.adminKey = certPath, keyPath
	admin, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	pool := x509.NewCertPool()
	bundle, err := os.ReadFile(env.caFile)
	if err != nil {
		return err
	}
	pool.AppendCertsFromPEM(bundle)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{admin},
			MinVersion:   tls.VersionTLS12,
		}},
	}

	env.admin = client

	leaf, err := x509.ParseCertificate(admin.Certificate[0])
	if err != nil {
		return err
	}
	if err := bindAdminCert(client, restURL, leaf); err != nil {
		return err
	}

	login, err := xkms.NewLoginClient(xkms.LoginClientConfig{
		BaseURL:           restURL,
		ClientCertificate: &admin,
		RootCAs:           pool,
		Timeout:           30 * time.Second,
	})
	if err != nil {
		return err
	}
	pair, err := login.PIVLogin(context.Background())
	if err != nil {
		return err
	}
	env.token = pair.AccessToken
	return nil
}

// bindAdminCert binds cert's SPKI thumbprint to the admin user, so a PIV
// login with it authenticates as the admin. client presents the admin
// credential.
func bindAdminCert(client *http.Client, restURL string, cert *x509.Certificate) error {
	body, err := json.Marshal(map[string]string{"thumbprint": qrdbsdk.ComputeSPKIThumbprint(cert)})
	if err != nil {
		return err
	}
	resp, err := client.Post(restURL+"/api/v1/users/admin/cert-bindings", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return drain(resp, http.StatusOK)
}

// findAdminCredential locates admin-cert.pem and admin-key.pem under dir.
func findAdminCredential(dir string) (certPath, keyPath string, err error) {
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch d.Name() {
		case "admin-cert.pem":
			certPath = path
		case "admin-key.pem":
			keyPath = path
		}
		return nil
	})
	if walkErr != nil {
		return "", "", walkErr
	}
	if certPath == "" || keyPath == "" {
		return "", "", errNoAdminCredential
	}
	return certPath, keyPath, nil
}

// drain consumes and closes resp, refusing any status but want.
func drain(resp *http.Response, want int) error {
	data, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		return &statusError{url: resp.Request.URL.String(), code: resp.StatusCode, body: string(data)}
	}
	return nil
}

// statusError reports an unexpected HTTP status.
type statusError struct {
	url  string
	code int
	body string
}

func (e *statusError) Error() string {
	return e.url + ": HTTP " + http.StatusText(e.code) + ": " + e.body
}
