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
	"io"
	"net/http"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/test/integration/xkmsdtest"
)

// authBootstrap authenticates the suite as the first-boot admin the way a
// deployment does: it SPKI-binds the admin credential to the admin user and
// logs in with it over the PIV/mTLS login plane for a session token
// (XKMSD_TOKEN). xkmsctl presents the admin certificate itself.
func authBootstrap(server *xkmsdtest.Server) error {
	client, err := server.HTTPClient(server.AdminCert, server.AdminKey)
	if err != nil {
		return err
	}
	env.admin = client

	admin, err := tls.LoadX509KeyPair(server.AdminCert, server.AdminKey)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(admin.Certificate[0])
	if err != nil {
		return err
	}
	if err := bindAdminCert(client, server.URL, leaf); err != nil {
		return err
	}

	roots, err := server.RootCAs()
	if err != nil {
		return err
	}
	login, err := xkms.NewLoginClient(xkms.LoginClientConfig{
		BaseURL:           server.URL,
		ClientCertificate: &admin,
		RootCAs:           roots,
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
	respBody, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &xkmsdtest.StatusError{URL: resp.Request.URL.String(), Code: resp.StatusCode, Body: string(respBody)}
	}
	return nil
}
