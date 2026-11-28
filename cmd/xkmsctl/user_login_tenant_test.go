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

package main

import (
	"context"
	"errors"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// tenantLoginClient records the login tenant of the ceremony it is asked to
// begin, then stops the ceremony.
type tenantLoginClient struct {
	mockUserClient
	begin *client.BeginAuthenticationRequest
}

func (c *tenantLoginClient) BeginAuthentication(_ context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	c.begin = req
	return nil, errors.New("ceremony stopped by the test")
}

func runTenantLogin(t *testing.T, tenant string) *tenantLoginClient {
	t.Helper()
	mock := &tenantLoginClient{}
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	})
	cmd := newUserLoginCmd()
	cmd.Flags().String(loginTenantFlag, "", "")
	if tenant != "" {
		if err := cmd.Flags().Set(loginTenantFlag, tenant); err != nil {
			t.Fatalf("set --%s: %v", loginTenantFlag, err)
		}
	}
	captureExit(t, func() {
		userLoginCmd.Run(cmd, []string{"alice@example.com"})
	})
	if mock.begin == nil {
		t.Fatal("a valid email must begin the ceremony")
	}
	return mock
}

// TestUserLoginCmd_TenantFlagNamesTheLoginTenant proves `user login
// --tenant tenant-b` begins the ceremony in tenant B (go-xkms#2319).
func TestUserLoginCmd_TenantFlagNamesTheLoginTenant(t *testing.T) {
	mock := runTenantLogin(t, "tenant-b")
	if mock.begin.TenantID != "tenant-b" {
		t.Errorf("ceremony begun in tenant %q, want tenant-b", mock.begin.TenantID)
	}
}

// TestUserLoginCmd_NoTenantFlagLeavesTheServerDefault proves a login without
// --tenant names no tenant, so the server picks its default.
func TestUserLoginCmd_NoTenantFlagLeavesTheServerDefault(t *testing.T) {
	mock := runTenantLogin(t, "")
	if mock.begin.TenantID != "" {
		t.Errorf("ceremony begun in tenant %q, want none", mock.begin.TenantID)
	}
}

// TestLoginFinishRequest_CarriesTheBeginTenant proves the finish request is
// built with the same tenant the ceremony began in.
func TestLoginFinishRequest_CarriesTheBeginTenant(t *testing.T) {
	req := loginFinishRequest("sess", "alice@example.com", "tenant-b", []byte("{}"))
	if req.TenantID != "tenant-b" {
		t.Errorf("finish request tenant %q, want tenant-b", req.TenantID)
	}
	if req.SessionID != "sess" || req.Email != "alice@example.com" || req.AssertionJSON != "{}" {
		t.Errorf("finish request fields not copied: %+v", req)
	}
}
