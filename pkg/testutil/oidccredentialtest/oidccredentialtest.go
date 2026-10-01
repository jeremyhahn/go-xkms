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

// Package oidccredentialtest holds the fixtures of tests that exercise the
// OIDC credential API (transport.OIDCCredentialService) without a provider.
// It imports only pkg/api/transport, so every transport's tests can use it;
// its offline sub-package builds a credential service for the server-side
// tests.
package oidccredentialtest

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Issuer is the issuer of Config. Nothing is ever requested from it: Config
// is an import-only provider.
const Issuer = "https://idp.example.test"

// Config returns the configuration of a provider whose tokens are imported
// and never refreshed, so a credential created with it reaches no network:
// a refresh of it is refused as a failed precondition, and a device login
// as an invalid configuration (it has no device endpoint).
func Config() transport.OIDCCredentialConfig {
	return transport.OIDCCredentialConfig{Issuer: Issuer, NoRefresh: true}
}

// Tokens returns tokens valid for an hour.
func Tokens(accessToken string) *transport.OIDCCredentialTokens {
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	return &transport.OIDCCredentialTokens{AccessToken: accessToken, TokenType: "Bearer", ExpiresAt: &expires}
}

// Calls returns one call of every OIDC credential method of svc, by method
// name, each returning only its error.
func Calls(ctx context.Context, svc transport.OIDCCredentialService) map[string]func() error {
	ref := transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: "ci"}
	return map[string]func() error{
		"OIDCCredentialCreate": func() error {
			_, err := svc.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: ref, Config: Config()})
			return err
		},
		"OIDCCredentialImport": func() error {
			_, err := svc.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{OIDCCredentialRef: ref, Tokens: *Tokens("at")})
			return err
		},
		"OIDCCredentialGet": func() error { _, err := svc.OIDCCredentialGet(ctx, &ref); return err },
		"OIDCCredentialList": func() error {
			_, err := svc.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{})
			return err
		},
		"OIDCCredentialDelete":         func() error { return svc.OIDCCredentialDelete(ctx, &ref) },
		"OIDCCredentialRefresh":        func() error { _, err := svc.OIDCCredentialRefresh(ctx, &ref); return err },
		"OIDCCredentialGetAccessToken": func() error { _, err := svc.OIDCCredentialGetAccessToken(ctx, &ref); return err },
		"OIDCCredentialDeviceStart":    func() error { _, err := svc.OIDCCredentialDeviceStart(ctx, &ref); return err },
		"OIDCCredentialDevicePoll":     func() error { _, err := svc.OIDCCredentialDevicePoll(ctx, &ref); return err },
	}
}
