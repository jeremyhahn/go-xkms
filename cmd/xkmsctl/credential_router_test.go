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

// credential_router_test.go drives the credential verbs against xkmsd's real
// REST route table rather than a stub handler, so the CLI's request paths and
// the registered routes cannot drift apart again (go-xkms#1464).
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// credentialRouterValue is the value every test credential is submitted
// with; the CLI must never print it.
const credentialRouterValue = "s3cr3t-credential-value"

// newCredentialRouterServer serves the real REST router (rest.NewServer, with
// a mock key store only because the server requires one backend) over a
// manual credential service that has been given submitted, and points the CLI at it.
func newCredentialRouterServer(t *testing.T, submitted ...string) {
	t.Helper()
	creds, err := credentialspkg.New(&credentialspkg.Config{Strategy: credentialspkg.StrategyManual}, nil, nil, nil)
	if err != nil {
		t.Fatalf("credentials.New: %v", err)
	}
	for _, name := range submitted {
		if err := creds.SubmitCredential(context.Background(), name, []byte(credentialRouterValue)); err != nil {
			t.Fatalf("SubmitCredential(%q): %v", name, err)
		}
	}
	svc := &xkms.XKMSService{}
	svc.SetCredentialService(creds)

	api, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"software": xkmsmocks.NewMockKeyStore()},
		XKMSService:   svc,
	})
	if err != nil {
		t.Fatalf("rest.NewServer: %v", err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)

	oldConfig := globalConfig
	oldFactory := serverHTTPClientFactory
	t.Cleanup(func() {
		globalConfig = oldConfig
		serverHTTPClientFactory = oldFactory
	})
	globalConfig = &Config{Server: server.URL, OutputFormat: "text"}
	serverHTTPClientFactory = func(cfg *Config) (*http.Client, error) {
		return server.Client(), nil
	}
}

func TestRunCredentialList_RealRouterNoCredentials(t *testing.T) {
	newCredentialRouterServer(t)

	out := captureStdout(t, func() {
		if err := runCredentialList(credentialListCmd, nil); err != nil {
			t.Fatalf("runCredentialList: %v", err)
		}
	})

	if !strings.Contains(out, "No credentials submitted.") {
		t.Errorf("expected the empty-list statement, got: %q", out)
	}
}
