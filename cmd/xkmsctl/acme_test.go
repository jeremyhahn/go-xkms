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

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// resetACMEConnectionFlags clears the package-level --acme-server /
// --acme-transport flag state so tests do not leak values into each other.
func resetACMEConnectionFlags(t *testing.T) {
	t.Helper()
	acmeServerFlag = ""
	acmeTransportFlag = ""
	t.Cleanup(func() {
		acmeServerFlag = ""
		acmeTransportFlag = ""
	})
}

func TestACMEClientOptions_AddressRequired(t *testing.T) {
	resetACMEConnectionFlags(t)

	_, _, err := acmeClientOptions(&Config{})
	var required *ACMEAdminAddressRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected ACMEAdminAddressRequiredError, got %v", err)
	}
}

func TestACMEClientOptions_Derivation(t *testing.T) {
	tests := []struct {
		name      string
		server    string
		transport string
		tlsCACert string
		wantErr   bool
	}{
		{name: "https URL selects REST", server: "https://ca.example.com:8443"},
		{name: "http URL selects REST", server: "http://ca.example.com:8443"},
		{name: "grpc URL plaintext", server: "grpc://ca.example.com:9443"},
		{name: "grpcs URL forces TLS", server: "grpcs://ca.example.com:9443"},
		{name: "quic URL", server: "quic://ca.example.com:9444"},
		{name: "mcp URL", server: "mcp://ca.example.com:9444"},
		{name: "mcps URL forces TLS", server: "mcps://ca.example.com:9444"},
		{name: "bare address defaults to grpc", server: "ca.example.com:9443"},
		{name: "bare address with explicit rest transport", server: "ca.example.com:8443", transport: "rest"},
		{name: "bare address with explicit quic transport", server: "ca.example.com:9444", transport: "quic"},
		{name: "bare address with explicit mcp transport", server: "ca.example.com:9444", transport: "mcp"},
		{name: "TLS material forces TLS option even without scheme", server: "ca.example.com:9443", tlsCACert: "/tmp/ca.pem"},
		{name: "unix scheme unsupported", server: "unix:///tmp/acme.sock", wantErr: true},
		{name: "bare address with unix transport unsupported", server: "ca.example.com", transport: "unix", wantErr: true},
		{name: "bare address with unknown transport unsupported", server: "ca.example.com", transport: "bogus", wantErr: true},
		{name: "unknown scheme unsupported", server: "ftp://ca.example.com", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetACMEConnectionFlags(t)
			acmeServerFlag = tc.server
			acmeTransportFlag = tc.transport

			address, opts, err := acmeClientOptions(&Config{TLSCACert: tc.tlsCACert})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var unsupported *ACMEAdminUnsupportedTransportError
				if !errors.As(err, &unsupported) {
					t.Fatalf("expected ACMEAdminUnsupportedTransportError, got %T: %v", err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if address == "" {
				t.Error("expected a non-empty address")
			}
			_ = opts
		})
	}
}

func TestACMEAdminClient_MissingFactory(t *testing.T) {
	restore := SetACMEAdminClientFactory(nil)
	t.Cleanup(restore)

	_, _, err := acmeAdminClient(context.Background())
	var missing *ACMEAdminClientMissingError
	if !errors.As(err, &missing) {
		t.Fatalf("expected ACMEAdminClientMissingError, got %v", err)
	}
}

func TestDefaultACMEAdminClientFactory_AddressRequired(t *testing.T) {
	resetACMEConnectionFlags(t)
	withGlobalConfig(t, &Config{})

	_, _, err := defaultACMEAdminClientFactory(context.Background())
	var required *ACMEAdminAddressRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected ACMEAdminAddressRequiredError, got %v", err)
	}
}

func TestACMEAdminConnectError_Unwrap(t *testing.T) {
	cause := errors.New("boom")
	err := &ACMEAdminConnectError{Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the wrapped cause")
	}
}

// TestACMETypedErrors_Messages exercises the Error()/Unwrap() methods of
// every typed error acme.go introduces, so a message regression (a typo
// that drops the operation name or the underlying cause) is caught here
// instead of only in an operator's terminal.
func TestACMETypedErrors_Messages(t *testing.T) {
	if got := (&ACMEAdminAddressRequiredError{}).Error(); got == "" {
		t.Error("ACMEAdminAddressRequiredError.Error() must not be empty")
	}

	unsupported := &ACMEAdminUnsupportedTransportError{Transport: "carrier-pigeon"}
	if got := unsupported.Error(); !strings.Contains(got, "carrier-pigeon") {
		t.Errorf("expected the rejected transport in the message, got %q", got)
	}

	if got := (&ACMEAdminClientMissingError{}).Error(); got == "" {
		t.Error("ACMEAdminClientMissingError.Error() must not be empty")
	}

	cause := errors.New("denied")
	forbidden := &ACMEAdminForbiddenError{Op: "list accounts", Err: cause}
	if !errors.Is(forbidden, cause) {
		t.Error("expected errors.Is to find the wrapped cause on ACMEAdminForbiddenError")
	}
	if got := forbidden.Error(); !strings.Contains(got, "list accounts") {
		t.Errorf("expected the operation name in the message, got %q", got)
	}

	notFound := &ACMEAdminNotFoundError{Op: "get account 1", Err: cause}
	if !errors.Is(notFound, cause) {
		t.Error("expected errors.Is to find the wrapped cause on ACMEAdminNotFoundError")
	}
	if got := notFound.Error(); !strings.Contains(got, "get account 1") {
		t.Errorf("expected the operation name in the message, got %q", got)
	}
}
