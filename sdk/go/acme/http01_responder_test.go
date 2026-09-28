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

package trustedca

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// loopbackChallengeClient returns an ACMEChallengeClient that may reach the
// loopback responders these tests start. Production clients leave
// AllowPrivateTargets false.
func loopbackChallengeClient() *ACMEChallengeClient {
	return NewACMEChallengeClient(ACMEChallengeClientConfig{AllowPrivateTargets: true})
}

// The SDK surface is what a consumer reaching go-xkms only through its SDK
// module can call. These tests exercise it through the exported names alone,
// so a re-export that stops resolving is caught here rather than downstream.

func TestNewHTTP01Responder_ServesTheKeyAuthorization(t *testing.T) {
	const (
		token   = "sdk-token"
		keyAuth = "sdk-token.thumbprint"
	)

	responder, err := NewHTTP01Responder(HTTP01ResponderConfig{
		Addr:    "127.0.0.1:0",
		KeyAuth: keyAuth,
	})
	if err != nil {
		t.Fatalf("NewHTTP01Responder: %v", err)
	}
	defer func() { _ = responder.Close() }()

	_, port, err := net.SplitHostPort(responder.Addr().String())
	if err != nil {
		t.Fatalf("split responder address: %v", err)
	}

	// ACMEVerifyHTTP01 is the ACME server half of the same challenge, so a
	// successful verification proves the two exported halves agree.
	if err := ACMEVerifyHTTP01(loopbackChallengeClient(), "127.0.0.1", port, token, keyAuth); err != nil {
		t.Fatalf("ACMEVerifyHTTP01 against the SDK responder: %v", err)
	}

	if got := responder.KeyAuth(); got != keyAuth {
		t.Errorf("KeyAuth = %q, want %q", got, keyAuth)
	}
	if err := responder.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestNewHTTP01Responder_BindErrorIsTypedAndExported(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	responder, err := NewHTTP01Responder(HTTP01ResponderConfig{
		Addr:    occupied.Addr().String(),
		KeyAuth: "sdk-token.thumbprint",
	})
	if responder != nil {
		_ = responder.Close()
		t.Fatal("NewHTTP01Responder bound a port that was already in use")
	}

	// The alias must preserve type identity, or errors.As on the SDK name
	// would never match an error produced inside the implementation package.
	var bindErr HTTP01ResponderBindError
	if !errors.As(err, &bindErr) {
		t.Fatalf("error is %T (%v), want HTTP01ResponderBindError", err, err)
	}

	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("bind error does not unwrap to *net.OpError: %v", err)
	}
}

func TestNewHTTP01Responder_ConfigErrorIsTypedAndExported(t *testing.T) {
	testCases := []struct {
		name  string
		cfg   HTTP01ResponderConfig
		field string
	}{
		{"missing address", HTTP01ResponderConfig{KeyAuth: "sdk-token.thumbprint"}, "Addr"},
		{"missing key authorization", HTTP01ResponderConfig{Addr: "127.0.0.1:0"}, "KeyAuth"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			responder, err := NewHTTP01Responder(tc.cfg)
			if responder != nil {
				_ = responder.Close()
				t.Fatal("NewHTTP01Responder accepted an incomplete configuration")
			}

			var configErr HTTP01ResponderConfigError
			if !errors.As(err, &configErr) {
				t.Fatalf("error is %T (%v), want HTTP01ResponderConfigError", err, err)
			}
			if configErr.Field != tc.field {
				t.Errorf("Field = %q, want %q", configErr.Field, tc.field)
			}
		})
	}
}

// TestNewHTTP01Responder_ChallengeSetupSeam drives the responder through the
// ACMECertificateRequest callbacks it exists to fill, with the signatures the
// ACME client actually calls.
func TestNewHTTP01Responder_ChallengeSetupSeam(t *testing.T) {
	const keyAuth = "seam-token.thumbprint"

	var responder *HTTP01Responder

	req := ACMECertificateRequest{
		AuthzType:     ACMEAuthzTypeDNS,
		AuthzValue:    "node.example.test",
		ChallengeType: ACMEChallengeTypeHTTP01,
		ChallengeSetup: func(challengeType, token, keyAuth string) error {
			r, err := NewHTTP01Responder(HTTP01ResponderConfig{
				Addr:    "127.0.0.1:0",
				KeyAuth: keyAuth,
			})
			if err != nil {
				return err
			}
			responder = r
			return nil
		},
		ChallengeCleanup: func(challengeType string) {
			if responder != nil {
				_ = responder.Close()
			}
		},
	}

	if err := req.ChallengeSetup(req.ChallengeType, "seam-token", keyAuth); err != nil {
		t.Fatalf("ChallengeSetup: %v", err)
	}
	if responder == nil {
		t.Fatal("ChallengeSetup did not install a responder")
	}

	_, port, err := net.SplitHostPort(responder.Addr().String())
	if err != nil {
		t.Fatalf("split responder address: %v", err)
	}
	if err := ACMEVerifyHTTP01(loopbackChallengeClient(), "127.0.0.1", port, "seam-token", keyAuth); err != nil {
		t.Errorf("verification of the provisioned challenge: %v", err)
	}

	req.ChallengeCleanup(req.ChallengeType)

	if conn, err := net.Dial("tcp", responder.Addr().String()); err == nil {
		_ = conn.Close()
		t.Error("ChallengeCleanup left the responder listening")
	}
}

// TestNewHTTP01Responder_ConcurrentOrders is the property the process-global
// Setup could not offer: two orders provisioned at the same time, each served
// correctly.
func TestNewHTTP01Responder_ConcurrentOrders(t *testing.T) {
	orders := []struct {
		token   string
		keyAuth string
	}{
		{"order-a", "order-a.thumbprint-a"},
		{"order-b", "order-b.thumbprint-b"},
		{"order-c", "order-c.thumbprint-c"},
	}

	responders := make([]*HTTP01Responder, len(orders))
	for i, order := range orders {
		responder, err := NewHTTP01Responder(HTTP01ResponderConfig{
			Addr:    "127.0.0.1:0",
			KeyAuth: order.keyAuth,
		})
		if err != nil {
			t.Fatalf("NewHTTP01Responder for %s: %v", order.token, err)
		}
		defer func() { _ = responder.Close() }()
		responders[i] = responder
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(orders))

	for i, order := range orders {
		wg.Add(1)
		go func(responder *HTTP01Responder, token, keyAuth string) {
			defer wg.Done()
			_, port, err := net.SplitHostPort(responder.Addr().String())
			if err != nil {
				errs <- err
				return
			}
			if err := ACMEVerifyHTTP01(loopbackChallengeClient(), "127.0.0.1", port, token, keyAuth); err != nil {
				errs <- err
			}
		}(responders[i], order.token, order.keyAuth)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent order failed verification: %v", err)
	}
}

func TestHTTP01ResponderDefaults_AreExported(t *testing.T) {
	if DefaultHTTP01ResponderShutdownTimeout <= 0 {
		t.Error("DefaultHTTP01ResponderShutdownTimeout must be positive")
	}
	if DefaultHTTP01ResponderReadTimeout <= 0 {
		t.Error("DefaultHTTP01ResponderReadTimeout must be positive")
	}
	if DefaultHTTP01ResponderWriteTimeout <= 0 {
		t.Error("DefaultHTTP01ResponderWriteTimeout must be positive")
	}
	if DefaultHTTP01ResponderIdleTimeout <= 0 {
		t.Error("DefaultHTTP01ResponderIdleTimeout must be positive")
	}
}
