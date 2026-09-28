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

package validation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// TestIsTargetRejected_ClientRefusals verifies that the failures the client
// decides by itself -- an invalid target and a reserved address refused at
// dial time -- are reported as rejections, as returned by a real Get.
func TestIsTargetRejected_ClientRefusals(t *testing.T) {
	client := NewClient(Config{})
	for name, target := range map[string]Target{
		"invalid host":     {Host: "169.254.169.254/latest/meta-data", Port: "80"},
		"invalid port":     {Host: "example.com", Port: "0"},
		"reserved address": {Host: "127.0.0.1", Port: "80", Path: "/"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client.Get(context.Background(), target)
			if !IsTargetRejected(err) {
				t.Fatalf("IsTargetRejected(%v) = false, want true", err)
			}
			if !IsTargetRejected(fmt.Errorf("verifier: %w", err)) {
				t.Fatalf("IsTargetRejected must see a rejection through wrapping")
			}
		})
	}
}

// TestIsTargetRejected_ContactedTargetFailures verifies that a failure to
// reach a target the client did try to contact is not a rejection, nor is
// anything that is not a validation failure.
func TestIsTargetRejected_ContactedTargetFailures(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", listener.Addr(), err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	_, connErr := NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: "127.0.0.1", Port: port, Path: "/"})
	requireKind(t, connErr, KindConnection)

	for name, err := range map[string]error{
		"connection failure":   connErr,
		"status":               &Error{Kind: KindStatus, Err: &StatusError{StatusCode: 404}},
		"response too large":   &Error{Kind: KindResponseTooLarge},
		"redirect":             &Error{Kind: KindRedirect},
		"nil client":           ErrNilClient,
		"non-validation error": errors.New("key authorization mismatch"),
		"nil":                  nil,
	} {
		t.Run(name, func(t *testing.T) {
			if IsTargetRejected(err) {
				t.Fatalf("IsTargetRejected(%v) = true, want false", err)
			}
		})
	}
}
