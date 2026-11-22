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

// algorithms_run_test.go exercises "xkmsctl algorithms" against a mock
// BackendService, covering rendering and error handling.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errAlgorithmsBoom = errors.New("boom")

type mockAlgorithmsClient struct {
	mockBackendsClient

	resp *transport.AlgorithmsResponse
	err  error
}

func (m *mockAlgorithmsClient) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	return m.resp, m.err
}

func newAlgorithmsConfig(mock *mockAlgorithmsClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestAlgorithmsCmd_Success(t *testing.T) {
	withGlobalConfig(t, newAlgorithmsConfig(&mockAlgorithmsClient{
		resp: &transport.AlgorithmsResponse{
			Signing: []transport.AlgorithmInfo{
				{Algorithm: "ECDSA", Curves: []string{"P-256", "P-384"}, Backends: []string{"software", "tpm2"}},
				{Algorithm: "RSA", KeySizes: []int{2048, 4096}, Backends: []string{"software"}},
				{Algorithm: "ML-DSA-65", Backends: []string{"software"}, PostQuantum: true},
			},
			KeyEncapsulation: []transport.AlgorithmInfo{
				{Algorithm: "ML-KEM-768", Backends: []string{"software"}, PostQuantum: true},
			},
		},
	}))

	out := captureStdout(t, func() {
		algorithmsCmd.Run(algorithmsCmd, nil)
	})

	for _, want := range []string{
		"Signing:", "Key encapsulation:",
		"ECDSA", "curves=P-256,P-384",
		"RSA", "sizes=2048,4096",
		"ML-DSA-65", "[post-quantum]",
		"backends=software,tpm2",
		"ML-KEM-768",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

// TestAlgorithmsCmd_EmptyGroups proves an empty group renders explicitly
// rather than silently vanishing — "no KEM algorithms" and "the section was
// dropped" must not look the same to an operator.
func TestAlgorithmsCmd_EmptyGroups(t *testing.T) {
	withGlobalConfig(t, newAlgorithmsConfig(&mockAlgorithmsClient{
		resp: &transport.AlgorithmsResponse{},
	}))

	out := captureStdout(t, func() {
		algorithmsCmd.Run(algorithmsCmd, nil)
	})

	if !strings.Contains(out, "Signing:") || !strings.Contains(out, "Key encapsulation:") {
		t.Errorf("expected both group headings, got:\n%s", out)
	}
	if strings.Count(out, "(none)") != 2 {
		t.Errorf("expected both groups marked empty, got:\n%s", out)
	}
}

func TestAlgorithmsCmd_Error(t *testing.T) {
	withGlobalConfig(t, newAlgorithmsConfig(&mockAlgorithmsClient{err: errAlgorithmsBoom}))

	code := captureExit(t, func() {
		algorithmsCmd.Run(algorithmsCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}
