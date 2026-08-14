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

// barrier_recovery_ext_test.go covers the barrier recovery delete-keys and
// root-token subcommands added in CLI wave 2.
package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errBarrierRecoveryExtBoom = errors.New("boom")

func (m *mockBarrierClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	m.deleteKeysCalled = true
	return m.deleteKeysErr
}

func (m *mockBarrierClient) BarrierGenerateRootToken(_ context.Context, req *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	m.rootTokenReq = req
	return m.rootTokenResp, m.rootTokenErr
}

func TestRunBarrierRecoveryDeleteKeysCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryDeleteKeysCmd
	cmd.SetOut(new(bytes.Buffer))
	if err := runBarrierRecoveryDeleteKeysCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.deleteKeysCalled {
		t.Error("BarrierDeleteRecoveryKeys was not called")
	}
}

func TestRunBarrierRecoveryDeleteKeysCmd_Error(t *testing.T) {
	resetBarrierFlags(t)
	mock := &mockBarrierClient{deleteKeysErr: errBarrierRecoveryExtBoom}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryDeleteKeysCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierRecoveryDeleteKeysCmd(cmd, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var typed *WrappedError
	if !errors.As(err, &typed) || !errors.Is(err, ErrDeleteRecoveryKeysFailed) {
		t.Fatalf("expected wrapped ErrDeleteRecoveryKeysFailed, got %v", err)
	}
}

func TestRunBarrierRecoveryRootTokenCmd_Success(t *testing.T) {
	resetBarrierFlags(t)
	barrierRecoveryShs = []string{"s-a", "s-b", "s-c"}
	mock := &mockBarrierClient{rootTokenResp: &transport.BarrierRootTokenResponse{
		Token: "root-xyz", CreatedAt: "2026-01-01T00:00:00Z",
	}}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryRootTokenCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	if err := runBarrierRecoveryRootTokenCmd(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.rootTokenReq == nil || len(mock.rootTokenReq.Shares) != 3 {
		t.Errorf("root token req = %+v, want 3 shares", mock.rootTokenReq)
	}
}

func TestRunBarrierRecoveryRootTokenCmd_MissingShares(t *testing.T) {
	resetBarrierFlags(t)
	mock := &mockBarrierClient{}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryRootTokenCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierRecoveryRootTokenCmd(cmd, nil)
	var typed *BarrierRecoverySharesRequiredError
	if !errors.As(err, &typed) {
		t.Fatalf("expected BarrierRecoverySharesRequiredError, got %T: %v", err, err)
	}
}

func TestRunBarrierRecoveryRootTokenCmd_Error(t *testing.T) {
	resetBarrierFlags(t)
	barrierRecoveryShs = []string{"s-a"}
	mock := &mockBarrierClient{rootTokenErr: errBarrierRecoveryExtBoom}
	withGlobalConfig(t, newBarrierMockConfig(mock))

	cmd := barrierRecoveryRootTokenCmd
	cmd.SetOut(new(bytes.Buffer))
	err := runBarrierRecoveryRootTokenCmd(cmd, nil)
	if !errors.Is(err, ErrGenerateRootTokenFailed) {
		t.Fatalf("expected ErrGenerateRootTokenFailed, got %v", err)
	}
}
