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

// custodian_run_test.go exercises the "xkmsctl custodian" command tree's Run
// closures (create, list, show, delete, add-member, remove-member,
// distribute), which read flags and delegate to the already-tested named
// functions. mockCustodianClient (defined in custodian_test.go) provides the
// client.Client surface.
package main

import (
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func newCustodianRunConfig(mock *mockCustodianClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func resetCustodianCreateFlags(t *testing.T) {
	t.Helper()
	_ = custodianCreateCmd.Flags().Set("name", "")
	_ = custodianCreateCmd.Flags().Set("purpose", "")
	_ = custodianCreateCmd.Flags().Set("threshold", "0")
	_ = custodianCreateCmd.Flags().Set("total", "0")
	_ = custodianCreateCmd.Flags().Set("tenant-id", "")
	_ = custodianCreateCmd.Flags().Set("id", "")
}

func TestCustodianCreateCmd_MissingName(t *testing.T) {
	resetCustodianCreateFlags(t)
	t.Cleanup(func() { resetCustodianCreateFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))

	code := captureExit(t, func() {
		custodianCreateCmd.Run(custodianCreateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianCreateCmd_InvalidThreshold(t *testing.T) {
	resetCustodianCreateFlags(t)
	t.Cleanup(func() { resetCustodianCreateFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))
	_ = custodianCreateCmd.Flags().Set("name", "Ops")
	_ = custodianCreateCmd.Flags().Set("threshold", "0")
	_ = custodianCreateCmd.Flags().Set("total", "0")

	code := captureExit(t, func() {
		custodianCreateCmd.Run(custodianCreateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianCreateCmd_ThresholdExceedsTotal(t *testing.T) {
	resetCustodianCreateFlags(t)
	t.Cleanup(func() { resetCustodianCreateFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))
	_ = custodianCreateCmd.Flags().Set("name", "Ops")
	_ = custodianCreateCmd.Flags().Set("threshold", "5")
	_ = custodianCreateCmd.Flags().Set("total", "3")

	code := captureExit(t, func() {
		custodianCreateCmd.Run(custodianCreateCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianCreateCmd_Success(t *testing.T) {
	resetCustodianCreateFlags(t)
	t.Cleanup(func() { resetCustodianCreateFlags(t) })
	mock := &mockCustodianClient{createGroupResp: &transport.CreateCustodianGroupResponse{
		Group: transport.CustodianGroupInfo{ID: "grp-1", Name: "Ops", Threshold: 3, Total: 5},
	}}
	withGlobalConfig(t, newCustodianRunConfig(mock))
	_ = custodianCreateCmd.Flags().Set("name", "Ops")
	_ = custodianCreateCmd.Flags().Set("purpose", "prod barrier")
	_ = custodianCreateCmd.Flags().Set("threshold", "3")
	_ = custodianCreateCmd.Flags().Set("total", "5")
	_ = custodianCreateCmd.Flags().Set("tenant-id", "acme")
	_ = custodianCreateCmd.Flags().Set("id", "grp-1")

	captureStdout(t, func() {
		custodianCreateCmd.Run(custodianCreateCmd, nil)
	})
}

func TestCustodianListCmd_Run(t *testing.T) {
	mock := &mockCustodianClient{listGroupsResp: &transport.ListCustodianGroupsResponse{
		Groups: []transport.CustodianGroupInfo{{ID: "grp-1", Name: "Ops"}},
	}}
	withGlobalConfig(t, newCustodianRunConfig(mock))

	captureStdout(t, func() {
		custodianListCmd.Run(custodianListCmd, nil)
	})
}

func TestCustodianShowCmd_MissingID(t *testing.T) {
	_ = custodianShowCmd.Flags().Set("id", "")
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))

	code := captureExit(t, func() {
		custodianShowCmd.Run(custodianShowCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianShowCmd_Success(t *testing.T) {
	mock := &mockCustodianClient{getGroupResp: &transport.GetCustodianGroupResponse{
		Group: transport.CustodianGroupInfo{ID: "grp-1", Name: "Ops", Threshold: 2, Total: 3},
	}}
	withGlobalConfig(t, newCustodianRunConfig(mock))
	_ = custodianShowCmd.Flags().Set("id", "grp-1")
	t.Cleanup(func() { _ = custodianShowCmd.Flags().Set("id", "") })

	captureStdout(t, func() {
		custodianShowCmd.Run(custodianShowCmd, nil)
	})
}

func TestCustodianDeleteCmd_MissingID(t *testing.T) {
	_ = custodianDeleteCmd.Flags().Set("id", "")
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))

	code := captureExit(t, func() {
		custodianDeleteCmd.Run(custodianDeleteCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianDeleteCmd_Success(t *testing.T) {
	mock := &mockCustodianClient{}
	withGlobalConfig(t, newCustodianRunConfig(mock))
	_ = custodianDeleteCmd.Flags().Set("id", "grp-1")
	t.Cleanup(func() { _ = custodianDeleteCmd.Flags().Set("id", "") })

	captureStdout(t, func() {
		custodianDeleteCmd.Run(custodianDeleteCmd, nil)
	})
}

func resetCustodianMemberFlags(t *testing.T) {
	t.Helper()
	_ = custodianAddMemberCmd.Flags().Set("group-id", "")
	_ = custodianAddMemberCmd.Flags().Set("user-id", "")
	_ = custodianAddMemberCmd.Flags().Set("username", "")
	_ = custodianAddMemberCmd.Flags().Set("method", "encrypted")
	_ = custodianRemoveMemberCmd.Flags().Set("group-id", "")
	_ = custodianRemoveMemberCmd.Flags().Set("user-id", "")
}

func TestCustodianAddMemberCmd_MissingGroupID(t *testing.T) {
	resetCustodianMemberFlags(t)
	t.Cleanup(func() { resetCustodianMemberFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))
	_ = custodianAddMemberCmd.Flags().Set("user-id", "user-1")

	code := captureExit(t, func() {
		custodianAddMemberCmd.Run(custodianAddMemberCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianAddMemberCmd_MissingUserID(t *testing.T) {
	resetCustodianMemberFlags(t)
	t.Cleanup(func() { resetCustodianMemberFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))
	_ = custodianAddMemberCmd.Flags().Set("group-id", "grp-1")

	code := captureExit(t, func() {
		custodianAddMemberCmd.Run(custodianAddMemberCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianAddMemberCmd_Success(t *testing.T) {
	resetCustodianMemberFlags(t)
	t.Cleanup(func() { resetCustodianMemberFlags(t) })
	mock := &mockCustodianClient{addMemberResp: &transport.AddCustodianMemberResponse{
		Member: transport.CustodianMemberInfo{UserID: "user-1", Username: "alice"},
	}}
	withGlobalConfig(t, newCustodianRunConfig(mock))
	_ = custodianAddMemberCmd.Flags().Set("group-id", "grp-1")
	_ = custodianAddMemberCmd.Flags().Set("user-id", "user-1")
	_ = custodianAddMemberCmd.Flags().Set("username", "alice")
	_ = custodianAddMemberCmd.Flags().Set("method", "manual")

	captureStdout(t, func() {
		custodianAddMemberCmd.Run(custodianAddMemberCmd, nil)
	})
}

func TestCustodianRemoveMemberCmd_MissingGroupID(t *testing.T) {
	resetCustodianMemberFlags(t)
	t.Cleanup(func() { resetCustodianMemberFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))
	_ = custodianRemoveMemberCmd.Flags().Set("user-id", "user-1")

	code := captureExit(t, func() {
		custodianRemoveMemberCmd.Run(custodianRemoveMemberCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianRemoveMemberCmd_MissingUserID(t *testing.T) {
	resetCustodianMemberFlags(t)
	t.Cleanup(func() { resetCustodianMemberFlags(t) })
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))
	_ = custodianRemoveMemberCmd.Flags().Set("group-id", "grp-1")

	code := captureExit(t, func() {
		custodianRemoveMemberCmd.Run(custodianRemoveMemberCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianRemoveMemberCmd_Success(t *testing.T) {
	resetCustodianMemberFlags(t)
	t.Cleanup(func() { resetCustodianMemberFlags(t) })
	mock := &mockCustodianClient{}
	withGlobalConfig(t, newCustodianRunConfig(mock))
	_ = custodianRemoveMemberCmd.Flags().Set("group-id", "grp-1")
	_ = custodianRemoveMemberCmd.Flags().Set("user-id", "user-1")

	captureStdout(t, func() {
		custodianRemoveMemberCmd.Run(custodianRemoveMemberCmd, nil)
	})
}

func TestCustodianDistributeCmd_MissingGroupID(t *testing.T) {
	_ = custodianDistributeCmd.Flags().Set("group-id", "")
	withGlobalConfig(t, newCustodianRunConfig(&mockCustodianClient{}))

	code := captureExit(t, func() {
		custodianDistributeCmd.Run(custodianDistributeCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestCustodianDistributeCmd_Success(t *testing.T) {
	mock := &mockCustodianClient{distributeResp: &transport.DistributeSharesResponse{Distributed: 5}}
	withGlobalConfig(t, newCustodianRunConfig(mock))
	_ = custodianDistributeCmd.Flags().Set("group-id", "grp-1")
	t.Cleanup(func() { _ = custodianDistributeCmd.Flags().Set("group-id", "") })

	captureStdout(t, func() {
		custodianDistributeCmd.Run(custodianDistributeCmd, nil)
	})
}
