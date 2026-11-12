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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errReferenceValuesStore = errors.New("reference-value store unavailable")

// referenceValuesCoRIM is the stand-in signed CoRIM the tests send; the CLI
// does not parse it.
var referenceValuesCoRIM = []byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26}

// mockReferenceValuesClient records the last reference-value request of each
// verb.
type mockReferenceValuesClient struct {
	mockBackendsClient

	fail   bool
	calls  int
	putReq *client.PutAttestationReferenceValuesRequest
	getReq *client.GetAttestationReferenceValuesRequest
	delReq *client.DeleteAttestationReferenceValuesRequest
}

func referenceValuesRecord(name string) *client.AttestationReferenceValues {
	return &client.AttestationReferenceValues{
		Name:        name,
		ManifestID:  "manifest-" + name,
		Profile:     "tag:example.com,2026:tpm",
		PCRIndices:  []uint32{0, 7},
		SignedCoRIM: referenceValuesCoRIM,
	}
}

func (m *mockReferenceValuesClient) PutAttestationReferenceValues(_ context.Context, req *client.PutAttestationReferenceValuesRequest) (*client.AttestationReferenceValues, error) {
	m.calls++
	m.putReq = req
	if m.fail {
		return nil, errReferenceValuesStore
	}
	rv := referenceValuesRecord(req.Name)
	rv.Repository = req.Repository
	return rv, nil
}

func (m *mockReferenceValuesClient) GetAttestationReferenceValues(_ context.Context, req *client.GetAttestationReferenceValuesRequest) (*client.AttestationReferenceValues, error) {
	m.calls++
	m.getReq = req
	if m.fail {
		return nil, errReferenceValuesStore
	}
	return referenceValuesRecord(req.Name), nil
}

func (m *mockReferenceValuesClient) ListAttestationReferenceValues(_ context.Context) (*client.ListAttestationReferenceValuesResponse, error) {
	m.calls++
	if m.fail {
		return nil, errReferenceValuesStore
	}
	return &client.ListAttestationReferenceValuesResponse{ReferenceValues: []*client.AttestationReferenceValues{
		referenceValuesRecord("rv1"),
		referenceValuesRecord("rv2"),
	}}, nil
}

func (m *mockReferenceValuesClient) DeleteAttestationReferenceValues(_ context.Context, req *client.DeleteAttestationReferenceValuesRequest) error {
	m.calls++
	m.delReq = req
	if m.fail {
		return errReferenceValuesStore
	}
	return nil
}

func writeReferenceValuesCoRIM(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rv.corim")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestAttestationReferenceValuesCmds_Registered(t *testing.T) {
	assert.True(t, hasSubcommand(attestationCmd, attestationReferenceValuesCmd))
	assert.Equal(t, "reference-values", attestationReferenceValuesCmd.Name())
	for _, verb := range []string{"put", "get", "list", "delete"} {
		cmd, _, err := attestationReferenceValuesCmd.Find([]string{verb})
		require.NoError(t, err, verb)
		assert.Equal(t, verb, cmd.Name())
		assert.True(t, hasSubcommand(attestationReferenceValuesCmd, cmd), verb)
	}
}

func TestAttestationReferenceValuesPutCmd(t *testing.T) {
	path := writeReferenceValuesCoRIM(t, referenceValuesCoRIM)

	mock := &mockReferenceValuesClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationReferenceValuesPutCmd, "text", []string{"rv1"},
		map[string]string{"corim": path})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "rv1")
	assert.Equal(t, &client.PutAttestationReferenceValuesRequest{Name: "rv1", SignedCoRIM: referenceValuesCoRIM}, mock.putReq)

	mock = &mockReferenceValuesClient{}
	_, _, code = runEndorsementCmd(t, mock, attestationReferenceValuesPutCmd, "text", []string{"rv1"},
		map[string]string{"corim": path, "repository": "oci.example/fw"})
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.PutAttestationReferenceValuesRequest{
		Name: "rv1", SignedCoRIM: referenceValuesCoRIM, Repository: "oci.example/fw",
	}, mock.putReq)
}

func TestAttestationReferenceValuesPutCmd_Refusals(t *testing.T) {
	empty := writeReferenceValuesCoRIM(t, nil)
	missing := filepath.Join(t.TempDir(), "absent.corim")
	cases := map[string]map[string]string{
		"no --corim":   nil,
		"empty file":   {"corim": empty},
		"missing file": {"corim": missing},
	}
	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			mock := &mockReferenceValuesClient{}
			_, _, code := runEndorsementCmd(t, mock, attestationReferenceValuesPutCmd, "text", []string{"rv1"}, flags)
			assert.NotEqual(t, -1, code)
			assert.NotEqual(t, 0, code)
			assert.Equal(t, 0, mock.calls)
		})
	}
}

func TestAttestationReferenceValuesGetCmd(t *testing.T) {
	mock := &mockReferenceValuesClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationReferenceValuesGetCmd, "text", []string{"rv1"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.GetAttestationReferenceValuesRequest{Name: "rv1"}, mock.getReq)
	assert.Contains(t, out, "rv1")
	assert.Contains(t, out, "manifest-rv1")
	assert.Contains(t, out, "0,7")
	assert.NotContains(t, out, string(referenceValuesCoRIM))

	mock = &mockReferenceValuesClient{}
	out, _, code = runEndorsementCmd(t, mock, attestationReferenceValuesGetCmd, "json", []string{"rv1"}, nil)
	assert.Equal(t, -1, code)
	var got client.AttestationReferenceValues
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "rv1", got.Name)
	assert.Equal(t, "manifest-rv1", got.ManifestID)
	assert.Equal(t, []uint32{0, 7}, got.PCRIndices)
}

func TestAttestationReferenceValuesListCmd(t *testing.T) {
	mock := &mockReferenceValuesClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationReferenceValuesListCmd, "text", nil, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, 1, mock.calls)
	assert.Contains(t, out, "rv1")
	assert.Contains(t, out, "rv2")

	mock = &mockReferenceValuesClient{}
	out, _, code = runEndorsementCmd(t, mock, attestationReferenceValuesListCmd, "json", nil, nil)
	assert.Equal(t, -1, code)
	var got client.ListAttestationReferenceValuesResponse
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Len(t, got.ReferenceValues, 2)
	assert.Equal(t, "rv1", got.ReferenceValues[0].Name)
	assert.Equal(t, "rv2", got.ReferenceValues[1].Name)
}

func TestAttestationReferenceValuesDeleteCmd(t *testing.T) {
	mock := &mockReferenceValuesClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationReferenceValuesDeleteCmd, "text", []string{"rv1"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "rv1")
	assert.Equal(t, &client.DeleteAttestationReferenceValuesRequest{Name: "rv1"}, mock.delReq)

	mock = &mockReferenceValuesClient{fail: true}
	_, stderr, code := runEndorsementCmd(t, mock, attestationReferenceValuesDeleteCmd, "text", []string{"rv1"}, nil)
	assert.NotEqual(t, -1, code)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, ErrDeleteAttestationReferenceValuesFailed.Error())
}
