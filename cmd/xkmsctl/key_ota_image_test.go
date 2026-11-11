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
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

const otaBadBoard = "Bad--Board"

var (
	errOTABoard     = errors.New("keystore: invalid board id")
	errOTAAlgorithm = errors.New("keystore: OTA image keys are ES256 only")
)

// mockOTAImageClient answers the OTA image-key calls the way xkmsd does: a
// malformed board id or a non-ES256 algorithm is refused, any other board
// gets a response naming its key. It records the last request it received.
type mockOTAImageClient struct {
	mockBackendsClient

	reissue bool
	keyReq  *client.OTAImageKeyRequest
	signReq *client.OTAImageSignRequest
}

func (m *mockOTAImageClient) validate(board, algorithm string) error {
	if algorithm != "" && algorithm != "ES256" {
		return errOTAAlgorithm
	}
	if board == otaBadBoard {
		return errOTABoard
	}
	return nil
}

func (m *mockOTAImageClient) CreateOTAImageKey(_ context.Context, req *client.OTAImageKeyRequest) (*client.GenerateKeyResponse, error) {
	m.keyReq = req
	if err := m.validate(req.BoardID, req.Algorithm); err != nil {
		return nil, err
	}
	return &client.GenerateKeyResponse{KeyID: "ota-image-" + req.BoardID}, nil
}

func (m *mockOTAImageClient) RotateOTAImageKey(_ context.Context, req *client.OTAImageKeyRequest) (*client.RotateKeyResponse, error) {
	m.keyReq = req
	if err := m.validate(req.BoardID, req.Algorithm); err != nil {
		return nil, err
	}
	return &client.RotateKeyResponse{KeyID: "ota-image-" + req.BoardID, KeyVersion: 2, CertificateReissueRequired: m.reissue}, nil
}

func (m *mockOTAImageClient) SignOTAImage(_ context.Context, req *client.OTAImageSignRequest) (*client.SignResponse, error) {
	m.signReq = req
	if err := m.validate(req.BoardID, ""); err != nil {
		return nil, err
	}
	return &client.SignResponse{Signature: []byte("sig"), KeyVersion: 2}, nil
}

// runOTAImageCmd runs cmd against mock and returns its stdout, stderr and
// exit code (-1 when it did not exit).
func runOTAImageCmd(t *testing.T, mock client.Client, cmd *cobra.Command, args []string, flags map[string]string) (string, string, int) {
	t.Helper()
	resetCmdFlags(t, cmd)
	t.Cleanup(func() { resetCmdFlags(t, cmd) })
	withGlobalConfig(t, &Config{
		OutputFormat:  "text",
		Backend:       "software",
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	})
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	code := -1
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			code = captureExit(t, func() { cmd.Run(cmd, args) })
		})
	})
	return out, stderr, code
}

func writeOTAImage(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.bin")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestKeyOTAImageCreateCmd(t *testing.T) {
	mock := &mockOTAImageClient{}
	out, _, code := runOTAImageCmd(t, mock, keyOTAImageCreateCmd, []string{"cm4"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "ota-image-cm4")
	require.NotNil(t, mock.keyReq)
	assert.Equal(t, &client.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", Algorithm: "ES256"}, mock.keyReq)
}

func TestKeyOTAImageRotateCmd(t *testing.T) {
	mock := &mockOTAImageClient{}
	out, _, code := runOTAImageCmd(t, mock, keyOTAImageRotateCmd, []string{"cm4"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "ota-image-cm4 (current version 2)")
	assert.NotContains(t, out, "re-issue")
	assert.Equal(t, &client.OTAImageKeyRequest{Backend: "software", BoardID: "cm4", Algorithm: "ES256"}, mock.keyReq)

	mock.reissue = true
	out, _, code = runOTAImageCmd(t, mock, keyOTAImageRotateCmd, []string{"cm4"}, nil)
	assert.Equal(t, -1, code, "a certificate to re-issue is a warning, not a failure")
	assert.Contains(t, out, "re-issue it for version 2")
}

func TestKeyOTAImageSignCmd(t *testing.T) {
	mock := &mockOTAImageClient{}
	image := writeOTAImage(t, "image")

	out, _, code := runOTAImageCmd(t, mock, keyOTAImageSignCmd, []string{"cm4", image}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, base64.StdEncoding.EncodeToString([]byte("sig")))
	assert.Equal(t, &client.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("image")}, mock.signReq)

	_, _, code = runOTAImageCmd(t, mock, keyOTAImageSignCmd, []string{"cm4", image}, map[string]string{"digest": "true"})
	assert.Equal(t, -1, code)
	assert.True(t, mock.signReq.DataIsDigest, "--digest sends the file as a precomputed digest")
}

func TestKeyOTAImageSignCmd_MissingImageFile(t *testing.T) {
	mock := &mockOTAImageClient{}
	_, stderr, code := runOTAImageCmd(t, mock, keyOTAImageSignCmd, []string{"cm4", filepath.Join(t.TempDir(), "absent")}, nil)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrReadDataFileFailed.Error())
	assert.Nil(t, mock.signReq, "nothing is sent when the image cannot be read")
}

func TestKeyOTAImageCmds_InvalidBoard(t *testing.T) {
	image := writeOTAImage(t, "image")
	cases := map[string]struct {
		cmd     *cobra.Command
		args    []string
		failure error
	}{
		"create": {keyOTAImageCreateCmd, []string{otaBadBoard}, ErrCreateOTAImageKeyFailed},
		"rotate": {keyOTAImageRotateCmd, []string{otaBadBoard}, ErrRotateOTAImageKeyFailed},
		"sign":   {keyOTAImageSignCmd, []string{otaBadBoard, image}, ErrSignOTAImageFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, stderr, code := runOTAImageCmd(t, &mockOTAImageClient{}, tc.cmd, tc.args, nil)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.failure.Error())
			assert.Contains(t, stderr, errOTABoard.Error())
			assert.Empty(t, out)
		})
	}
}

func TestKeyOTAImageCmds_NonES256Algorithm(t *testing.T) {
	cases := map[string]struct {
		cmd     *cobra.Command
		failure error
	}{
		"create": {keyOTAImageCreateCmd, ErrCreateOTAImageKeyFailed},
		"rotate": {keyOTAImageRotateCmd, ErrRotateOTAImageKeyFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mock := &mockOTAImageClient{}
			out, stderr, code := runOTAImageCmd(t, mock, tc.cmd, []string{"cm4"}, map[string]string{"algorithm": "RS256"})
			assert.Equal(t, 1, code)
			assert.Equal(t, "RS256", mock.keyReq.Algorithm, "the algorithm reaches xkmsd, which owns the ES256 rule")
			assert.Contains(t, stderr, tc.failure.Error())
			assert.Contains(t, stderr, errOTAAlgorithm.Error())
			assert.Empty(t, out)
		})
	}
}
