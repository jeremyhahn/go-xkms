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

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errOTATestBoardID is the error the fake returns for a malformed board id,
// as xkmsd does.
var errOTATestBoardID = errors.New("invalid board id")

// otaImageSDKClient is the SDK fake extended with the OTA image-key methods:
// it records each request and answers like xkmsd, refusing the board id
// "CM4!" and failing every call when err is set.
type otaImageSDKClient struct {
	mockSDKClient
	err     error
	keyReq  *transport.OTAImageKeyRequest
	signReq *transport.OTAImageSignRequest
	reissue bool
}

func (c *otaImageSDKClient) CreateOTAImageKey(_ context.Context, req *transport.OTAImageKeyRequest) (*transport.GenerateKeyResponse, error) {
	c.keyReq = req
	if err := c.fail(req.BoardID); err != nil {
		return nil, err
	}
	return &transport.GenerateKeyResponse{KeyID: "ota-image-" + req.BoardID}, nil
}

func (c *otaImageSDKClient) RotateOTAImageKey(_ context.Context, req *transport.OTAImageKeyRequest) (*transport.RotateKeyResponse, error) {
	c.keyReq = req
	if err := c.fail(req.BoardID); err != nil {
		return nil, err
	}
	return &transport.RotateKeyResponse{
		Success:                    true,
		KeyID:                      "ota-image-" + req.BoardID,
		KeyVersion:                 2,
		CertificateReissueRequired: c.reissue,
	}, nil
}

func (c *otaImageSDKClient) SignOTAImage(_ context.Context, req *transport.OTAImageSignRequest) (*transport.SignResponse, error) {
	c.signReq = req
	if err := c.fail(req.BoardID); err != nil {
		return nil, err
	}
	return &transport.SignResponse{Signature: []byte("signature"), KeyVersion: 2}, nil
}

func (c *otaImageSDKClient) fail(boardID string) error {
	if c.err != nil {
		return c.err
	}
	if boardID == "CM4!" {
		return errOTATestBoardID
	}
	return nil
}

// useOTAImageClient serves the OTA image-key verbs from client for one test.
func useOTAImageClient(t *testing.T, client transport.Client, err error) {
	t.Helper()
	previous := otaImageClientFactory
	otaImageClientFactory = func(*cobra.Command) (transport.Client, error) { return client, err }
	t.Cleanup(func() { otaImageClientFactory = previous })
}

// refuseOTAImageClient fails the test if a verb reaches xkmsd.
func refuseOTAImageClient(t *testing.T) {
	t.Helper()
	previous := otaImageClientFactory
	otaImageClientFactory = func(*cobra.Command) (transport.Client, error) {
		t.Fatal("the verb must not connect to xkmsd")
		return nil, nil
	}
	t.Cleanup(func() { otaImageClientFactory = previous })
}

// captureOTAImageOutput sends cmd's stdout and stderr to buffers for one test.
func captureOTAImageOutput(t *testing.T, cmd *cobra.Command) (stdout, stderr *bytes.Buffer) {
	t.Helper()
	stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	t.Cleanup(func() {
		cmd.SetOut(nil)
		cmd.SetErr(nil)
	})
	return stdout, stderr
}

// useOTABackend selects the xkmsd backend for one test.
func useOTABackend(t *testing.T, backend string) {
	t.Helper()
	previous := viper.Get("backend")
	viper.Set("backend", backend)
	t.Cleanup(func() { viper.Set("backend", previous) })
}

// writeOTAImage writes an image file and returns its path.
func writeOTAImage(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "firmware.bin")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func TestKeyOTAImageCommandTree(t *testing.T) {
	found, _, err := RootCmd.Find([]string{"key", "ota-image", "sign"})
	require.NoError(t, err)
	assert.Equal(t, keyOTAImageSignCmd, found)
	assert.NotNil(t, keyOTAImageCreateCmd.Flags().Lookup("algorithm"))
	assert.NotNil(t, keyOTAImageRotateCmd.Flags().Lookup("algorithm"))
	assert.NotNil(t, keyOTAImageSignCmd.Flags().Lookup("digest"))
	assert.NotNil(t, keyCmd.PersistentFlags().Lookup(tlsCAFlagName))
}

func TestRunKeyOTAImageCreate_Success(t *testing.T) {
	client := &otaImageSDKClient{}
	useOTAImageClient(t, client, nil)
	useOTABackend(t, "tpm2")
	stdout, _ := captureOTAImageOutput(t, keyOTAImageCreateCmd)

	require.NoError(t, runKeyOTAImageCreate(keyOTAImageCreateCmd, []string{"cm4"}))

	assert.Equal(t, &transport.OTAImageKeyRequest{Backend: "tpm2", BoardID: "cm4", Algorithm: "ES256"}, client.keyReq)
	assert.Equal(t, "Successfully created OTA image key: ota-image-cm4\n", stdout.String())
	assert.True(t, client.closed)
}

func TestRunKeyOTAImageCreate_JSON(t *testing.T) {
	useOTAImageClient(t, &otaImageSDKClient{}, nil)
	stdout, _ := captureOTAImageOutput(t, keyOTAImageCreateCmd)
	require.NoError(t, setFlagForTest(t, keyOTAImageCreateCmd.Flags(), "json", "true"))

	require.NoError(t, runKeyOTAImageCreate(keyOTAImageCreateCmd, []string{"cm4"}))

	var got transport.GenerateKeyResponse
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &got))
	assert.Equal(t, "ota-image-cm4", got.KeyID)
}

func TestRunKeyOTAImageCreate_EmptyBoardID(t *testing.T) {
	refuseOTAImageClient(t)

	err := runKeyOTAImageCreate(keyOTAImageCreateCmd, []string{""})
	assert.ErrorIs(t, err, ErrOTAImageBoardIDRequired)
}

func TestRunKeyOTAImageCreate_MalformedBoardID(t *testing.T) {
	client := &otaImageSDKClient{}
	useOTAImageClient(t, client, nil)

	err := runKeyOTAImageCreate(keyOTAImageCreateCmd, []string{"CM4!"})
	assert.ErrorIs(t, err, ErrOTAImageKeyCreateFailed)
	assert.ErrorIs(t, err, errOTATestBoardID)
	assert.True(t, client.closed)
}

func TestRunKeyOTAImageCreate_ConnectFailed(t *testing.T) {
	useOTAImageClient(t, nil, ErrXKMSdConnectFailed)

	err := runKeyOTAImageCreate(keyOTAImageCreateCmd, []string{"cm4"})
	assert.ErrorIs(t, err, ErrOTAImageKeyCreateFailed)
	assert.ErrorIs(t, err, ErrXKMSdConnectFailed)
}

func TestRunKeyOTAImageRotate_Success(t *testing.T) {
	client := &otaImageSDKClient{}
	useOTAImageClient(t, client, nil)
	stdout, stderr := captureOTAImageOutput(t, keyOTAImageRotateCmd)

	require.NoError(t, runKeyOTAImageRotate(keyOTAImageRotateCmd, []string{"cm4"}))

	assert.Equal(t, "cm4", client.keyReq.BoardID)
	assert.Equal(t, "Successfully rotated OTA image key: ota-image-cm4 (current version 2)\n", stdout.String())
	assert.Empty(t, stderr.String())
	assert.True(t, client.closed)
}

func TestRunKeyOTAImageRotate_CertificateReissueWarning(t *testing.T) {
	useOTAImageClient(t, &otaImageSDKClient{reissue: true}, nil)
	_, stderr := captureOTAImageOutput(t, keyOTAImageRotateCmd)

	require.NoError(t, runKeyOTAImageRotate(keyOTAImageRotateCmd, []string{"cm4"}))

	assert.Equal(t, "WARNING: Key ota-image-cm4 has a certificate, which still certifies the previous version: re-issue it for version 2\n", stderr.String())
}

func TestRunKeyOTAImageRotate_SDKError(t *testing.T) {
	errUnavailable := errors.New("xkmsd unavailable")
	useOTAImageClient(t, &otaImageSDKClient{err: errUnavailable}, nil)

	err := runKeyOTAImageRotate(keyOTAImageRotateCmd, []string{"cm4"})
	assert.ErrorIs(t, err, ErrOTAImageKeyRotateFailed)
	assert.ErrorIs(t, err, errUnavailable)
}

func TestRunKeyOTAImageRotate_EmptyBoardID(t *testing.T) {
	refuseOTAImageClient(t)

	err := runKeyOTAImageRotate(keyOTAImageRotateCmd, []string{""})
	assert.ErrorIs(t, err, ErrOTAImageBoardIDRequired)
}

func TestRunKeyOTAImageSign_Success(t *testing.T) {
	client := &otaImageSDKClient{}
	useOTAImageClient(t, client, nil)
	useOTABackend(t, "software")
	stdout, _ := captureOTAImageOutput(t, keyOTAImageSignCmd)
	image := writeOTAImage(t, []byte("image"))

	require.NoError(t, runKeyOTAImageSign(keyOTAImageSignCmd, []string{"cm4", image}))

	assert.Equal(t, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("image")}, client.signReq)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("signature"))+"\n", stdout.String())
	assert.True(t, client.closed)
}

func TestRunKeyOTAImageSign_DigestJSON(t *testing.T) {
	client := &otaImageSDKClient{}
	useOTAImageClient(t, client, nil)
	stdout, _ := captureOTAImageOutput(t, keyOTAImageSignCmd)
	require.NoError(t, setFlagForTest(t, keyOTAImageSignCmd.Flags(), "digest", "true"))
	require.NoError(t, setFlagForTest(t, keyOTAImageSignCmd.Flags(), "json", "true"))
	digest := bytes.Repeat([]byte{0xAB}, 32)

	require.NoError(t, runKeyOTAImageSign(keyOTAImageSignCmd, []string{"cm4", writeOTAImage(t, digest)}))

	assert.True(t, client.signReq.DataIsDigest)
	assert.Equal(t, digest, client.signReq.Data)
	var got otaImageSignature
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &got))
	assert.Equal(t, otaImageSignature{Signature: base64.StdEncoding.EncodeToString([]byte("signature")), KeyVersion: 2}, got)
}

func TestRunKeyOTAImageSign_MissingImageFile(t *testing.T) {
	refuseOTAImageClient(t)

	err := runKeyOTAImageSign(keyOTAImageSignCmd, []string{"cm4", filepath.Join(t.TempDir(), "missing.bin")})
	assert.ErrorIs(t, err, ErrOTAImageReadFailed)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunKeyOTAImageSign_EmptyBoardID(t *testing.T) {
	refuseOTAImageClient(t)

	err := runKeyOTAImageSign(keyOTAImageSignCmd, []string{"", writeOTAImage(t, []byte("image"))})
	assert.ErrorIs(t, err, ErrOTAImageBoardIDRequired)
}

func TestRunKeyOTAImageSign_MalformedBoardID(t *testing.T) {
	useOTAImageClient(t, &otaImageSDKClient{}, nil)

	err := runKeyOTAImageSign(keyOTAImageSignCmd, []string{"CM4!", writeOTAImage(t, []byte("image"))})
	assert.ErrorIs(t, err, ErrOTAImageSignFailed)
	assert.ErrorIs(t, err, errOTATestBoardID)
}
