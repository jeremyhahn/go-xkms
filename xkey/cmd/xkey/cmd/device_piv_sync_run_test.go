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

//go:build ble

package cmd

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
)

func pivSyncTestCmd(extraFlags func(*cobra.Command)) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	if extraFlags != nil {
		extraFlags(cmd)
	}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd
}

func TestRunPIVDeviceList_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(nil)
	err := runPIVDeviceList(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunPIVDeviceList_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := pivSyncTestCmd(nil)
	err := runPIVDeviceList(cmd, nil)
	require.ErrorIs(t, err, ErrPIVDeviceListSlotsFailed)
}

func TestRunPIVDevicePushCert_InvalidSlot(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(nil)
	err := runPIVDevicePushCert(cmd, []string{"zz", "unused.pem"})
	require.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunPIVDevicePushCert_CertificateReadFailed(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(nil)
	err := runPIVDevicePushCert(cmd, []string{"9a", filepath.Join(t.TempDir(), "missing.pem")})
	require.ErrorIs(t, err, ErrPIVCertificateReadFailed)
}

func TestRunPIVDevicePushCert_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	certPath := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certPath, generateTestCertificatePEM(t), 0600))

	cmd := pivSyncTestCmd(nil)
	err := runPIVDevicePushCert(cmd, []string{"9a", certPath})
	require.ErrorIs(t, err, ErrPIVDevicePushCertFailed)
}

func TestRunPIVDevicePullCert_InvalidSlot(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().String("output", "", "") })
	err := runPIVDevicePullCert(cmd, []string{"zz"})
	require.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunPIVDevicePullCert_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().String("output", "", "") })
	err := runPIVDevicePullCert(cmd, []string{"9a"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunPIVDeviceGenerateKey_InvalidSlot(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().StringP("algorithm", "a", "ECDSA-P256", "") })
	err := runPIVDeviceGenerateKey(cmd, []string{"zz"})
	require.ErrorIs(t, err, ErrPIVInvalidSlot)
}

func TestRunPIVDeviceGenerateKey_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := pivSyncTestCmd(func(c *cobra.Command) { c.Flags().StringP("algorithm", "a", "ECDSA-P256", "") })
	err := runPIVDeviceGenerateKey(cmd, []string{"9a"})
	require.ErrorIs(t, err, ErrPIVDeviceGenerateKeyFailed)
}

// pivFailureCases are the ways a phone round trip can fail, for the given
// method.
func pivFailureCases(method string) []struct {
	name      string
	transport *fakeDeviceTransport
	detail    string
} {
	return []struct {
		name      string
		transport *fakeDeviceTransport
		detail    string
	}{
		{
			name:      "connect",
			transport: &fakeDeviceTransport{connectErr: errors.New("radio off")},
			detail:    "radio off",
		},
		{
			name:      "send",
			transport: &fakeDeviceTransport{sendErr: errors.New("link dropped")},
			detail:    "link dropped",
		},
		{
			name: "phone error",
			transport: &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
				method: {Code: -32000, Message: "slot locked"},
			}},
			detail: "[-32000] slot locked",
		},
		{
			name: "malformed reply",
			transport: &fakeDeviceTransport{results: map[string]any{
				method: "not an object",
			}},
			detail: "failed to decode result",
		},
	}
}

// pivOutput returns what the command printed.
func pivOutput(cmd *cobra.Command) string {
	return cmd.OutOrStdout().(*bytes.Buffer).String()
}

func TestRunPIVDeviceList_RendersEverySlot(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalPIVListSlots: &pairingproto.LocalPIVListSlotsResult{Slots: []pairingproto.PIVSlotInfo{
			{Slot: "9a", Label: "PIV Authentication with a long label", Algorithm: "ECDSA-P256",
				HasKey: true, HasCertificate: true, CertSubject: "alice"},
			{Slot: "9c", Label: "Digital Signature"},
		}},
	}}
	useFakeTransport(t, transport)

	cmd := pivSyncTestCmd(nil)
	require.NoError(t, runPIVDeviceList(cmd, nil))

	output := pivOutput(cmd)
	assert.Contains(t, output, "Phone PIV Slots (2):")
	assert.Regexp(t, `9a\s+PIV Authentication wi\.\.\.\s+ECDSA-P256\s+yes\s+yes\s+alice`, output)
	assert.Regexp(t, `9c\s+Digital Signature\s+no\s+no\s+-`, output)
	assert.True(t, transport.closed)
}

func TestRunPIVDeviceList_EmptyPhone(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalPIVListSlots: &pairingproto.LocalPIVListSlotsResult{},
	}})

	cmd := pivSyncTestCmd(nil)
	require.NoError(t, runPIVDeviceList(cmd, nil))
	assert.Contains(t, pivOutput(cmd), "No PIV slots configured on phone.")
}

func TestRunPIVDeviceList_PhoneFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	for _, tt := range pivFailureCases(pairingproto.MethodLocalPIVListSlots) {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			err := runPIVDeviceList(pivSyncTestCmd(nil), nil)
			require.ErrorIs(t, err, ErrPIVDeviceListSlotsFailed)
			assert.ErrorContains(t, err, tt.detail)
		})
	}
}

// writePIVTestCert writes a fresh certificate for commonName and returns the
// path and DER bytes.
func writePIVTestCert(t *testing.T, commonName string) (string, []byte) {
	t.Helper()

	certPEM := newTestCertificatePEM(t, commonName)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	path := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(path, certPEM, 0600))
	return path, block.Bytes
}

func TestRunPIVDevicePushCert_SendsTheCertificate(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	certPath, certDER := writePIVTestCert(t, "piv-push")

	transport := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalPIVImportCert: &pairingproto.LocalPIVImportCertResult{Success: true},
	}}
	useFakeTransport(t, transport)

	cmd := pivSyncTestCmd(nil)
	require.NoError(t, runPIVDevicePushCert(cmd, []string{"9c", certPath}))

	require.Len(t, transport.requests, 1)
	params, ok := transport.requests[0].Params.(*pairingproto.LocalPIVImportCertParams)
	require.True(t, ok)
	assert.Equal(t, "9c", params.Slot)
	assert.Equal(t, certDER, params.CertificateDER)

	output := pivOutput(cmd)
	assert.Contains(t, output, `Pushing certificate to slot 9c`)
	assert.Contains(t, output, "Subject: piv-push")
	assert.Contains(t, output, "Certificate pushed successfully.")
}

func TestRunPIVDevicePushCert_RejectsANonCertificate(t *testing.T) {
	isolatedBackupHome(t)
	path := filepath.Join(t.TempDir(), "junk.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0600))

	err := runPIVDevicePushCert(pivSyncTestCmd(nil), []string{"9a", path})
	require.ErrorIs(t, err, ErrPIVCertificateParseFailed)
}

func TestRunPIVDevicePushCert_PhoneFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	certPath, _ := writePIVTestCert(t, "piv-push")

	for _, tt := range pivFailureCases(pairingproto.MethodLocalPIVImportCert) {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			cmd := pivSyncTestCmd(nil)
			err := runPIVDevicePushCert(cmd, []string{"9a", certPath})
			require.ErrorIs(t, err, ErrPIVDevicePushCertFailed)
			assert.ErrorContains(t, err, tt.detail)
			assert.NotContains(t, pivOutput(cmd), "pushed successfully")
		})
	}
}

// pivPullCmd builds a pull-cert command, optionally writing to outputPath.
func pivPullCmd(outputPath string) *cobra.Command {
	return pivSyncTestCmd(func(c *cobra.Command) {
		c.Flags().String("output", outputPath, "")
	})
}

func TestRunPIVDevicePullCert_PrintsOrSavesTheCertificate(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	_, certDER := writePIVTestCert(t, "piv-pull")

	transport := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalPIVGetCert: &pairingproto.LocalPIVGetCertResult{CertificateDER: certDER},
	}}
	useFakeTransport(t, transport)
	wantPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	t.Run("stdout", func(t *testing.T) {
		cmd := pivPullCmd("")
		require.NoError(t, runPIVDevicePullCert(cmd, []string{"9d"}))

		output := pivOutput(cmd)
		assert.Contains(t, output, wantPEM)
		assert.Contains(t, output, "Subject: piv-pull")
		assert.Contains(t, output, "Issuer:  piv-pull")
	})

	t.Run("file", func(t *testing.T) {
		outputPath := filepath.Join(t.TempDir(), "pulled.pem")
		cmd := pivPullCmd(outputPath)
		require.NoError(t, runPIVDevicePullCert(cmd, []string{"9d"}))

		saved, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		assert.Equal(t, wantPEM, string(saved))
		assert.Contains(t, pivOutput(cmd), "Certificate saved to: "+outputPath)
		assert.NotContains(t, pivOutput(cmd), "BEGIN CERTIFICATE")
	})

	var sent pairingproto.LocalPIVGetCertParams
	require.NoError(t, json.Unmarshal(transport.wire[0], &sent))
	assert.Equal(t, "9d", sent.Slot)
}

func TestRunPIVDevicePullCert_BadReplies(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	t.Run("empty slot", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
			pairingproto.MethodLocalPIVGetCert: &pairingproto.LocalPIVGetCertResult{},
		}})

		err := runPIVDevicePullCert(pivPullCmd(""), []string{"9a"})
		require.ErrorIs(t, err, ErrPIVCertificateNotFound)
		assert.ErrorContains(t, err, "no certificate in slot 9a")
	})

	t.Run("unparseable certificate", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
			pairingproto.MethodLocalPIVGetCert: &pairingproto.LocalPIVGetCertResult{CertificateDER: []byte("junk")},
		}})

		err := runPIVDevicePullCert(pivPullCmd(""), []string{"9a"})
		require.ErrorIs(t, err, ErrPIVDevicePullCertFailed)
	})

	for _, tt := range pivFailureCases(pairingproto.MethodLocalPIVGetCert) {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			err := runPIVDevicePullCert(pivPullCmd(""), []string{"9a"})
			require.ErrorIs(t, err, ErrPIVDevicePullCertFailed)
			assert.ErrorContains(t, err, tt.detail)
		})
	}
}

// pivDeviceGenerateCmd builds a generate-key command for the given algorithm.
func pivDeviceGenerateCmd(algorithm string) *cobra.Command {
	return pivSyncTestCmd(func(c *cobra.Command) {
		c.Flags().StringP("algorithm", "a", algorithm, "")
	})
}

func TestRunPIVDeviceGenerateKey_ReportsTheNewKey(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalPIVGenerateKey: &pairingproto.LocalPIVGenerateKeyResult{
			Slot: "9e", Algorithm: "ECDSA-P384", PublicKeyDER: make([]byte, 120),
		},
	}}
	useFakeTransport(t, transport)

	cmd := pivDeviceGenerateCmd("ECDSA-P384")
	require.NoError(t, runPIVDeviceGenerateKey(cmd, []string{"9e"}))

	params, ok := transport.requests[0].Params.(*pairingproto.LocalPIVGenerateKeyParams)
	require.True(t, ok)
	assert.Equal(t, "9e", params.Slot)
	assert.Equal(t, "ECDSA-P384", params.Algorithm)

	output := pivOutput(cmd)
	assert.Contains(t, output, "Algorithm: ECDSA-P384")
	assert.Contains(t, output, "Public Key: 120 bytes (DER)")
	assert.Contains(t, output, "Key generated successfully.")
}

func TestRunPIVDeviceGenerateKey_PhoneFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	for _, tt := range pivFailureCases(pairingproto.MethodLocalPIVGenerateKey) {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			cmd := pivDeviceGenerateCmd("ECDSA-P256")
			err := runPIVDeviceGenerateKey(cmd, []string{"9a"})
			require.ErrorIs(t, err, ErrPIVDeviceGenerateKeyFailed)
			assert.ErrorContains(t, err, tt.detail)
			assert.NotContains(t, pivOutput(cmd), "generated successfully")
		})
	}
}

func TestRunPIVDeviceCommands_UnknownDevice(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	certPath, _ := writePIVTestCert(t, "piv-push")

	runs := map[string]func(cmd *cobra.Command) error{
		"list":      func(cmd *cobra.Command) error { return runPIVDeviceList(cmd, nil) },
		"push-cert": func(cmd *cobra.Command) error { return runPIVDevicePushCert(cmd, []string{"9a", certPath}) },
		"pull-cert": func(cmd *cobra.Command) error { return runPIVDevicePullCert(cmd, []string{"9a"}) },
		"generate":  func(cmd *cobra.Command) error { return runPIVDeviceGenerateKey(cmd, []string{"9a"}) },
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			cmd := pivSyncTestCmd(func(c *cobra.Command) {
				c.Flags().String("output", "", "")
				c.Flags().String("algorithm", "ECDSA-P256", "")
			})
			require.NoError(t, cmd.Flags().Set("device", "Other Phone"))

			err := run(cmd)
			require.ErrorIs(t, err, ErrDeviceNotFound)
			assert.ErrorContains(t, err, "Other Phone")
		})
	}
}
