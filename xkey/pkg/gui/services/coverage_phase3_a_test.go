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

package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Phone Service tests
// ---------------------------------------------------------------------------

func TestP3A_PhoneService_PubKeyAlgoInfo_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "RSA Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "RSA", algo)
	assert.Equal(t, 2048, size)
	assert.Empty(t, curve)
}

func TestP3A_PhoneService_PubKeyAlgoInfo_ECDSA(t *testing.T) {
	cert := generateTestCert(t)
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "ECDSA", algo)
	assert.Equal(t, 256, size)
	assert.Equal(t, "P-256", curve)
}

func TestP3A_PhoneService_PubKeyAlgoInfo_Default(t *testing.T) {
	cert := p3aGenerateEd25519Cert(t)
	algo, size, curve := pubKeyAlgoInfo(cert)
	assert.Equal(t, "Ed25519", algo)
	assert.Equal(t, 0, size)
	assert.Empty(t, curve)
}

func TestP3A_PhoneService_BuildCertInfoList_WithRSACert(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "RSA Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	chain := []*x509.Certificate{cert}
	infos := buildCertInfoList(chain, nil)
	require.Len(t, infos, 1)
	assert.Contains(t, infos[0].Algorithm, "RSA")
	assert.Contains(t, infos[0].Algorithm, "2048")
	assert.Equal(t, "Leaf", infos[0].Label)
}

func TestP3A_PhoneService_BuildCertInfoList_EmptyChain(t *testing.T) {
	infos := buildCertInfoList(nil, nil)
	assert.Empty(t, infos)
}

func TestP3A_PhoneService_FindMatchingTrustRoot_EmptyChain(t *testing.T) {
	root := findMatchingTrustRoot(nil, []*x509.Certificate{generateTestCert(t)})
	assert.Nil(t, root)
}

func TestP3A_PhoneService_FindMatchingTrustRoot_NoMatch(t *testing.T) {
	leaf := generateTestCert(t)
	otherRoot := generateTestCert(t)
	root := findMatchingTrustRoot([]*x509.Certificate{leaf}, []*x509.Certificate{otherRoot})
	assert.Nil(t, root)
}

func TestP3A_PhoneService_PubKeyFP_NonNil(t *testing.T) {
	cert := generateTestCert(t)
	fp := pubKeyFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex = 64 chars
}

func TestP3A_PhoneService_CertFP_NonNil(t *testing.T) {
	cert := generateTestCert(t)
	fp := certFP(cert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64)
}

func TestP3A_PhoneService_FormatTrustAnchorName_NilCert(t *testing.T) {
	assert.Equal(t, "Unknown", formatTrustAnchorName(nil))
}

func TestP3A_PhoneService_FormatTrustAnchorName_OrgAndCN(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"Google"},
			CommonName:   "Hardware Root",
		},
	}
	assert.Equal(t, "Google - Hardware Root", formatTrustAnchorName(cert))
}

func TestP3A_PhoneService_FormatTrustAnchorName_CNOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "Root CA"},
	}
	assert.Equal(t, "Root CA", formatTrustAnchorName(cert))
}

func TestP3A_PhoneService_FormatTrustAnchorName_OrgOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{Organization: []string{"Google LLC"}},
	}
	assert.Equal(t, "Google LLC", formatTrustAnchorName(cert))
}

func TestP3A_PhoneService_FormatTrustAnchorName_SerialNumberOnly(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{SerialNumber: "ABC123"},
	}
	name := formatTrustAnchorName(cert)
	assert.Contains(t, name, "SN=ABC123")
}

func TestP3A_PhoneService_FormatTrustAnchorName_EmptySubject(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{},
	}
	assert.Equal(t, "Google Hardware Attestation Root", formatTrustAnchorName(cert))
}

func TestP3A_PhoneService_TruncateHash_Short(t *testing.T) {
	h := "abcdef"
	assert.Equal(t, h, truncateHash(h))
}

func TestP3A_PhoneService_TruncateHash_Long(t *testing.T) {
	h := strings.Repeat("a", 64)
	result := truncateHash(h)
	assert.Contains(t, result, "...")
	assert.True(t, strings.HasPrefix(result, h[:16]))
	assert.True(t, strings.HasSuffix(result, h[len(h)-8:]))
}

func TestP3A_PhoneService_SecurityLevelRank_Unknown(t *testing.T) {
	assert.Equal(t, -1, securityLevelRank("unknown"))
	assert.Equal(t, -1, securityLevelRank(""))
}

func TestP3A_PhoneService_SecurityLevelRank_Known(t *testing.T) {
	assert.Equal(t, 0, securityLevelRank("software"))
	assert.Equal(t, 1, securityLevelRank("tee"))
	assert.Equal(t, 2, securityLevelRank("strongbox"))
}

func TestP3A_PhoneService_GetCertLabel_VariousPositions(t *testing.T) {
	assert.Equal(t, "Leaf", getCertLabel(0, 1))
	assert.Equal(t, "Leaf", getCertLabel(0, 2))
	assert.Equal(t, "Root", getCertLabel(1, 2))
	assert.Equal(t, "Leaf", getCertLabel(0, 3))
	assert.Equal(t, "Intermediate", getCertLabel(1, 3))
	assert.Equal(t, "Root", getCertLabel(2, 3))
	assert.Equal(t, "Leaf", getCertLabel(0, 4))
	assert.Equal(t, "Intermediate 1", getCertLabel(1, 4))
	assert.Equal(t, "Intermediate 2", getCertLabel(2, 4))
	assert.Equal(t, "Root", getCertLabel(3, 4))
}

func TestP3A_PhoneService_KeymasterPurposeNameList_UnknownCode(t *testing.T) {
	names := keymasterPurposeNameList([]int{99})
	require.Len(t, names, 1)
	assert.Contains(t, names[0], "UNKNOWN(99)")
}

func TestP3A_PhoneService_KeymasterPurposeNameList_Empty(t *testing.T) {
	names := keymasterPurposeNameList(nil)
	assert.Empty(t, names)
}

func TestP3A_PhoneService_KeymasterPurposeNameList_Mixed(t *testing.T) {
	names := keymasterPurposeNameList([]int{0, 2, 99})
	require.Len(t, names, 3)
	assert.Equal(t, "ENCRYPT", names[0])
	assert.Equal(t, "SIGN", names[1])
	assert.Contains(t, names[2], "UNKNOWN")
}

func TestP3A_PhoneService_KeymasterAlgorithmName_Unknown(t *testing.T) {
	name := keymasterAlgorithmName(999)
	assert.Contains(t, name, "UNKNOWN(999)")
}

func TestP3A_PhoneService_KeymasterAlgorithmName_Known(t *testing.T) {
	assert.Equal(t, "RSA", keymasterAlgorithmName(1))
	assert.Equal(t, "EC", keymasterAlgorithmName(3))
	assert.Equal(t, "AES", keymasterAlgorithmName(32))
	assert.Equal(t, "TRIPLE_DES", keymasterAlgorithmName(33))
	assert.Equal(t, "HMAC", keymasterAlgorithmName(128))
}

func TestP3A_PhoneService_KeymasterOriginName_Unknown(t *testing.T) {
	name := keymasterOriginName(999)
	assert.Contains(t, name, "UNKNOWN(999)")
}

func TestP3A_PhoneService_KeymasterOriginName_Known(t *testing.T) {
	assert.Equal(t, "GENERATED", keymasterOriginName(0))
	assert.Equal(t, "DERIVED", keymasterOriginName(1))
	assert.Equal(t, "IMPORTED", keymasterOriginName(2))
	assert.Equal(t, "UNKNOWN", keymasterOriginName(3))
	assert.Equal(t, "SECURELY_IMPORTED", keymasterOriginName(4))
}

func TestP3A_PhoneService_VerifiedBootStateName_Known(t *testing.T) {
	assert.Equal(t, "verified", verifiedBootStateName(android.VerifiedBootVerified))
	assert.Equal(t, "self-signed", verifiedBootStateName(android.VerifiedBootSelfSigned))
	assert.Equal(t, "unverified", verifiedBootStateName(android.VerifiedBootUnverified))
	assert.Equal(t, "failed", verifiedBootStateName(android.VerifiedBootFailed))
}

func TestP3A_PhoneService_VerifiedBootStateName_Unknown(t *testing.T) {
	assert.Equal(t, "unknown", verifiedBootStateName(android.VerifiedBootState(99)))
}

func TestP3A_PhoneService_ParseDERChain_EmptySlice(t *testing.T) {
	chain, err := parseDERChain(nil)
	require.NoError(t, err)
	assert.Empty(t, chain)
}

func TestP3A_PhoneService_ParseDERChain_InvalidDER(t *testing.T) {
	_, err := parseDERChain([][]byte{{0x01, 0x02, 0x03}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate at index 0")
}

func TestP3A_PhoneService_ParseDERChain_ValidSingleCert(t *testing.T) {
	cert := generateTestCert(t)
	chain, err := parseDERChain([][]byte{cert.Raw})
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, cert.Subject.CommonName, chain[0].Subject.CommonName)
}

func TestP3A_PhoneService_EmitAttestationEvent_NilEmitter(t *testing.T) {
	svc := NewPhoneService()
	svc.emitAttestationEvent("device1", true, "")
}

func TestP3A_PhoneService_EmitAttestationEvent_WithEmitter(t *testing.T) {
	svc := NewPhoneService()
	var captured events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		captured = evt
	})
	svc.emitAttestationEvent("device1", true, "success")
	assert.Equal(t, events.EventAttestationResult, captured.Type)
}

func TestP3A_PhoneService_EmitPolicyViolationEvent_NilEmitter(t *testing.T) {
	svc := NewPhoneService()
	svc.emitPolicyViolationEvent("device1", map[string]string{"boot": "mismatch"}, "violation")
}

func TestP3A_PhoneService_EmitPolicyViolationEvent_WithEmitter(t *testing.T) {
	svc := NewPhoneService()
	var captured events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		captured = evt
	})
	svc.emitPolicyViolationEvent("device1", map[string]string{"boot": "mismatch"}, "violation")
	assert.Equal(t, events.EventPolicyViolation, captured.Type)
}

func TestP3A_PhoneService_SetConnected_EmitsEventAndCallback(t *testing.T) {
	svc := NewPhoneService()

	var emittedEvent events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvent = evt
	})

	var callbackConnected bool
	var callbackName string
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		callbackConnected = connected
		callbackName = name
	})

	svc.setConnected("MyPhone")

	assert.True(t, svc.IsConnected())
	assert.Equal(t, "MyPhone", svc.ConnectedDeviceName())
	assert.Equal(t, events.EventPhoneConnected, emittedEvent.Type)
	assert.True(t, callbackConnected)
	assert.Equal(t, "MyPhone", callbackName)
}

func TestP3A_PhoneService_SetDisconnected_EmitsEventAndCallback(t *testing.T) {
	svc := NewPhoneService()
	svc.setConnected("MyPhone")

	var emittedEvent events.Event
	svc.SetEventEmitter(func(evt events.Event) {
		emittedEvent = evt
	})

	var callbackConnected bool
	svc.SetStatusChangeFunc(func(connected bool, name string) {
		callbackConnected = connected
	})

	svc.setDisconnected("MyPhone", "test_reason")

	assert.False(t, svc.IsConnected())
	assert.Empty(t, svc.ConnectedDeviceName())
	assert.Equal(t, events.EventPhoneDisconnected, emittedEvent.Type)
	assert.False(t, callbackConnected)
}

func TestP3A_PhoneService_SetConnected_NilCallbacks(t *testing.T) {
	svc := NewPhoneService()
	svc.setConnected("Phone")
	assert.True(t, svc.IsConnected())
}

func TestP3A_PhoneService_SetDisconnected_NilCallbacks(t *testing.T) {
	svc := NewPhoneService()
	svc.setDisconnected("Phone", "reason")
	assert.False(t, svc.IsConnected())
}

func TestP3A_PhoneService_GetDeviceStatus_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.GetDeviceStatus("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_GetDeviceStatus_NonEmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.GetDeviceStatus("any-device")
	assert.ErrorIs(t, err, ErrPhoneNotConnected)
}

func TestP3A_PhoneService_Unpair_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Unpair("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_ListDevices_NoConfigFile(t *testing.T) {
	svc := NewPhoneService()
	devices, err := svc.ListDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)
}

func TestP3A_PhoneService_Connect_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Connect("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_Disconnect_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.Disconnect("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_AttestDevice_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.AttestDevice("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_AttestDevice_NotConnected(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.AttestDevice("SomePhone")
	assert.ErrorIs(t, err, ErrPhoneNotConnected)
}

func TestP3A_PhoneService_AttestDevice_WrongDevice(t *testing.T) {
	svc := NewPhoneService()
	svc.setConnected("OtherPhone")
	_, err := svc.AttestDevice("SomePhone")
	assert.ErrorIs(t, err, ErrPhoneNotConnected)
}

func TestP3A_PhoneService_SetAttestationPolicy_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.SetAttestationPolicy("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_ClearAttestationPolicy_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	err := svc.ClearAttestationPolicy("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_GetAttestationPolicy_EmptyName(t *testing.T) {
	svc := NewPhoneService()
	_, err := svc.GetAttestationPolicy("")
	assert.ErrorIs(t, err, ErrPhoneDeviceNotFound)
}

func TestP3A_PhoneService_Hostname(t *testing.T) {
	name := hostname()
	assert.NotEmpty(t, name)
}

func TestP3A_PhoneService_Scan_InvalidTimeouts(t *testing.T) {
	svc := NewPhoneService()

	_, err := svc.Scan(0)
	assert.ErrorIs(t, err, ErrPhoneInvalidTimeout)

	_, err = svc.Scan(-5)
	assert.ErrorIs(t, err, ErrPhoneInvalidTimeout)

	_, err = svc.Scan(121)
	assert.ErrorIs(t, err, ErrPhoneInvalidTimeout)
}

func TestP3A_PhoneService_ConnectedDeviceName_Empty(t *testing.T) {
	svc := NewPhoneService()
	assert.Empty(t, svc.ConnectedDeviceName())
}

func TestP3A_PhoneService_CloseActiveConnectionLocked_NilTransport(t *testing.T) {
	svc := NewPhoneService()
	svc.closeActiveConnectionLocked()
	assert.Nil(t, svc.activeTransport)
	assert.Nil(t, svc.activeSession)
}

func TestP3A_PhoneService_BuildCertInfoList_ECDSACurveFormatting(t *testing.T) {
	cert := generateTestCert(t)
	chain := []*x509.Certificate{cert}
	infos := buildCertInfoList(chain, nil)
	require.Len(t, infos, 1)
	// ECDSA should show curve name and bit size.
	assert.Contains(t, infos[0].Algorithm, "ECDSA")
	assert.Contains(t, infos[0].Algorithm, "P-256")
	assert.Contains(t, infos[0].Algorithm, "256")
}

// ---------------------------------------------------------------------------
// OIDC Service tests
// ---------------------------------------------------------------------------

func TestP3A_OIDCService_SaveProviders_EmptyDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.saveProviders()
	assert.NoError(t, err)
}

func TestP3A_OIDCService_LoadProviders_EmptyDataDir(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.loadProviders()
	assert.NoError(t, err)
}

func TestP3A_OIDCService_SaveProviders_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {
			Name:     "test",
			Issuer:   "https://example.com",
			ClientID: "client123",
			Type:     OIDCProviderTypeStandard,
		},
	}

	err := svc.saveProviders()
	require.NoError(t, err)

	path := filepath.Join(dir, oidcProvidersFile)
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var config oidcProvidersConfig
	require.NoError(t, json.Unmarshal(data, &config))
	require.Len(t, config.Providers, 1)
	assert.Equal(t, "test", config.Providers[0].Name)
}

func TestP3A_OIDCService_SaveProviders_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(roDir, 0500))

	svc := NewOIDCService(nil)
	svc.dataDir = filepath.Join(roDir, "nested")
	svc.providers = map[string]*OIDCProviderEntry{
		"test": {Name: "test"},
	}

	err := svc.saveProviders()
	assert.Error(t, err)
}

func TestP3A_OIDCService_LoadProviders_Success(t *testing.T) {
	dir := t.TempDir()

	config := oidcProvidersConfig{
		Providers: []OIDCProviderEntry{
			{Name: "google", Issuer: "https://accounts.google.com", Type: OIDCProviderTypeStandard},
			{Name: "github", Issuer: "https://github.com", Type: OIDCProviderTypeStandard},
		},
	}
	data, err := json.Marshal(config)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), data, 0600))

	svc := NewOIDCService(nil)
	svc.dataDir = dir

	err = svc.loadProviders()
	require.NoError(t, err)
	assert.Len(t, svc.providers, 2)
	assert.NotNil(t, svc.providers["google"])
	assert.NotNil(t, svc.providers["github"])
}

func TestP3A_OIDCService_LoadProviders_FileNotExist(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir

	err := svc.loadProviders()
	assert.NoError(t, err)
	assert.Empty(t, svc.providers)
}

func TestP3A_OIDCService_LoadProviders_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, oidcProvidersFile), []byte("{bad json"), 0600))

	svc := NewOIDCService(nil)
	svc.dataDir = dir

	err := svc.loadProviders()
	assert.Error(t, err)
}

func TestP3A_OIDCService_LoadProviders_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, oidcProvidersFile)
	require.NoError(t, os.WriteFile(path, []byte(`{"providers":[]}`), 0600))
	require.NoError(t, os.Chmod(path, 0000))
	t.Cleanup(func() {
		os.Chmod(path, 0600)
	})

	svc := NewOIDCService(nil)
	svc.dataDir = dir

	err := svc.loadProviders()
	assert.Error(t, err)
}

func TestP3A_OIDCService_SaveAndReload_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir
	svc.providers = map[string]*OIDCProviderEntry{
		"provider1": {
			Name:     "provider1",
			Issuer:   "https://issuer1.example.com",
			ClientID: "id1",
			Type:     OIDCProviderTypeStandard,
			Scopes:   []string{"openid", "profile"},
		},
	}

	require.NoError(t, svc.saveProviders())

	svc2 := NewOIDCService(nil)
	svc2.dataDir = dir
	require.NoError(t, svc2.loadProviders())

	require.Len(t, svc2.providers, 1)
	p := svc2.providers["provider1"]
	require.NotNil(t, p)
	assert.Equal(t, "https://issuer1.example.com", p.Issuer)
	assert.Equal(t, "id1", p.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, p.Scopes)
}

func TestP3A_OIDCService_TokenResponseToInfo_ExpiresInOnly(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Issuer: "https://example.com",
		Scopes: []string{"openid"},
	}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "access_token",
		ExpiresIn:   3600,
	}

	info := svc.tokenResponseToInfo("test-provider", entry, tokenResp)
	assert.Equal(t, "test-provider", info.Provider)
	assert.Equal(t, "https://example.com", info.Issuer)
	assert.NotEmpty(t, info.ExpiresAt)
	assert.Equal(t, int64(3600), info.ExpiresIn)
	assert.False(t, info.IsExpired)
}

func TestP3A_OIDCService_TokenResponseToInfo_ExpirySet(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}
	futureExpiry := time.Now().Add(1 * time.Hour)
	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
		Expiry:      futureExpiry,
	}

	info := svc.tokenResponseToInfo("test-provider", entry, tokenResp)
	assert.NotEmpty(t, info.ExpiresAt)
	assert.False(t, info.IsExpired)
	assert.True(t, info.ExpiresIn > 0)
}

func TestP3A_OIDCService_TokenResponseToInfo_BothExpiryAndExpiresInZero(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
	}

	info := svc.tokenResponseToInfo("test-provider", entry, tokenResp)
	assert.Empty(t, info.ExpiresAt)
}

func TestP3A_OIDCService_TokenResponseToInfo_WithRefreshToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}
	tokenResp := &oidc.TokenResponse{
		AccessToken:  "access",
		RefreshToken: "refresh",
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.True(t, info.HasRefresh)
}

func TestP3A_OIDCService_TokenResponseToInfo_WithScope(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
		Scope:       "openid profile email",
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, []string{"openid", "profile", "email"}, info.Scopes)
}

func TestP3A_OIDCService_TokenResponseToInfo_EntryScopesTakePrecedence(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Issuer: "https://example.com",
		Scopes: []string{"openid"},
	}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
		Scope:       "openid profile email",
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, []string{"openid"}, info.Scopes)
}

func TestP3A_OIDCService_TokenResponseToInfo_WithIDToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}

	claims := `{"sub":"user123","email":"user@example.com","name":"Test User"}`
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	fakeIDToken := "eyJ0eXAiOiJKV1QifQ." + encodedPayload + ".signature"

	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
		IDToken:     fakeIDToken,
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "user@example.com", info.Email)
	assert.Equal(t, "Test User", info.Name)
}

func TestP3A_OIDCService_TokenResponseToInfo_InvalidIDToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
		IDToken:     "invalid-token",
	}

	info := svc.tokenResponseToInfo("test", entry, tokenResp)
	assert.Empty(t, info.Subject)
}

func TestP3A_OIDCService_ExtractIDTokenClaims_InvalidBase64(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	svc.extractIDTokenClaims("header.!!!invalid!!!.sig", info)
	assert.Empty(t, info.Subject)
}

func TestP3A_OIDCService_ExtractIDTokenClaims_InvalidJSON(t *testing.T) {
	svc := NewOIDCService(nil)
	info := &OIDCTokenInfo{}
	encoded := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	svc.extractIDTokenClaims("header."+encoded+".sig", info)
	assert.Empty(t, info.Subject)
}

func TestP3A_OIDCService_BuildExecPayload_WithToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Issuer:   "https://example.com",
		ClientID: "client123",
		Scopes:   []string{"openid"},
	}
	expiry := time.Now().Add(time.Hour)
	tokenResp := &oidc.TokenResponse{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id-token",
		ExpiresIn:    3600,
		Expiry:       expiry,
	}

	payload := svc.buildExecPayload("provider1", entry, tokenResp)
	assert.Equal(t, "provider1", payload.Provider)
	assert.Equal(t, "https://example.com", payload.Issuer)
	assert.Equal(t, "client123", payload.ClientID)
	assert.Equal(t, "access", payload.AccessToken)
	assert.Equal(t, "refresh", payload.RefreshToken)
	assert.Equal(t, "id-token", payload.IDToken)
	assert.Equal(t, 3600, payload.ExpiresIn)
	assert.NotEmpty(t, payload.ExpiresAt)
}

func TestP3A_OIDCService_BuildExecPayload_NilToken(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{
		Issuer:   "https://example.com",
		ClientID: "client123",
	}

	payload := svc.buildExecPayload("provider1", entry, nil)
	assert.Equal(t, "provider1", payload.Provider)
	assert.Empty(t, payload.AccessToken)
	assert.Empty(t, payload.RefreshToken)
	assert.Empty(t, payload.ExpiresAt)
}

func TestP3A_OIDCService_BuildExecPayload_ZeroExpiry(t *testing.T) {
	svc := NewOIDCService(nil)
	entry := &OIDCProviderEntry{Issuer: "https://example.com"}
	tokenResp := &oidc.TokenResponse{
		AccessToken: "token",
		ExpiresIn:   3600,
	}

	payload := svc.buildExecPayload("provider1", entry, tokenResp)
	assert.Empty(t, payload.ExpiresAt)
}

func TestP3A_OIDCService_Close_NilTokenStore(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.Close()
	assert.NoError(t, err)
}

func TestP3A_OIDCService_GetTemplates_NotEmpty(t *testing.T) {
	svc := NewOIDCService(nil)
	templates := svc.GetTemplates()
	assert.NotEmpty(t, templates)
	lastTmpl := templates[len(templates)-1]
	assert.Equal(t, "custom", lastTmpl.Name)
	assert.True(t, lastTmpl.RequiresIssuer)
}

func TestP3A_OIDCService_GetProviders_Empty(t *testing.T) {
	svc := NewOIDCService(nil)
	providers := svc.GetProviders()
	assert.Empty(t, providers)
}

func TestP3A_OIDCService_GetProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetProvider("")
	assert.ErrorIs(t, err, ErrOIDCProviderNameRequired)
}

func TestP3A_OIDCService_GetProvider_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	_, err := svc.GetProvider("nonexistent")
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

func TestP3A_OIDCService_AddProvider_NilEntry(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.AddProvider(nil)
	assert.ErrorIs(t, err, ErrOIDCInvalidProvider)
}

func TestP3A_OIDCService_AddProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.AddProvider(&OIDCProviderEntry{})
	assert.ErrorIs(t, err, ErrOIDCProviderNameRequired)
}

func TestP3A_OIDCService_AddProvider_AlreadyExists(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()
	svc.providers["existing"] = &OIDCProviderEntry{Name: "existing"}

	err := svc.AddProvider(&OIDCProviderEntry{Name: "existing", Issuer: "https://test.com"})
	assert.ErrorIs(t, err, ErrOIDCProviderExists)
}

func TestP3A_OIDCService_AddProvider_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir

	err := svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Issuer:   "https://example.com",
		ClientID: "client123",
	})
	require.NoError(t, err)
	assert.Len(t, svc.providers, 1)
	assert.NotNil(t, svc.providers["test"])
	assert.Equal(t, OIDCProviderTypeStandard, svc.providers["test"].Type)
	assert.Contains(t, svc.providers["test"].RedirectURL, "localhost")
}

func TestP3A_OIDCService_AddProvider_InvalidTemplate(t *testing.T) {
	svc := NewOIDCService(nil)
	svc.dataDir = t.TempDir()

	err := svc.AddProvider(&OIDCProviderEntry{
		Name:     "test",
		Template: "nonexistent-template",
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrOIDCTemplateNotFound))
}

func TestP3A_OIDCService_UpdateProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.UpdateProvider("", &OIDCProviderEntry{})
	assert.ErrorIs(t, err, ErrOIDCProviderNameRequired)
}

func TestP3A_OIDCService_UpdateProvider_NilEntry(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.UpdateProvider("test", nil)
	assert.ErrorIs(t, err, ErrOIDCInvalidProvider)
}

func TestP3A_OIDCService_UpdateProvider_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.UpdateProvider("nonexistent", &OIDCProviderEntry{Name: "nonexistent"})
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

func TestP3A_OIDCService_UpdateProvider_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir
	svc.providers["test"] = &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://old.example.com",
	}

	err := svc.UpdateProvider("test", &OIDCProviderEntry{
		Name:   "test",
		Issuer: "https://new.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://new.example.com", svc.providers["test"].Issuer)
}

func TestP3A_OIDCService_UpdateProvider_Rename(t *testing.T) {
	dir := t.TempDir()
	svc := NewOIDCService(nil)
	svc.dataDir = dir
	svc.providers["oldname"] = &OIDCProviderEntry{
		Name:   "oldname",
		Issuer: "https://example.com",
	}

	err := svc.UpdateProvider("oldname", &OIDCProviderEntry{
		Name:   "newname",
		Issuer: "https://example.com",
	})
	require.NoError(t, err)
	assert.Nil(t, svc.providers["oldname"])
	assert.NotNil(t, svc.providers["newname"])
}

func TestP3A_OIDCService_DeleteProvider_EmptyName(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.DeleteProvider("")
	assert.ErrorIs(t, err, ErrOIDCProviderNameRequired)
}

func TestP3A_OIDCService_DeleteProvider_NotFound(t *testing.T) {
	svc := NewOIDCService(nil)
	err := svc.DeleteProvider("nonexistent")
	assert.ErrorIs(t, err, ErrOIDCProviderNotFound)
}

// ---------------------------------------------------------------------------
// Platform Policy Service tests
// ---------------------------------------------------------------------------

func TestP3A_PlatformPolicyService_ExportPolicy_EmptyPCRs(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	def := &PlatformPolicyDefinition{
		PCRs:      []int{},
		Bank:      "sha256",
		Digests:   map[int]string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	exported, err := svc.ExportPolicy()
	require.NoError(t, err)
	assert.NotEmpty(t, exported)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &result))

	_, hasPCRSelections := result["pcr_selections"]
	assert.False(t, hasPCRSelections)
	_, hasPCRDigests := result["pcr_digests"]
	assert.False(t, hasPCRDigests)
}

func TestP3A_PlatformPolicyService_ExportPolicy_EmptyDigestsNonEmptyPCRs(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7},
		Bank:      "sha256",
		Digests:   map[int]string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	exported, err := svc.ExportPolicy()
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(exported), &result))

	_, hasPCRSelections := result["pcr_selections"]
	assert.True(t, hasPCRSelections)
	_, hasPCRDigests := result["pcr_digests"]
	assert.False(t, hasPCRDigests)
}

func TestP3A_PlatformPolicyService_ReadPCRDigests_BankMismatch(t *testing.T) {
	mock := &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
				},
			},
		},
	}
	svc := newPolicyServiceWithMock(t, mock)

	digests, err := svc.readPCRDigests([]int{0}, "sha384")
	require.NoError(t, err)
	assert.Empty(t, digests)
}

func TestP3A_PlatformPolicyService_ReadPCRDigests_MultipleBanks(t *testing.T) {
	mock := &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA1",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0x01}},
				},
			},
			{
				Algorithm: "SHA256",
				PCRs: []tpm2pkg.PCR{
					{ID: 0, Value: []byte{0xAA, 0xBB}},
				},
			},
		},
	}
	svc := newPolicyServiceWithMock(t, mock)

	digests, err := svc.readPCRDigests([]int{0}, "sha256")
	require.NoError(t, err)
	assert.Equal(t, "aabb", digests[0])
}

func TestP3A_PlatformPolicyService_VerifyDigests_InvalidStoredHex(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "ZZZZ"},
	}

	valid, err := svc.verifyDigests(def)
	assert.False(t, valid)
	assert.ErrorIs(t, err, ErrPolicyVerifyFailed)
}

func TestP3A_PlatformPolicyService_VerifyDigests_MissingLivePCR(t *testing.T) {
	mock := &policyMockTPM{
		mockTPM: *defaultMockTPM(),
		pcrBanksOverride: []tpm2pkg.PCRBank{
			{
				Algorithm: "SHA256",
				PCRs:      []tpm2pkg.PCR{},
			},
		},
	}
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabbccdd"},
	}

	valid, err := svc.verifyDigests(def)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestP3A_PlatformPolicyService_ValidatePlatformPolicyDigests_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{},
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result)
}

func TestP3A_PlatformPolicyService_ValidatePlatformPolicyDigests_NoTPM(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabb"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	assert.Nil(t, result)
}

func TestP3A_PlatformPolicyService_ValidatePlatformPolicyDigests_Match(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0, 7},
		Bank:    "sha256",
		Digests: map[int]string{0: "aabbccdd", 7: "11223344"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	require.NotNil(t, result)
	assert.True(t, *result)
}

func TestP3A_PlatformPolicyService_ValidatePlatformPolicyDigests_Mismatch(t *testing.T) {
	mock := defaultPolicyMock()
	svc := newPolicyServiceWithMock(t, mock)

	def := &PlatformPolicyDefinition{
		PCRs:    []int{0},
		Bank:    "sha256",
		Digests: map[int]string{0: "deadbeef"},
	}

	result := svc.validatePlatformPolicyDigests(def)
	require.NotNil(t, result)
	assert.False(t, *result)
}

func TestP3A_PlatformPolicyService_NormalizeBankAlg_SHA386(t *testing.T) {
	assert.Equal(t, "sha384", normalizeBankAlg("sha386"))
	assert.Equal(t, "sha384", normalizeBankAlg("SHA386"))
}

func TestP3A_PlatformPolicyService_NormalizeBankAlg_Passthrough(t *testing.T) {
	assert.Equal(t, "sha256", normalizeBankAlg("SHA256"))
	assert.Equal(t, "sha512", normalizeBankAlg("sha512"))
}

func TestP3A_PlatformPolicyService_GetPlatformPolicyAsPCRPolicy_EmptyDigests(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	def := &PlatformPolicyDefinition{
		PCRs:      []int{0},
		Bank:      "sha256",
		Digests:   map[int]string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	svc.policy.Store(def)

	policy, err := svc.GetPlatformPolicyAsPCRPolicy()
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Nil(t, policy.Valid)
}

func TestP3A_PlatformPolicyService_DefinitionToPCRPolicy_Conversion(t *testing.T) {
	svc := NewPlatformPolicyService(filepath.Join(t.TempDir(), "test.policy"))

	now := time.Now()
	def := &PlatformPolicyDefinition{
		PCRs:      []int{0, 7, 14},
		Bank:      "sha256",
		Digests:   map[int]string{0: "aa", 7: "bb", 14: "cc"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	policy := svc.definitionToPCRPolicy(def)
	assert.Equal(t, "Platform Policy", policy.Name)
	assert.True(t, policy.IsPlatformPolicy)
	require.Len(t, policy.PCRSelections, 3)
	assert.Equal(t, 0, policy.PCRSelections[0].Index)
	assert.Equal(t, "sha256", policy.PCRSelections[0].Bank)
	require.Len(t, policy.PCRDigests, 3)
	assert.Equal(t, "aa", policy.PCRDigests["sha256:0"])
	assert.Equal(t, "bb", policy.PCRDigests["sha256:7"])
	assert.Equal(t, "cc", policy.PCRDigests["sha256:14"])
}

// ---------------------------------------------------------------------------
// Admin Service tests
// ---------------------------------------------------------------------------

func TestP3A_AdminService_GetBackendInfo_RemoteBackends(t *testing.T) {
	svc := NewAdminService()
	remoteBackends := []BackendInfo{
		{ID: "remote-sw", Type: "software", Enabled: true, Algorithms: []string{"RSA"}},
		{ID: "remote-tpm", Type: "tpm2", Enabled: true, Algorithms: []string{"ECDSA"}},
	}
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return remoteBackends, nil
	})

	info, err := svc.GetBackendInfo("remote-sw")
	require.NoError(t, err)
	assert.Equal(t, "remote-sw", info.ID)
	assert.Equal(t, "software", info.Type)
}

func TestP3A_AdminService_GetBackendInfo_RemoteError_FallsBackToLocal(t *testing.T) {
	svc := NewAdminService()
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
		return nil, errors.New("network error")
	})

	info, err := svc.GetBackendInfo("software")
	require.NoError(t, err)
	assert.Equal(t, "software", info.ID)
}

func TestP3A_AdminService_GetServerStatus_ConnInfoFn_NilInfo(t *testing.T) {
	svc := NewAdminService()
	svc.SetConnectionInfoFunc(func() *ConnectionInfo { return nil })

	status, err := svc.GetServerStatus()
	require.NoError(t, err)
	assert.False(t, status.Running)
}

func TestP3A_AdminService_ListBackends_LocalDefaults(t *testing.T) {
	svc := NewAdminService()
	backends, err := svc.ListBackends()
	require.NoError(t, err)

	ids := make(map[string]bool)
	for _, b := range backends {
		ids[b.ID] = true
	}
	// Without registry or hardware providers, fallbackBackends only returns software.
	assert.True(t, ids["software"])
	require.True(t, len(backends) >= 1, "expected at least software backend")
}

func TestP3A_AdminService_GetAuditLogs_WithStore(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "software", "key1", true, nil, 10)

	auditSvc := NewAuditService(store)
	auditSvc.SetContext(context.Background())

	entries, err := auditSvc.GetEntries(nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "key_created", entries[0].Operation)
	assert.Equal(t, "key1", entries[0].KeyID)
}

func TestP3A_AdminService_GetAuditLogs_NilStore(t *testing.T) {
	auditSvc := NewAuditService(nil)
	entries, err := auditSvc.GetEntries(nil)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestP3A_AdminService_ExportEntries_InvalidFormat(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	auditSvc := NewAuditService(store)
	_, err := auditSvc.ExportEntries("yaml", nil)
	assert.ErrorIs(t, err, ErrAuditInvalidFormat)
}

func TestP3A_AdminService_ExportEntries_NoEntries(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	auditSvc := NewAuditService(store)
	auditSvc.SetContext(context.Background())

	_, err := auditSvc.ExportEntries("json", nil)
	assert.ErrorIs(t, err, ErrAuditNoEntries)
}

func TestP3A_AdminService_ExportEntries_JSON(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "sw", "k1", true, nil, 5)

	auditSvc := NewAuditService(store)
	auditSvc.SetContext(context.Background())

	data, err := auditSvc.ExportEntries("json", nil)
	require.NoError(t, err)

	var entries []AuditEntry
	require.NoError(t, json.Unmarshal(data, &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "key_created", entries[0].Operation)
}

func TestP3A_AdminService_ExportEntries_CSV(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "sw", "k1", true, nil, 5)

	auditSvc := NewAuditService(store)
	auditSvc.SetContext(context.Background())

	data, err := auditSvc.ExportEntries("csv", nil)
	require.NoError(t, err)

	csv := string(data)
	assert.True(t, strings.HasPrefix(csv, "timestamp,"))
	assert.Contains(t, csv, "key_created")
	assert.Contains(t, csv, "k1")
}

func TestP3A_AdminService_ExportAuditLogs_NotAuthorized_JSON(t *testing.T) {
	svc := NewAdminService()
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.ExportAuditLogs("json")
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

func TestP3A_AdminService_ExportAuditLogs_NotAuthorized_CSV(t *testing.T) {
	svc := NewAdminService()
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.ExportAuditLogs("csv")
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

func TestP3A_AdminService_ExportAuditLogs_InvalidFormat(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.ExportAuditLogs("xml")
	assert.Error(t, err)
}

func TestP3A_AdminService_GetAuditLogs_NonAdmin(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	svc.SetAuditStore(store)

	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.GetAuditLogs(nil)
	assert.ErrorIs(t, err, ErrAdminNotAuthorized)
}

func TestP3A_AdminService_AuditFilter_WithOperationFilter(t *testing.T) {
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "sw", "k1", true, nil, 5)
	store.LogKeyOperation(audit.OpKeyDeleted, "sw", "k2", true, nil, 3)

	auditSvc := NewAuditService(store)
	auditSvc.SetContext(context.Background())

	filter := &AuditFilter{Operation: "key_created"}
	entries, err := auditSvc.GetEntries(filter)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "key_created", entries[0].Operation)
}

func TestP3A_AdminService_ExportCSV_FormatCorrect(t *testing.T) {
	auditSvc := NewAuditService(nil)

	entries := []AuditEntry{
		{
			Timestamp:  time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
			Operation:  "key_created",
			Backend:    "software",
			KeyID:      "key-abc",
			DeviceID:   "dev1",
			DeviceName: "phone1",
			Success:    true,
			Error:      "",
			DurationMs: 42,
		},
	}

	data, err := auditSvc.exportCSV(entries)
	require.NoError(t, err)

	csv := string(data)
	lines := strings.Split(csv, "\n")
	require.True(t, len(lines) >= 2)

	assert.Equal(t, "timestamp,operation,backend,key_id,device_id,device_name,success,error,duration_ms", lines[0])
	assert.Contains(t, lines[1], "key_created")
	assert.Contains(t, lines[1], "software")
	assert.Contains(t, lines[1], "key-abc")
	assert.Contains(t, lines[1], "true")
	assert.Contains(t, lines[1], "42")
}

func TestP3A_AdminService_IntToStr_Values(t *testing.T) {
	assert.Equal(t, "0", intToStr(0))
	assert.Equal(t, "42", intToStr(42))
	assert.Equal(t, "100", intToStr(100))
	assert.Equal(t, "-1", intToStr(-1))
}

func TestP3A_AdminService_BoolToStr(t *testing.T) {
	assert.Equal(t, "true", boolToStr(true))
	assert.Equal(t, "false", boolToStr(false))
}

func TestP3A_AdminService_Int64ToStr(t *testing.T) {
	result := int64ToStr(42)
	assert.Equal(t, "42", result)
}

// ---------------------------------------------------------------------------
// Test helper: generate a self-signed Ed25519 certificate.
// ---------------------------------------------------------------------------

func p3aGenerateEd25519Cert(t *testing.T) *x509.Certificate {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "Ed25519 Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}
