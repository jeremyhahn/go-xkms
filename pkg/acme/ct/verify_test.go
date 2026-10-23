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

package ct

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifySCT(t *testing.T) {
	ca, caKey := newTestCA(t, "Test CA")
	entry := newTestPrecert(t, ca, caKey, nil, nil)
	logKey := newP256Key(t)
	log := LogGroup{URL: "https://log.example.com", PublicKey: logKey.Public(), Enabled: true}
	sct, err := signSCT(logKey, entry, nil)
	require.NoError(t, err)

	t.Run("valid SCT", func(t *testing.T) {
		assert.NoError(t, VerifySCT(sct, log, entry.der, entry.chain))
	})

	t.Run("valid SCT from a precertificate signing certificate", func(t *testing.T) {
		psc, pscKey := newPrecertSigningCert(t, ca, caKey)
		pscEntry := newTestPrecert(t, ca, caKey, psc, pscKey)
		pscSCT, err := signSCT(logKey, pscEntry, nil)
		require.NoError(t, err)
		assert.NoError(t, VerifySCT(pscSCT, log, pscEntry.der, pscEntry.chain))
	})

	otherCA, _ := newTestCA(t, "Other CA")
	psc, pscKey := newPrecertSigningCert(t, ca, caKey)
	pscEntry := newTestPrecert(t, ca, caKey, psc, pscKey)
	withKey := func(key crypto.PublicKey) LogGroup {
		withKey := log
		withKey.PublicKey = key
		return withKey
	}

	tests := []struct {
		name    string
		sct     *SignedCertificateTimestamp
		log     LogGroup
		precert []byte
		chain   [][]byte
		want    error
	}{
		{"nil SCT", nil, log, entry.der, entry.chain, ErrNilInput},
		{"empty precertificate", sct, log, nil, entry.chain, ErrNilInput},
		{"log without a key", sct, withKey(nil), entry.der, entry.chain, ErrLogPublicKeyMissing},
		{"RSA-1024 log key", sct, withKey(newRSAKey(t, 1024).Public()), entry.der, entry.chain, ErrLogPublicKeyUnsupported},
		{"key of another log", sct, withKey(newP256Key(t).Public()), entry.der, entry.chain, ErrSCTLogIDMismatch},
		{"precertificate not DER", sct, log, []byte("not DER"), entry.chain, ErrPrecertMalformed},
		{"certificate without poison", sct, log, ca.Raw, entry.chain, ErrPrecertPoisonMissing},
		{"no issuer", sct, log, entry.der, nil, ErrPrecertIssuerMissing},
		{"issuer not DER", sct, log, entry.der, [][]byte{[]byte("not DER")}, ErrPrecertIssuerMissing},
		{"signing certificate without the final issuer", sct, log, pscEntry.der, pscEntry.chain[:1], ErrPrecertIssuerMissing},
		{"another issuer", sct, log, entry.der, [][]byte{otherCA.Raw}, ErrInvalidSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, VerifySCT(tt.sct, tt.log, tt.precert, tt.chain), tt.want)
		})
	}

	t.Run("RSA log", func(t *testing.T) {
		rsaKey := newRSAKey(t, 2048)
		rsaLog := withKey(rsaKey.Public())
		rsaSCT, err := signSCT(rsaKey, entry, nil)
		require.NoError(t, err)
		require.NoError(t, VerifySCT(rsaSCT, rsaLog, entry.der, entry.chain))

		ecdsaAlg := *rsaSCT
		ecdsaAlg.Signature.SigAlgorithm = SignatureAlgorithmECDSA
		assert.ErrorIs(t, VerifySCT(&ecdsaAlg, rsaLog, entry.der, entry.chain), ErrUnsupportedSCTAlgorithm)

		tampered := *rsaSCT
		tampered.Signature.Signature = append([]byte{}, rsaSCT.Signature.Signature...)
		tampered.Signature.Signature[0] ^= 0x01
		assert.ErrorIs(t, VerifySCT(&tampered, rsaLog, entry.der, entry.chain), ErrInvalidSignature)
	})

	t.Run("unknown version", func(t *testing.T) {
		v2 := *sct
		v2.Version = V1 + 1
		assert.ErrorIs(t, VerifySCT(&v2, log, entry.der, entry.chain), ErrInvalidSCT)
	})
}

func TestLogGroup_validate(t *testing.T) {
	key := newP256Key(t).Public()
	logID, err := KeyToLogID(key)
	require.NoError(t, err)

	t.Run("derives the log ID from the key", func(t *testing.T) {
		log := LogGroup{Name: "Log", URL: "https://log.example.com", PublicKey: key}
		require.NoError(t, log.validate())
		assert.Equal(t, logID, log.LogID)
	})

	t.Run("accepts a matching configured log ID", func(t *testing.T) {
		log := LogGroup{URL: "http://log.example.com/ct", PublicKey: key, LogID: logID}
		assert.NoError(t, log.validate())
	})

	t.Run("accepts an RSA-2048 key", func(t *testing.T) {
		log := LogGroup{URL: "https://log.example.com", PublicKey: newRSAKey(t, 2048).Public()}
		assert.NoError(t, log.validate())
	})

	tests := []struct {
		name string
		log  LogGroup
		want error
	}{
		{"empty URL", LogGroup{PublicKey: key}, ErrLogURLInvalid},
		{"relative URL", LogGroup{URL: "/ct/v1", PublicKey: key}, ErrLogURLInvalid},
		{"unsupported scheme", LogGroup{URL: "ftp://log.example.com", PublicKey: key}, ErrLogURLInvalid},
		{"unparsable URL", LogGroup{URL: "https://log example.com/%zz", PublicKey: key}, ErrLogURLInvalid},
		{"no key", LogGroup{URL: "https://log.example.com"}, ErrLogPublicKeyMissing},
		{"P-384 key", LogGroup{URL: "https://log.example.com", PublicKey: newP384Key(t).Public()}, ErrLogPublicKeyUnsupported},
		{"RSA-1024 key", LogGroup{URL: "https://log.example.com", PublicKey: newRSAKey(t, 1024).Public()}, ErrLogPublicKeyUnsupported},
		{"key of another type", LogGroup{URL: "https://log.example.com", PublicKey: "not a key"}, ErrLogPublicKeyUnsupported},
		{"configured log ID of another key", LogGroup{URL: "https://log.example.com", PublicKey: key, LogID: [32]byte{1}}, ErrLogIDMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.log.validate()
			assert.ErrorIs(t, err, tt.want)
			assert.ErrorIs(t, err, ErrInvalidLogConfig)
			var configErr *LogConfigError
			require.ErrorAs(t, err, &configErr)
			assert.Equal(t, tt.log.URL, configErr.LogURL)
			assert.Contains(t, err.Error(), tt.want.Error())
		})
	}
}

func TestPolicyConfig_Enabled(t *testing.T) {
	config := PolicyConfig{LogGroups: createTestLogGroups(t)}
	assert.True(t, config.Enabled())

	for i := range config.LogGroups {
		config.LogGroups[i].Enabled = false
	}
	assert.False(t, config.Enabled())

	var empty PolicyConfig
	assert.False(t, empty.Enabled())
}

func TestNewCTPolicy_LogConfig(t *testing.T) {
	t.Run("CT is off when no log is enabled", func(t *testing.T) {
		logs := createTestLogGroups(t)
		for i := range logs {
			logs[i].Enabled = false
		}
		_, err := NewCTPolicy(PolicyConfig{MinSCTs: 1, MinOperators: 1, LogGroups: logs}, NewMockLogSubmitter())
		assert.ErrorIs(t, err, ErrNoLogsConfigured)
	})

	t.Run("derived log IDs are kept", func(t *testing.T) {
		logs := createTestLogGroups(t)
		policy, err := NewCTPolicy(PolicyConfig{MinSCTs: 1, MinOperators: 1, LogGroups: logs}, NewMockLogSubmitter())
		require.NoError(t, err)
		for i, log := range policy.Config().LogGroups {
			want, err := KeyToLogID(logs[i].PublicKey)
			require.NoError(t, err)
			assert.Equal(t, want, log.LogID)
		}
	})

	t.Run("invalid log refused", func(t *testing.T) {
		logs := createTestLogGroups(t)
		logs[1].PublicKey = nil
		_, err := NewCTPolicy(PolicyConfig{MinSCTs: 1, MinOperators: 1, LogGroups: logs}, NewMockLogSubmitter())
		assert.ErrorIs(t, err, ErrLogPublicKeyMissing)
	})

	duplicates := map[string]func(logs []LogGroup){
		"duplicate URL": func(logs []LogGroup) { logs[1].URL = logs[0].URL },
		"duplicate key": func(logs []LogGroup) { logs[1].PublicKey = logs[0].PublicKey },
	}
	for name, duplicate := range duplicates {
		t.Run(name, func(t *testing.T) {
			logs := createTestLogGroups(t)
			duplicate(logs)
			_, err := NewCTPolicy(PolicyConfig{MinSCTs: 1, MinOperators: 1, LogGroups: logs}, NewMockLogSubmitter())
			assert.ErrorIs(t, err, ErrDuplicateLog)
			assert.ErrorIs(t, err, ErrInvalidLogConfig)
		})
	}
}
