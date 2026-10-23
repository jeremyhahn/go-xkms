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
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPLogSubmitter(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		submitter := NewHTTPLogSubmitter(nil)
		require.NotNil(t, submitter)
		require.NotNil(t, submitter.client)
	})

	t.Run("custom client", func(t *testing.T) {
		customClient := &http.Client{Timeout: 60 * time.Second}
		submitter := NewHTTPLogSubmitter(customClient)
		require.NotNil(t, submitter)
		assert.Equal(t, customClient, submitter.client)
	})
}

func TestHTTPLogSubmitter_SubmitPrecert(t *testing.T) {
	ca, caKey := newTestCA(t, "Test CA")
	entry := newTestPrecert(t, ca, caKey, nil, nil)
	submitter := NewHTTPLogSubmitter(nil)
	ctx := context.Background()

	// submitVerified submits entry to a log holding key and checks the
	// verified SCT it returns.
	submitVerified := func(t *testing.T, key crypto.Signer, entry testPrecert, sigAlg SignatureAlgorithm) {
		t.Helper()
		log := newTestCTLog(t, key, entry)
		sct, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, log.group())
		require.NoError(t, err)

		spki, err := x509.MarshalPKIXPublicKey(key.Public())
		require.NoError(t, err)
		assert.Equal(t, V1, sct.Version)
		assert.Equal(t, sha256.Sum256(spki), sct.LogID)
		assert.Equal(t, testTimestamp, sct.Timestamp)
		assert.Equal(t, HashAlgorithmSHA256, sct.Signature.HashAlgorithm)
		assert.Equal(t, sigAlg, sct.Signature.SigAlgorithm)
	}

	t.Run("ECDSA P-256 log", func(t *testing.T) {
		submitVerified(t, newP256Key(t), entry, SignatureAlgorithmECDSA)
	})

	t.Run("RSA-2048 log", func(t *testing.T) {
		submitVerified(t, newRSAKey(t, 2048), entry, SignatureAlgorithmRSA)
	})

	t.Run("precertificate signing certificate", func(t *testing.T) {
		psc, pscKey := newPrecertSigningCert(t, ca, caKey)
		submitVerified(t, newP256Key(t), newTestPrecert(t, ca, caKey, psc, pscKey), SignatureAlgorithmECDSA)
	})

	t.Run("trailing slash URL", func(t *testing.T) {
		log := newTestCTLog(t, newP256Key(t), entry)
		group := log.group()
		group.URL += "/"
		_, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, group)
		require.NoError(t, err)
	})

	t.Run("signed extensions", func(t *testing.T) {
		log := newTestCTLog(t, newP256Key(t), entry)
		log.extensions = []byte{0x00, 0x01, 0x02}
		sct, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, log.group())
		require.NoError(t, err)
		assert.Equal(t, log.extensions, sct.Extensions)
	})

	t.Run("log configuration refused before submitting", func(t *testing.T) {
		tests := []struct {
			name string
			key  crypto.PublicKey
			want error
		}{
			{"no public key", nil, ErrLogPublicKeyMissing},
			{"P-384 key", newP384Key(t).Public(), ErrLogPublicKeyUnsupported},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				log := newTestCTLog(t, newP256Key(t), entry)
				group := log.group()
				group.PublicKey = tt.key
				_, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, group)
				assert.ErrorIs(t, err, tt.want)
				assert.ErrorIs(t, err, ErrInvalidLogConfig)
				assert.Zero(t, log.requests.Load())
			})
		}
	})

	t.Run("SCT refused", func(t *testing.T) {
		otherSPKI, err := x509.MarshalPKIXPublicKey(newP256Key(t).Public())
		require.NoError(t, err)
		otherLogID := sha256.Sum256(otherSPKI)

		tests := []struct {
			name string
			edit func(*addPrecertChainResponse)
			want error
		}{
			{"log ID of another log", func(resp *addPrecertChainResponse) {
				resp.ID = base64.StdEncoding.EncodeToString(otherLogID[:])
			}, ErrSCTLogIDMismatch},
			{"SHA-384 hash", withSignature(func(sig []byte) {
				sig[0] = byte(HashAlgorithmSHA384)
			}), ErrUnsupportedSCTAlgorithm},
			{"RSA signature from an ECDSA log", withSignature(func(sig []byte) {
				sig[1] = byte(SignatureAlgorithmRSA)
			}), ErrUnsupportedSCTAlgorithm},
			{"tampered signature", withSignature(func(sig []byte) {
				sig[len(sig)-1] ^= 0x01
			}), ErrInvalidSignature},
			{"tampered timestamp", func(resp *addPrecertChainResponse) {
				resp.Timestamp++
			}, ErrInvalidSignature},
			{"unsigned extensions", func(resp *addPrecertChainResponse) {
				resp.Extensions = base64.StdEncoding.EncodeToString([]byte{0x01})
			}, ErrInvalidSignature},
			{"unknown SCT version", func(resp *addPrecertChainResponse) {
				resp.SCTVersion = V1 + 1
			}, ErrInvalidSCT},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				log := newTestCTLog(t, newP256Key(t), entry)
				log.edit = tt.edit
				sct, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, log.group())
				assert.ErrorIs(t, err, tt.want)
				assert.Nil(t, sct)
			})
		}
	})

	t.Run("SCT signed over another precertificate", func(t *testing.T) {
		other := newTestPrecert(t, ca, caKey, nil, nil)
		log := newTestCTLog(t, newP256Key(t), other)
		log.entry.der = entry.der
		_, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, log.group())
		assert.ErrorIs(t, err, ErrInvalidSignature)
	})

	t.Run("malformed response", func(t *testing.T) {
		tests := []struct {
			name string
			edit func(*addPrecertChainResponse)
		}{
			{"log ID not base64", func(resp *addPrecertChainResponse) {
				resp.ID = "!!"
			}},
			{"log ID wrong length", func(resp *addPrecertChainResponse) {
				resp.ID = base64.StdEncoding.EncodeToString(make([]byte, 16))
			}},
			{"extensions not base64", func(resp *addPrecertChainResponse) {
				resp.Extensions = "!!"
			}},
			{"signature not base64", func(resp *addPrecertChainResponse) {
				resp.Signature = "!!"
			}},
			{"signature too short", func(resp *addPrecertChainResponse) {
				resp.Signature = base64.StdEncoding.EncodeToString([]byte{0x04, 0x03})
			}},
			{"signature data incomplete", func(resp *addPrecertChainResponse) {
				resp.Signature = base64.StdEncoding.EncodeToString([]byte{0x04, 0x03, 0x00, 0x10, 0x01})
			}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				log := newTestCTLog(t, newP256Key(t), entry)
				log.edit = tt.edit
				_, err := submitter.SubmitPrecert(ctx, entry.der, entry.chain, log.group())
				var caErr *caerrors.TrustedCAError
				assert.ErrorAs(t, err, &caErr)
			})
		}
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		log := newTestCTLog(t, newP256Key(t), entry)
		expired, cancel := context.WithDeadline(ctx, time.Unix(0, 0))
		defer cancel()
		_, err := submitter.SubmitPrecert(expired, entry.der, entry.chain, log.group())
		assert.ErrorIs(t, err, ErrCTSubmissionTimeout)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Zero(t, log.requests.Load())
	})

	t.Run("transport failure", func(t *testing.T) {
		failing := func(t *testing.T, handler http.HandlerFunc) LogGroup {
			t.Helper()
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)
			return LogGroup{URL: server.URL, PublicKey: newP256Key(t).Public(), Enabled: true}
		}
		closed := httptest.NewServer(http.NotFoundHandler())
		closed.Close()
		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		tests := []struct {
			name string
			ctx  context.Context
			log  LogGroup
		}{
			{"HTTP error status", ctx, failing(t, func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "log unavailable", http.StatusServiceUnavailable)
			})},
			{"invalid JSON", ctx, failing(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, err := w.Write([]byte("{not json"))
				assert.NoError(t, err)
			})},
			{"cancelled context", cancelled, newTestCTLog(t, newP256Key(t), entry).group()},
			{"log unreachable", ctx, LogGroup{URL: closed.URL, PublicKey: newP256Key(t).Public(), Enabled: true}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := submitter.SubmitPrecert(tt.ctx, entry.der, entry.chain, tt.log)
				var caErr *caerrors.TrustedCAError
				assert.ErrorAs(t, err, &caErr)
			})
		}
	})
}

// withSignature returns a response edit that changes the encoded
// digitally-signed struct: hash, signature algorithm, length, signature.
func withSignature(edit func(sig []byte)) func(*addPrecertChainResponse) {
	return func(resp *addPrecertChainResponse) {
		sig, err := base64.StdEncoding.DecodeString(resp.Signature)
		if err != nil {
			resp.Signature = ""
			return
		}
		edit(sig)
		resp.Signature = base64.StdEncoding.EncodeToString(sig)
	}
}

func TestMockLogSubmitter(t *testing.T) {
	t.Run("basic submission", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{
			Name:     "Test Log",
			Operator: "Test Op",
			URL:      "https://test.example.com",
		}

		precertDER := []byte("test-precert-data")
		chain := [][]byte{[]byte("issuer-cert")}

		sct, err := submitter.SubmitPrecert(context.Background(), precertDER, chain, log)
		require.NoError(t, err)
		require.NotNil(t, sct)

		assert.Equal(t, V1, sct.Version)
		assert.NotZero(t, sct.Timestamp)
	})

	t.Run("configured SCT", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{URL: "https://test.example.com"}
		expectedSCT := &SignedCertificateTimestamp{
			Version:   V1,
			Timestamp: 12345678,
		}

		submitter.SetSCT(log.URL, expectedSCT)

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)

		assert.Equal(t, expectedSCT.Timestamp, sct.Timestamp)
	})

	t.Run("configured error", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{URL: "https://test.example.com"}
		expectedErr := errors.New("submission failed")

		submitter.SetError(log.URL, expectedErr)

		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("delay simulation", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		submitter.Delay = 100 * time.Millisecond

		log := LogGroup{URL: "https://test.example.com"}

		start := time.Now()
		_, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	})

	t.Run("context cancellation during delay", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		submitter.Delay = 1 * time.Second

		log := LogGroup{URL: "https://test.example.com"}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := submitter.SubmitPrecert(ctx, []byte("test"), nil, log)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("submission tracking", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log1 := LogGroup{URL: "https://log1.example.com", Name: "Log1"}
		log2 := LogGroup{URL: "https://log2.example.com", Name: "Log2"}

		_, _ = submitter.SubmitPrecert(context.Background(), []byte("cert1"), nil, log1)
		_, _ = submitter.SubmitPrecert(context.Background(), []byte("cert2"), [][]byte{[]byte("chain")}, log2)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 2)

		assert.Equal(t, []byte("cert1"), submissions[0].PrecertDER)
		assert.Equal(t, "Log1", submissions[0].Log.Name)

		assert.Equal(t, []byte("cert2"), submissions[1].PrecertDER)
		assert.Equal(t, "Log2", submissions[1].Log.Name)
		assert.Len(t, submissions[1].Chain, 1)
	})

	t.Run("reset", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{URL: "https://test.example.com"}

		submitter.SetSCT(log.URL, &SignedCertificateTimestamp{})
		submitter.SetError(log.URL, errors.New("error"))
		_, _ = submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)

		// Reset clears everything
		submitter.Reset()

		assert.Empty(t, submitter.SCTs)
		assert.Empty(t, submitter.Errors)
		assert.Empty(t, submitter.Submissions)
	})

	t.Run("log ID from LogGroup", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		var customLogID [32]byte
		for i := range customLogID {
			customLogID[i] = byte(i)
		}

		log := LogGroup{
			URL:   "https://test.example.com",
			LogID: customLogID,
		}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)

		assert.Equal(t, customLogID, sct.LogID)
	})

	t.Run("log ID generated from URL when not set", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		log := LogGroup{
			URL: "https://test.example.com",
			// LogID is zero value
		}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)

		// Log ID should be SHA-256 of URL
		assert.NotEqual(t, [32]byte{}, sct.LogID)
	})

	t.Run("submission with nil chain", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
		require.NoError(t, err)
		require.NotNil(t, sct)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 1)
		assert.Nil(t, submissions[0].Chain)
	})

	t.Run("submission with empty chain", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		sct, err := submitter.SubmitPrecert(context.Background(), []byte("test"), [][]byte{}, log)
		require.NoError(t, err)
		require.NotNil(t, sct)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 1)
		assert.Empty(t, submissions[0].Chain)
	})

	t.Run("multiple submissions to same log", func(t *testing.T) {
		submitter := NewMockLogSubmitter()
		log := LogGroup{URL: "https://test.example.com"}

		_, err := submitter.SubmitPrecert(context.Background(), []byte("cert1"), nil, log)
		require.NoError(t, err)

		_, err = submitter.SubmitPrecert(context.Background(), []byte("cert2"), nil, log)
		require.NoError(t, err)

		submissions := submitter.GetSubmissions()
		require.Len(t, submissions, 2)
	})

	t.Run("concurrent submissions thread-safe", func(t *testing.T) {
		submitter := NewMockLogSubmitter()

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				log := LogGroup{URL: "https://test.example.com"}
				_, _ = submitter.SubmitPrecert(context.Background(), []byte("test"), nil, log)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		submissions := submitter.GetSubmissions()
		assert.Len(t, submissions, 10)
	})
}
