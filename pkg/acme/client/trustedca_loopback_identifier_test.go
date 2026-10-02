//go:build codec_json

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

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// newTestStorageFactory returns a real, in-memory-backed storage.Factory —
// the same production objstore/kvadapter composition
// pkg/acme/server/handlers' own tests use — so the tests below persist and
// retrieve genuine accounts, orders, authorizations and challenges rather
// than programming a mock's call expectations.
func newTestStorageFactory(t *testing.T) storage.Factory {
	t.Helper()
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)
	return factory
}

// startLoopbackIdentifierTrustedCA starts a TrustedCA whose ACME server
// enrollment challenges are gated by allowLoopback
// (TCAACMEConfig.AllowLoopbackIdentifier), using a real storage factory and a
// no-op "enroll-01" verifier. It returns the running instance, its storage
// factory and external URL, and a cleanup func that cancels Serve and waits
// for it to return.
func startLoopbackIdentifierTrustedCA(t *testing.T, allowLoopback bool) (tca *TrustedCA, factory storage.Factory, externalURL string) {
	t.Helper()

	acmePort := getAvailablePort(t)
	externalURL = fmt.Sprintf("https://127.0.0.1:%d", acmePort)
	factory = newTestStorageFactory(t)

	cfg := validConfig()
	cfg.ACME.HTTPSAddr = fmt.Sprintf("127.0.0.1:%d", acmePort)
	cfg.ACME.ExternalURL = externalURL
	cfg.ACME.AllowLoopbackIdentifier = allowLoopback

	// An attesting verifier that attests the order's own identifier: this
	// test is about the loopback substitution, not the identity comparison.
	attesting := map[string]acmecommon.AttestingVerifier{
		"enroll-01": acmecommon.AttestingVerifierFunc(func(
			_ *net.Resolver, _ acmecommon.CertificateAuthority, c acmecommon.AttestationChallenge,
		) (*acmecommon.AttestedIdentity, error) {
			return &acmecommon.AttestedIdentity{Identifier: c.IdentifierValue}, nil
		}),
	}

	var err error
	tca, err = New(
		WithCA(newMockCA()),
		WithStorageFactory(factory),
		WithConfig(cfg),
		WithAttestingVerifiers(attesting),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- tca.Serve(ctx)
	}()

	// Wait for the actual readiness signal the test needs — Serve has
	// published the REST service — rather than the TCP listener accepting a
	// connection: a successful dial says the socket is open, not that
	// tca.restService (or anything Serve initialized before it) is visible
	// to this goroutine. RestService() is mutex-guarded, so once it stops
	// returning nil every field the running service holds is safe to read
	// here (#140).
	waitFor(t, "rest service ready", func() bool {
		return tca.RestService() != nil
	})

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Serve did not return after context cancellation")
		}
	})

	return tca, factory, externalURL
}

// loopbackTestKey is an account keypair signed JWS requests are built from.
type loopbackTestKey struct {
	private *ecdsa.PrivateKey
}

func newLoopbackTestKey(t *testing.T) *loopbackTestKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &loopbackTestKey{private: priv}
}

// createLoopbackTestAccount saves an account directly through the storage
// factory, exactly as an ACME newAccount request would persist it, so the
// JWS requests below authenticate against a real, stored account.
func createLoopbackTestAccount(t *testing.T, factory storage.Factory, externalURL string, key *loopbackTestKey) *entities.ACMEAccount {
	t.Helper()

	accountDAO, err := factory.AccountDAO()
	require.NoError(t, err)

	pubKeyPEM, err := encoding.EncodePublicKeyPEM(key.private.Public())
	require.NoError(t, err)

	accountID, err := handlers.AccountIDFromPublicKey(key.private.Public())
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:                   accountID,
		Status:               acmecommon.StatusValid,
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
		Key:                  string(pubKeyPEM),
		CreatedAt:            time.Now(),
		Orders:               fmt.Sprintf("%s/acme/account/%d/orders", externalURL, accountID),
		URL:                  fmt.Sprintf("%s/acme/account/%d", externalURL, accountID),
	}
	require.NoError(t, accountDAO.Save(context.Background(), account))
	return account
}

// createLoopbackEnrollmentChallenge saves an order, a permanent-identifier
// authorization and a pending enroll-01 challenge, and returns the
// challenge's URL.
func createLoopbackEnrollmentChallenge(t *testing.T, factory storage.Factory, externalURL string, account *entities.ACMEAccount, identifierValue string) (challengeURL string) {
	t.Helper()
	ctx := context.Background()

	orderDAO, err := factory.OrderDAO(account.ID)
	require.NoError(t, err)
	orderID, err := handlers.GenerateID()
	require.NoError(t, err)
	order := &entities.ACMEOrder{
		ID:      orderID,
		Status:  acmecommon.StatusPending,
		Expires: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifiers: []entities.ACMEIdentifier{
			{Type: acmecommon.AuthzTypePermanentIdentifier, Value: identifierValue},
		},
		AccountID: account.ID,
	}
	order.URL = fmt.Sprintf("%s/acme/order/%d", externalURL, order.ID)
	order.Finalize = fmt.Sprintf("%s/acme/finalize/%d", externalURL, order.ID)
	require.NoError(t, orderDAO.Save(ctx, order))

	authzDAO, err := factory.AuthorizationDAO(account.ID)
	require.NoError(t, err)
	authzID, err := handlers.GenerateID()
	require.NoError(t, err)
	challengeID, err := handlers.GenerateID()
	require.NoError(t, err)

	challenge := entities.ACMEChallenge{
		ID:              challengeID,
		Type:            "enroll-01",
		Status:          acmecommon.StatusPending,
		Token:           fmt.Sprintf("test-token-%d", challengeID),
		AccountID:       account.ID,
		AuthorizationID: authzID,
		URL:             fmt.Sprintf("%s/acme/challenge/%d", externalURL, challengeID),
	}

	authz := &entities.ACMEAuthorization{
		ID:         authzID,
		Identifier: entities.ACMEIdentifier{Type: acmecommon.AuthzTypePermanentIdentifier, Value: identifierValue},
		Status:     acmecommon.StatusPending,
		Expires:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		AccountID:  account.ID,
		OrderID:    order.ID,
		Challenges: []entities.ACMEChallenge{challenge},
		URL:        fmt.Sprintf("%s/acme/authz/%d", externalURL, authzID),
	}
	require.NoError(t, authzDAO.Save(ctx, authz))

	order.Authorizations = append(order.Authorizations, authz.URL)
	require.NoError(t, orderDAO.Save(ctx, order))

	return challenge.URL
}

// signedChallengeRequest builds a JWS-signed POST request for url, using a
// fresh Replay-Nonce obtained from the running service's own NewNonceHandler
// so the request authenticates through the real, unexported nonce store.
func signedChallengeRequest(t *testing.T, restService handlers.RestServicer, key *loopbackTestKey, url string, accountID uint64) *http.Request {
	t.Helper()

	nonceRec := httptest.NewRecorder()
	restService.NewNonceHandler(nonceRec, httptest.NewRequest(http.MethodHead, url, nil))
	nonce := nonceRec.Header().Get("Replay-Nonce")
	require.NotEmpty(t, nonce, "NewNonceHandler must return a Replay-Nonce header")

	signerOpts := &jose.SignerOptions{
		NonceSource: staticNonceSourceFunc(nonce),
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
			"kid": accountKID(url, accountID),
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.private}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign([]byte(""))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")
	return req
}

// accountKID renders the account URL (the ACME "kid") from the base URL
// implied by url (scheme://host) and the account ID.
func accountKID(challengeURL string, accountID uint64) string {
	idx := strings.Index(challengeURL[len("https://"):], "/")
	base := challengeURL[:len("https://")+idx]
	return fmt.Sprintf("%s/acme/account/%d", base, accountID)
}

type staticNonceSourceFunc string

func (s staticNonceSourceFunc) Nonce() (string, error) { return string(s), nil }

// TestTrustedCA_Serve_LoopbackIdentifier proves TCAACMEConfig.AllowLoopbackIdentifier
// reaches the embedded ACME REST service's ChallengeHandler through Serve:
// off by default, an enroll-01 challenge whose permanent-identifier is
// 127.0.0.1 is refused; set true, it validates (#140).
func TestTrustedCA_Serve_LoopbackIdentifier(t *testing.T) {
	t.Run("refused by default", func(t *testing.T) {
		tca, factory, externalURL := startLoopbackIdentifierTrustedCA(t, false)

		key := newLoopbackTestKey(t)
		account := createLoopbackTestAccount(t, factory, externalURL, key)
		challengeURL := createLoopbackEnrollmentChallenge(t, factory, externalURL, account, "127.0.0.1")

		req := signedChallengeRequest(t, tca.RestService(), key, challengeURL, account.ID)
		resp := httptest.NewRecorder()
		tca.RestService().ChallengeHandler(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		var body struct {
			Status string          `json:"status"`
			Error  *entities.Error `json:"error"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		require.Equal(t, acmecommon.StatusInvalid, body.Status)
		require.NotNil(t, body.Error)
		require.Contains(t, body.Error.Detail, handlers.ErrLoopbackIdentifierNotAllowed.Error())
	})

	t.Run("allowed when configured", func(t *testing.T) {
		tca, factory, externalURL := startLoopbackIdentifierTrustedCA(t, true)

		key := newLoopbackTestKey(t)
		account := createLoopbackTestAccount(t, factory, externalURL, key)
		challengeURL := createLoopbackEnrollmentChallenge(t, factory, externalURL, account, "127.0.0.1")

		req := signedChallengeRequest(t, tca.RestService(), key, challengeURL, account.ID)
		resp := httptest.NewRecorder()
		tca.RestService().ChallengeHandler(resp, req)

		require.Equal(t, http.StatusOK, resp.Code)
		var body struct {
			Status string `json:"status"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		require.Equal(t, acmecommon.StatusValid, body.Status)
	})
}
