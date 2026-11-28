package webauthn

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// barrierCredStore holds each GetByCredentialID until every expected reader
// has read, so concurrent assertions all check the same stored counter.
type barrierCredStore struct {
	CredentialStore
	readers *sync.WaitGroup
}

func (s *barrierCredStore) GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error) {
	cred, err := s.CredentialStore.GetByCredentialID(ctx, credID)
	s.readers.Done()
	s.readers.Wait()
	return cred, err
}

// TestVerifyAssertion_ConcurrentCounterAtomic proves two assertions that read
// the same stored counter cannot both succeed and the counter never decreases.
func TestVerifyAssertion_ConcurrentCounterAtomic(t *testing.T) {
	ctx := context.Background()
	users, creds := newTestStores(t)
	readers := &sync.WaitGroup{}
	readers.Add(2)
	svc, err := NewService(ServiceParams{
		Config:          validTestConfig(),
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: &barrierCredStore{CredentialStore: creds, readers: readers},
	})
	require.NoError(t, err)

	m, err := NewMockAuthenticator("example.com", WithSignCount(2))
	require.NoError(t, err)
	require.NoError(t, creds.Save(ctx, storedCredentialFor(t, m, 2)))
	challenge := []byte("caller-held-challenge")
	high := signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)
	resignWithCount(t, m, high, 10)
	low := signedAssertion(t, m, "webauthn.get", challenge, assertionOrigin)
	resignWithCount(t, m, low, 5)

	counters := []uint32{10, 5}
	errs := make([]error, 2)
	var done sync.WaitGroup
	for i, a := range []*AssertionVerification{
		{Challenge: challenge, Credential: storedCredentialFor(t, m, 2), Assertion: high},
		{Challenge: challenge, Credential: storedCredentialFor(t, m, 2), Assertion: low},
	} {
		done.Add(1)
		go func() {
			defer done.Done()
			_, errs[i] = svc.VerifyAssertion(ctx, a)
		}()
	}
	done.Wait()

	saved, err := creds.GetByCredentialID(ctx, m.CredentialID)
	require.NoError(t, err)
	succeeded := 0
	for i, e := range errs {
		if e == nil {
			succeeded++
			assert.Equal(t, counters[i], saved.Authenticator.SignCount)
		} else {
			assert.True(t, IsVerificationFailed(e), "refusal %d: %v", i, e)
		}
	}
	assert.LessOrEqual(t, succeeded, 1)
	assert.GreaterOrEqual(t, saved.Authenticator.SignCount, uint32(2))
}
