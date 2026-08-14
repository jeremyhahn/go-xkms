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

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// stubAuthenticator is an Authenticator that reports a fixed name and either
// admits a fixed identity or refuses.
type stubAuthenticator struct {
	name string
	err  error
}

func (s *stubAuthenticator) AuthenticateHTTP(*http.Request) (*Identity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &Identity{Subject: s.name}, nil
}

func (s *stubAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*Identity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &Identity{Subject: s.name}, nil
}

func (s *stubAuthenticator) Name() string { return s.name }

// TestLiveAuthenticator_StoreSwapsDelegate is the property the type exists for:
// a caller holding the value from before the swap decides with the
// authenticator installed after it. A transport captures its Authenticator at
// construction, so this is what lets a reload reach a running listener.
func TestLiveAuthenticator_StoreSwapsDelegate(t *testing.T) {
	permissive := &stubAuthenticator{name: "permissive"}
	strict := &stubAuthenticator{name: "strict", err: errors.New("denied")}

	live := NewLiveAuthenticator(permissive)

	// A transport would capture the holder once, exactly like this.
	var captured Authenticator = live

	id, err := captured.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NoError(t, err)
	assert.Equal(t, "permissive", id.Subject)
	assert.Equal(t, "permissive", captured.Name(), "Name must report the delegate, not the holder")

	live.Store(strict)

	_, err = captured.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Error(t, err, "the captured holder must enforce the authenticator installed after capture")
	assert.Equal(t, "strict", captured.Name())

	_, err = captured.AuthenticateGRPC(context.Background(), metadata.MD{})
	assert.Error(t, err, "the gRPC path must swap with the HTTP path")
}

// TestLiveAuthenticator_FailsClosed pins that a holder with no delegate refuses
// rather than admits. Tightening authentication must never be able to produce
// an "authenticator" that lets everyone through.
func TestLiveAuthenticator_FailsClosed(t *testing.T) {
	cases := map[string]*LiveAuthenticator{
		"never stored":  {},
		"stored nil":    NewLiveAuthenticator(nil),
		"cleared":       NewLiveAuthenticator(&stubAuthenticator{name: "gone"}),
		"nil receiver":  nil,
		"zero delegate": {},
	}
	cases["cleared"].Store(nil)

	for name, live := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := live.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/", nil))
			require.Error(t, err, "must not admit a request with no delegate")
			assert.True(t, errors.Is(err, ErrNoAuthenticator), "want ErrNoAuthenticator, got %v", err)

			_, err = live.AuthenticateGRPC(context.Background(), metadata.MD{})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNoAuthenticator), "want ErrNoAuthenticator, got %v", err)

			assert.Equal(t, "none", live.Name())
			assert.Nil(t, live.Load())
		})
	}
}

// TestLiveAuthenticator_ConcurrentSwap runs authentications against a holder
// while it is being swapped. A reload happens on a live server, so the swap
// races real traffic by construction; this must be race-free (run with -race)
// and must never yield a nil identity with a nil error.
func TestLiveAuthenticator_ConcurrentSwap(t *testing.T) {
	a := &stubAuthenticator{name: "a"}
	b := &stubAuthenticator{name: "b"}
	live := NewLiveAuthenticator(a)

	var wg sync.WaitGroup
	const rounds = 200

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if i%2 == 0 {
				live.Store(b)
			} else {
				live.Store(a)
			}
		}
	}()

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				id, err := live.AuthenticateHTTP(httptest.NewRequest(http.MethodGet, "/", nil))
				if err != nil {
					continue
				}
				// A successful authentication must always carry an identity;
				// a nil identity with a nil error would admit an anonymous
				// caller as authenticated.
				require.NotNil(t, id)
				require.Contains(t, []string{"a", "b"}, id.Subject)
			}
		}()
	}

	wg.Wait()
}
