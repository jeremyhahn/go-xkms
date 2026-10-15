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

package authenticator

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUserPresenceHandlerConcurrentSwap exercises the presence handler under
// the race detector. The GUI swaps it from the Wails UI goroutine when the
// virtual FIDO2 device starts or stops, while the UHID bridge goroutine may be
// mid-command — and an interface value is two words, so an unsynchronized read
// can tear and call into a handler that never existed.
//
// SetUserPresenceHandler and requestUserPresence hold the authenticator lock;
// this test is what fails if either loses it.
func TestUserPresenceHandlerConcurrentSwap(t *testing.T) {
	const iterations = 200

	config := DefaultConfig()
	config.UserPresenceHandler = NewAutoGrantHandler()
	config.Storage = NewMemoryStorage()
	config.EnablePIN = false
	config.MaxCredentials = iterations + 1
	config.UserPresenceHandler = NewAutoGrantHandler()

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			auth.SetUserPresenceHandler(NewAutoGrantHandler())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			clientDataHash := sha256.Sum256([]byte(fmt.Sprintf("swap-%d", i)))
			_, mcErr := auth.MakeCredential(
				clientDataHash[:],
				RelyingParty{ID: "example.com", Name: "Example Corp"},
				User{ID: []byte("user-1"), Name: "user@example.com", DisplayName: "User"},
				[]PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}},
				&MakeCredentialOptions{Options: map[string]bool{"rk": false}},
			)
			require.NoError(t, mcErr)
		}
	}()

	wg.Wait()
}
