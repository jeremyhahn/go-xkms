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

package xkms

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// bootstrapListenerKeyState guards the published trust-bootstrap listener
// public keys with its own mutex; see the field comment on XKMSService.
type bootstrapListenerKeyState struct {
	mu   sync.RWMutex
	keys *transport.BootstrapListenerKeysResponse
}

// SetBootstrapListenerKeys publishes the trust-bootstrap listener's public
// keys, making them visible to BootstrapListenerKeys. Called by pkg/server
// once the listener's Start succeeds; keys is copied so the caller's own
// reference stays theirs to reuse or discard.
func (s *XKMSService) SetBootstrapListenerKeys(keys *transport.BootstrapListenerKeysResponse) {
	if keys == nil {
		return
	}
	published := *keys
	s.bootstrapListenerKeys.mu.Lock()
	defer s.bootstrapListenerKeys.mu.Unlock()
	s.bootstrapListenerKeys.keys = &published
}

// ClearBootstrapListenerKeys withdraws the published keys, e.g. when the
// bootstrap listener stops during server shutdown. After this call
// BootstrapListenerKeys reports ErrBootstrapListenerNotEnabled again.
func (s *XKMSService) ClearBootstrapListenerKeys() {
	s.bootstrapListenerKeys.mu.Lock()
	defer s.bootstrapListenerKeys.mu.Unlock()
	s.bootstrapListenerKeys.keys = nil
}

// BootstrapListenerKeys returns the running trust-bootstrap listener's
// public static keys. Only public material is ever returned — see
// pkg/server/bootstrap_key_custody.go for the private-key custody that
// never leaves the server process.
//
// Returns ErrBootstrapListenerNotEnabled when no listener has published its
// keys: either none is configured for this server, or startup has not yet
// reached publication.
func (s *XKMSService) BootstrapListenerKeys(ctx context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	s.bootstrapListenerKeys.mu.RLock()
	defer s.bootstrapListenerKeys.mu.RUnlock()
	if s.bootstrapListenerKeys.keys == nil {
		return nil, ErrBootstrapListenerNotEnabled
	}
	// Copy out: the caller must not be able to mutate the published response
	// through a pointer this service keeps handing out.
	resp := *s.bootstrapListenerKeys.keys
	return &resp, nil
}
