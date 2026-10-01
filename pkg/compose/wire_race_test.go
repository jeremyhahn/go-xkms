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

package compose

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// storeReaders returns one read through the XKMSService for every store
// Stores.Wire publishes.
func storeReaders(ctx context.Context, svc *xkms.XKMSService) map[string]func() error {
	return map[string]func() error{
		"platform store": func() error {
			_, err := svc.SealStoreList(ctx)
			return err
		},
		"barrier": func() error { _, err := svc.BarrierStatus(ctx); return err },
		"pin":     func() error { _, err := svc.GetLockoutStatus(ctx); return err },
		"passwords": func() error {
			_, err := svc.PasswordStoreStatus(ctx)
			return err
		},
		"custody":     func() error { _, err := svc.ListCustodianGroups(ctx); return err },
		"shares":      func() error { _, err := svc.ListShares(ctx); return err },
		"credentials": func() error { _, err := svc.ListCredentials(ctx); return err },
		"oidc credentials": func() error {
			_, err := svc.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{})
			return err
		},
		"ca": func() error {
			_, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
			return err
		},
	}
}

// TestWire_ConcurrentWithServiceReads wires every store into a shared
// XKMSService while every store is being read through it, the way a host's
// module composes its stores on first use while other transports already
// serve. Under -race it proves the setters and readers share no unsynchronized
// memory; without -race it still proves a read sees either "not configured"
// or the wired store, never anything else, and that every store answers once
// wiring is done.
func TestWire_ConcurrentWithServiceReads(t *testing.T) {
	svc := hostdeps.NewService(t)
	st, err := Build(context.Background(), fullDeps(t, svc))
	require.NoError(t, err)
	require.Len(t, st.Disabled, 1, "only the TPM policy service, which needs a TPM, is off")
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	ctx := platformCtx()
	readers := storeReaders(ctx, svc)

	const rounds = 25
	start := make(chan struct{})
	unexpected := make(chan error, len(readers)*rounds)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range rounds {
			st.Wire(svc)
		}
	}()
	for name, read := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				if err := read(); err != nil && !errors.Is(err, xkms.ErrNotConfigured) {
					unexpected <- &readError{store: name, err: err}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(unexpected)

	for err := range unexpected {
		t.Errorf("a read racing the wiring failed: %v", err)
	}
	for name, read := range readers {
		require.NoError(t, read(), "%s must answer once wiring is done", name)
	}
}

// readError names the store a racing read failed on.
type readError struct {
	store string
	err   error
}

func (e *readError) Error() string { return e.store + ": " + e.err.Error() }

func (e *readError) Unwrap() error { return e.err }
