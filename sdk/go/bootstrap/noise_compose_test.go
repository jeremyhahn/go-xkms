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

package bootstrap

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// TestSDKNoiseSurfaceComposes walks the whole protected-key flow using only
// what this package re-exports, because that is the only surface consumers
// are allowed to use.
//
// A test that only constructs a key proves nothing here. This one performs
// every step a consumer performs, in order. Under GODEBUG=fips140=only the
// first step must be the typed X25519 refusal, re-exported here so a
// consumer can recognise it; the flow then runs under fips140=off.
func TestSDKNoiseSurfaceComposes(t *testing.T) {
	key, err := GenerateNoiseStaticKey()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrNoiseFIPSUnsupported) {
		return
	}
	if err != nil {
		t.Fatalf("GenerateNoiseStaticKey: %v", err)
	}
	defer key.Destroy()

	// 1. Hand the protected key to the server config.
	cfg := &NoiseServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  key,
	}
	if len(cfg.StaticKey.PublicBytes()) == 0 {
		t.Fatal("the configured static key has no public half")
	}

	// 2. Persist it. The buffer has to be sized from the re-exported
	//    constant; without it a consumer is guessing.
	encoded := make([]byte, NoiseHexKeySize)
	if err := EncodeNoiseStaticKey(encoded, key); err != nil {
		t.Fatalf("EncodeNoiseStaticKey: %v", err)
	}

	// 3. Load it back. Decoding must reproduce the same identity, which the
	//    public half proves without reading the private one.
	restored, err := DecodeNoiseStaticKey(encoded)
	if err != nil {
		t.Fatalf("DecodeNoiseStaticKey: %v", err)
	}
	defer restored.Destroy()

	if !bytes.Equal(restored.PublicBytes(), key.PublicBytes()) {
		t.Fatal("the decoded key is not the one that was encoded")
	}

	// 4. Wipe the buffer the consumer now owns. Encoded key material is as
	//    sensitive as the key, and this is the only way to clear it.
	WipeNoiseBytes(encoded)
	for i, b := range encoded {
		if b != 0 {
			t.Fatalf("WipeNoiseBytes left byte %d set to %#x", i, b)
		}
	}

	// 5. RUN THE SERVER. Everything above composes the pieces; only this
	//    proves the composed thing works. Constructing a config and stopping
	//    there is the assertion that survives deleting the server lifecycle
	//    from the SDK surface entirely (#40) -- NewNoiseServer, Start, Addr
	//    and Stop are all re-exports, and a re-export that nobody calls is
	//    exactly the half that goes missing without anything failing.
	srv, err := NewNoiseServer(&NoiseServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  key,
		CABundler:  staticBundler{bundle: []byte("test-ca-bundle")},
	})
	if err != nil {
		t.Fatalf("NewNoiseServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Registered IMMEDIATELY, before any assertion that can call t.Fatal.
	// Every check between here and the explicit Stop below is a path that
	// would otherwise leave a listener bound and its goroutines running, to
	// be inherited by whatever test ran next. Stop reports ErrServerNotStarted
	// on the second call rather than panicking, so this is safe alongside the
	// explicit Stop that the test still asserts on.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Start returned but the server is not listening")
	}
	// A bound port is the observable difference between "started" and
	// "constructed"; a config alone has none.
	if _, port, splitErr := net.SplitHostPort(addr.String()); splitErr != nil || port == "" || port == "0" {
		t.Fatalf("server did not bind a real port: addr=%v err=%v", addr, splitErr)
	}

	// The listener has to actually accept, or "listening" is only a field.
	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	if err != nil {
		t.Fatalf("the started server refused a connection: %v", err)
	}
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// And Stop has to release the port, or shutdown is cosmetic. On the
	// unexpected success the connection is still closed: a test that proves a
	// leak by leaking is not an improvement.
	if leaked, err := net.DialTimeout("tcp", addr.String(), 250*time.Millisecond); err == nil {
		_ = leaked.Close()
		t.Fatal("the server still accepts connections after Stop")
	}
}

// staticBundler is the smallest BundleProvider that satisfies the server.
type staticBundler struct{ bundle []byte }

func (b staticBundler) CABundle() ([]byte, error) { return b.bundle, nil }
