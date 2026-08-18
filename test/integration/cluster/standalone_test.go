// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package cluster

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// envStandaloneURL names the standalone (non-clustered) xkmsd REST endpoint.
const envStandaloneURL = "CLUSTER_STANDALONE_URL"

// standaloneURL returns the standalone node URL, failing if it is not wired.
func standaloneURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv(envStandaloneURL)
	if u == "" {
		t.Fatalf("required environment variable %q is not set", envStandaloneURL)
	}
	return u
}

// TestStandalone_Ready verifies the standalone server's health probes answer,
// proving a single-node (non-Raft) qrdb-backed deployment boots and serves.
func TestStandalone_Ready(t *testing.T) {
	url := standaloneURL(t)
	ctx := context.Background()
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		return isReady(ctx, url), "standalone server not ready yet"
	})
	for _, path := range []string{"/health", "/health/live", "/health/ready"} {
		code, _, err := get(ctx, url+path)
		if err != nil || code != http.StatusOK {
			t.Fatalf("standalone %s: status=%d err=%v", path, code, err)
		}
	}
	// A standalone node is a single-replica deployment: when the qrdb admin
	// plane serves peers, no shard may enumerate more than one replica.
	if p, err := fetchPeers(ctx, url); err == nil {
		for _, shard := range p.Shards {
			if len(shard.Peers) > 1 {
				t.Fatalf("standalone node unexpectedly reports %d replicas in shard %d",
					len(shard.Peers), shard.ShardID)
			}
		}
	}
}

// TestStandalone_KeyGenSignVerify proves full crypto lifecycle on the
// standalone server across ECDSA/Ed25519/RSA: generate → sign → verify →
// read public key → delete.
func TestStandalone_KeyGenSignVerify(t *testing.T) {
	url := standaloneURL(t)
	ctx := context.Background()
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		return isReady(ctx, url), "standalone server not ready yet"
	})

	for _, spec := range cryptoKeySpecs {
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			keyID := fmt.Sprintf("standalone-%s-%d", spec.name, time.Now().UnixNano())

			code, body, err := genKey(ctx, url, spec, keyID)
			if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
				t.Fatalf("gen %s: status=%d err=%v body=%s", spec.name, code, err, body)
			}
			if !keyExists(ctx, url, keyID) {
				t.Fatalf("generated key %q not readable on the standalone server", keyID)
			}

			// Public key must be retrievable.
			pem, code, err := publicKeyPEM(ctx, url, keyID)
			if err != nil || code != http.StatusOK || pem == "" {
				t.Fatalf("get public key for %q: status=%d err=%v", keyID, code, err)
			}

			// Sign + verify round-trip on the single node.
			signAndVerifyRoundTrip(t, ctx, url, url, keyID)

			// A tampered signature must NOT verify (negative check).
			data := []byte("standalone-negative-check")
			sig, code, err := signData(ctx, url, keyID, data)
			if err != nil || code != http.StatusOK || len(sig) == 0 {
				t.Fatalf("sign for negative check: status=%d err=%v", code, err)
			}
			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)-1] ^= 0xFF
			valid, code, err := verifySig(ctx, url, keyID, data, tampered)
			if err != nil || code != http.StatusOK {
				t.Fatalf("verify tampered: status=%d err=%v", code, err)
			}
			if valid {
				t.Fatalf("tampered signature for %q unexpectedly verified as valid", keyID)
			}

			// Delete and confirm removal.
			code, body, err = deleteKey(ctx, url, keyID)
			if err != nil || (code != http.StatusOK && code != http.StatusNoContent) {
				t.Fatalf("delete %q: status=%d err=%v body=%s", keyID, code, err, body)
			}
			if keyExists(ctx, url, keyID) {
				t.Fatalf("key %q still present after delete on the standalone server", keyID)
			}
			t.Logf("%s: full gen→sign→verify→delete lifecycle passed on the standalone server", spec.name)
		})
	}
}

// TestStandalone_AsymEncryptDecryptRotate proves asymmetric encryption and key
// rotation on the standalone server: encrypt to an RSA key's public half,
// decrypt with its private half, then rotate and confirm the key changes and
// still signs+verifies.
func TestStandalone_AsymEncryptDecryptRotate(t *testing.T) {
	url := standaloneURL(t)
	ctx := context.Background()
	poll(t, 60*time.Second, 1*time.Second, func() (bool, string) {
		return isReady(ctx, url), "standalone server not ready yet"
	})

	// Asymmetric encrypt/decrypt round-trip (RSA).
	rsaID := fmt.Sprintf("standalone-asym-%d", time.Now().UnixNano())
	code, body, err := genKey(ctx, url, keySpec{name: "rsa-2048", keyType: "rsa", bits: 2048}, rsaID)
	if err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen rsa key: status=%d err=%v body=%s", code, err, body)
	}
	plaintext := []byte("standalone asymmetric secret")
	ct, code, err := encryptAsym(ctx, url, rsaID, plaintext)
	if err != nil || code != http.StatusOK || len(ct) == 0 {
		t.Fatalf("encrypt-asym: status=%d err=%v", code, err)
	}
	pt, code, err := decryptData(ctx, url, rsaID, ct)
	if err != nil || code != http.StatusOK {
		t.Fatalf("decrypt: status=%d err=%v", code, err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypt returned %q, want %q", pt, plaintext)
	}

	// Rotation changes the key but it remains usable.
	rotID := fmt.Sprintf("standalone-rotate-%d", time.Now().UnixNano())
	if code, body, err := genKey(ctx, url, cryptoKeySpecs[0], rotID); err != nil || (code != http.StatusOK && code != http.StatusCreated) {
		t.Fatalf("gen key for rotate: status=%d err=%v body=%s", code, err, body)
	}
	original, _, err := publicKeyPEM(ctx, url, rotID)
	if err != nil || original == "" {
		t.Fatalf("read original public key: %v", err)
	}
	rotated, code, err := rotateKey(ctx, url, rotID)
	if err != nil || code != http.StatusOK {
		t.Fatalf("rotate: status=%d err=%v", code, err)
	}
	if rotated == original {
		t.Fatalf("rotation did not change the public key")
	}
	signAndVerifyRoundTrip(t, ctx, url, url, rotID)
	t.Logf("standalone: asymmetric encrypt/decrypt + rotation lifecycle passed")
}
