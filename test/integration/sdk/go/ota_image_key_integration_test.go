//go:build integration

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

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	xkmssvc "github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// createOTAServiceClient returns an embedded SDK client over the production
// XKMSService (software backend in memory, key-version store wired), so the
// OTA image key tests exercise the real rotation, export and signature
// encoding rather than the TestXKMSService double.
func createOTAServiceClient(t *testing.T) xkms.Client {
	t.Helper()
	xkmssvc.Reset()
	t.Cleanup(xkmssvc.Reset)

	factory, ok := xkmssvc.GetBackendFactory(xkmssvc.BackendSoftware)
	if !ok {
		t.Fatal("software backend factory is not registered")
	}
	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	if err != nil {
		t.Fatalf("software backend: %v", err)
	}
	backend, err := xkmssvc.New(&xkmssvc.BackendConfig{Backend: provider, CertStorage: storage.New()})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if err := xkmssvc.Initialize(&xkmssvc.ServiceConfig{
		Backends:       map[string]xkmssvc.Backend{"software": backend},
		DefaultBackend: "software",
	}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	svc, err := xkmssvc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	store, err := keyversion.NewStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("key-version store: %v", err)
	}
	svc.SetKeyVersionStore(store)

	client, err := xkms.NewEmbedded(svc)
	if err != nil {
		t.Fatalf("Failed to create embedded client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("Warning: failed to close client: %v", err)
		}
	})
	return client
}

// TestSDK_Embedded_ExportOTAImagePublicKey exports a board's OTA image
// public key after a rotation through the production XKMSService: the
// version is the rotated one, raw is the 64-byte X||Y point, the COSE_Key
// carries the same point and the key id, and raw verifies the board's
// fixed-width r || s image signature (docs/SPEC.md, ota-image-keys).
func TestSDK_Embedded_ExportOTAImagePublicKey(t *testing.T) {
	client := createOTAServiceClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &xkms.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"}
	if _, err := client.CreateOTAImageKey(ctx, req); err != nil {
		t.Fatalf("CreateOTAImageKey failed: %v", err)
	}
	if _, err := client.RotateOTAImageKey(ctx, req); err != nil {
		t.Fatalf("RotateOTAImageKey failed: %v", err)
	}

	resp, err := client.ExportOTAImagePublicKey(ctx, req)
	if err != nil {
		t.Fatalf("ExportOTAImagePublicKey failed: %v", err)
	}
	if resp.KeyID != "ota-image-cm4" || resp.BoardID != "cm4" {
		t.Errorf("export names key %q board %q, want ota-image-cm4 cm4", resp.KeyID, resp.BoardID)
	}
	if resp.Version != 2 {
		t.Errorf("export version is %d, want 2 after one rotation", resp.Version)
	}
	if len(resp.Raw) != 64 {
		t.Fatalf("raw public key is %d bytes, want 64", len(resp.Raw))
	}

	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(resp.COSEKey, &coseKey); err != nil {
		t.Fatalf("COSE_Key does not decode: %v", err)
	}
	if x, _ := coseKey[-2].([]byte); !bytes.Equal(x, resp.Raw[:32]) {
		t.Error("COSE_Key x differs from raw X")
	}
	if y, _ := coseKey[-3].([]byte); !bytes.Equal(y, resp.Raw[32:]) {
		t.Error("COSE_Key y differs from raw Y")
	}
	if kid, _ := coseKey[2].([]byte); string(kid) != resp.KeyID {
		t.Errorf("COSE_Key kid is %q, want %q", kid, resp.KeyID)
	}

	// The exported key verifies an image the rotated key signs; the OTA_AUTH
	// signature is the RFC 9053 fixed-width r || s, 64 bytes for ES256.
	image := []byte("ota image")
	sig, err := client.SignOTAImage(ctx, &xkms.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: image})
	if err != nil {
		t.Fatalf("SignOTAImage failed: %v", err)
	}
	if len(sig.Signature) != 64 {
		t.Fatalf("image signature is %d bytes, want the 64-byte r || s", len(sig.Signature))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{0x04}, resp.Raw...))
	if err != nil {
		t.Fatalf("raw is not a P-256 ECDSA key: %v", err)
	}
	digest := sha256.Sum256(image)
	r := new(big.Int).SetBytes(sig.Signature[:32])
	s := new(big.Int).SetBytes(sig.Signature[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("the exported key does not verify the board's image signature")
	}
}

// TestSDK_Embedded_ExportOTAImagePublicKey_NotFound checks that a board
// without an OTA image key exports nothing.
func TestSDK_Embedded_ExportOTAImagePublicKey_NotFound(t *testing.T) {
	client := createOTAServiceClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := client.ExportOTAImagePublicKey(ctx, &xkms.OTAImageKeyRequest{Backend: "software", BoardID: "no-key"}); err == nil {
		t.Fatal("ExportOTAImagePublicKey of a board without a key succeeded")
	}
}
