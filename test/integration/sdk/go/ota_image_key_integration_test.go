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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestSDK_Embedded_ExportOTAImagePublicKey exports a board's OTA image
// public key after a rotation: raw is the 64-byte X||Y point of the key that
// signs the board's images.
func TestSDK_Embedded_ExportOTAImagePublicKey(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &xkms.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"}
	if _, err := client.CreateOTAImageKey(ctx, req); err != nil {
		t.Fatalf("CreateOTAImageKey failed: %v", err)
	}
	defer client.DeleteKey(ctx, "software", "ota-image-cm4")
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
	if len(resp.Raw) != 64 {
		t.Fatalf("raw public key is %d bytes, want 64", len(resp.Raw))
	}

	// The exported key verifies an image the rotated key signs.
	image := []byte("ota image")
	sig, err := client.SignOTAImage(ctx, &xkms.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: image})
	if err != nil {
		t.Fatalf("SignOTAImage failed: %v", err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{0x04}, resp.Raw...))
	if err != nil {
		t.Fatalf("raw is not a P-256 ECDSA key: %v", err)
	}
	digest := sha256.Sum256(image)
	if !ecdsa.VerifyASN1(pub, digest[:], sig.Signature) {
		t.Error("the exported key does not verify the board's image signature")
	}
}

// TestSDK_Embedded_ExportOTAImagePublicKey_NotFound checks that a board
// without an OTA image key exports nothing.
func TestSDK_Embedded_ExportOTAImagePublicKey_NotFound(t *testing.T) {
	client, cleanup := createTestClient(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := client.ExportOTAImagePublicKey(ctx, &xkms.OTAImageKeyRequest{Backend: "software", BoardID: "no-key"}); err == nil {
		t.Fatal("ExportOTAImagePublicKey of a board without a key succeeded")
	}
}
