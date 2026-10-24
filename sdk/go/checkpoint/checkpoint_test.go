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

package checkpoint_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/checkpoint"
)

func TestSDKSignOpenCheckpoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := checkpoint.NewSigner("example.com/log", key, checkpoint.WithAlgorithm(checkpoint.AlgorithmECDSAP384SHA384))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	v, err := checkpoint.NewVerifier(s.VerifierKey())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	root := bytes.Repeat([]byte{7}, checkpoint.HashSize)
	note, err := checkpoint.SignCheckpoint(&checkpoint.Checkpoint{Origin: "example.com/log", Size: 9, Hash: root}, s)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	c, _, err := checkpoint.OpenCheckpoint(note, v)
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v", err)
	}
	if c.Size != 9 || !bytes.Equal(c.Hash, root) {
		t.Fatalf("checkpoint = %+v", c)
	}
}

func TestSDKRefusals(t *testing.T) {
	if _, err := checkpoint.NewVerifier("example.com/log"); !errors.Is(err, checkpoint.ErrMalformedVerifierKey) {
		t.Fatalf("NewVerifier: err = %v", err)
	}
	if err := checkpoint.Register(checkpoint.Algorithm{ID: checkpoint.AlgorithmEd25519}); !errors.Is(err, checkpoint.ErrInvalidAlgorithm) {
		t.Fatalf("Register: err = %v", err)
	}
	if _, err := checkpoint.ParseCheckpoint([]byte("o\n01\nAA==\n")); !errors.Is(err, checkpoint.ErrInvalidTreeSize) {
		t.Fatalf("ParseCheckpoint: err = %v", err)
	}
}
