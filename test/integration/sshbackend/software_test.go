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

package sshbackend

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestSSHBackend_Software proves SSH key generation + signing on the software
// backend across every algorithm it supports (the in-memory baseline).
func TestSSHBackend_Software(t *testing.T) {
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	cases := []algoCase{
		{keys.AlgorithmEd25519, 0, "", ssh.KeyAlgoED25519},
		{keys.AlgorithmECDSAP256, 0, "", ssh.KeyAlgoECDSA256},
		{keys.AlgorithmECDSAP384, 0, "", ssh.KeyAlgoECDSA384},
		{keys.AlgorithmRSA, 2048, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA256},
		{keys.AlgorithmRSA, 2048, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA512},
	}
	runMatrix(t, resolverFor("software", kp), "software", cases, true)
}
