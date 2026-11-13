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

package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return s
}

func newRSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return s
}

func TestAgent_ReadOnly(t *testing.T) {
	a := New(newEd25519Signer(t))
	if err := a.Add(sshagent.AddedKey{}); err != ErrUnsupported {
		t.Fatalf("Add should be unsupported, got %v", err)
	}
	if err := a.RemoveAll(); err != ErrUnsupported {
		t.Fatalf("RemoveAll should be unsupported, got %v", err)
	}
	if err := a.Lock(nil); err != ErrUnsupported {
		t.Fatalf("Lock should be unsupported, got %v", err)
	}
	if err := a.Remove(nil); err != ErrUnsupported {
		t.Fatalf("Remove should be unsupported, got %v", err)
	}
	if err := a.Unlock(nil); err != ErrUnsupported {
		t.Fatalf("Unlock should be unsupported, got %v", err)
	}
	if _, err := a.Extension("some@ext", nil); err == nil {
		t.Fatal("Extension should be unsupported")
	}
}

func TestAgent_SignUnknownKey(t *testing.T) {
	a := New(newEd25519Signer(t))
	other := newEd25519Signer(t)
	if _, err := a.Sign(other.PublicKey(), []byte("x")); err == nil {
		t.Fatal("expected error signing with an unknown key")
	}
}
