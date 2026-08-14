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

//go:build integration && awskms

package sshbackend

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestSSHBackend_AWSKMS proves SSH key generation + signing on the AWS KMS
// backend against a Floci emulator (real KMS API, real verifiable ECDSA
// signatures). ECDSA-P256 is the only SSH-valid algorithm on AWS — AWS KMS RSA
// is PSS-only (invalid for SSH) and ed25519 is unsupported.
//
// The awskms build tag is only set by `make integration-test-ssh-backends`,
// which brings the Floci emulator up and exports AWS_ENDPOINT_URL. A missing
// endpoint therefore means the harness is broken, not that the lane is
// inapplicable.
func TestSSHBackend_AWSKMS(t *testing.T) {
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	if endpoint == "" {
		t.Fatal("AWS_ENDPOINT_URL is not set: the AWS KMS SSH lane requires the Floci emulator " +
			"started by `make integration-test-ssh-backends`")
	}

	keyStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (keys): %v", err)
	}
	certStorage, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend (certs): %v", err)
	}

	be, err := awskms.NewBackend(&awskms.Config{
		Region:          envOr("AWS_REGION", "us-east-1"),
		AccessKeyID:     envOr("AWS_ACCESS_KEY_ID", "test"),
		SecretAccessKey: envOr("AWS_SECRET_ACCESS_KEY", "test"),
		Endpoint:        endpoint,
		KeyStorage:      keyStorage,
		CertStorage:     certStorage,
	})
	if err != nil {
		t.Fatalf("awskms.NewBackend: %v", err)
	}

	runMatrix(t, resolverFor("awskms", be), "awskms", cloudAlgos, true)
	assertRejects(t, resolverFor("awskms", be), "awskms", keys.AlgorithmEd25519)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
