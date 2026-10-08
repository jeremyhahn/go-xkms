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

package module_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/embedded"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// provisionFixture is an in-process key service, a token store over it, and
// the ProvisionConfig that reaches both -- the composition a CGO-free
// embedder uses.
type provisionFixture struct {
	service *xkms.XKMSService
	config  module.ProvisionConfig
}

func newProvisionFixture(t *testing.T, token string) *provisionFixture {
	t.Helper()
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	svc, err := xkms.NewService(&xkms.ServiceConfig{Backends: map[string]xkms.Backend{"software": backend}})
	if err != nil {
		t.Fatal(err)
	}
	state, err := pkcs11state.NewStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatal(err)
	}
	svc.SetPKCS11StateStore(state)
	client, err := embedded.New(svc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := module.NewRemoteStorage(svc, "", token)
	if err != nil {
		t.Fatal(err)
	}
	return &provisionFixture{
		service: svc,
		config:  module.ProvisionConfig{Client: client, Storage: store, Backend: "software"},
	}
}

func TestProvisionECKeyPair_CreatesTheNamedKey(t *testing.T) {
	ctx := context.Background()
	f := newProvisionFixture(t, "ike")
	req := module.KeyPairRequest{
		Label: "vtep", ID: []byte{0xbe, 0xef}, Curve: "P-384",
		UserPIN: "user-pin-1234", SOPIN: "so-pin-5678", TokenLabel: "ike",
	}

	key, err := module.ProvisionECKeyPair(ctx, f.config, req)
	if err != nil {
		t.Fatalf("ProvisionECKeyPair: %v", err)
	}
	if !key.Created || key.Label != "vtep" || string(key.ID) != "\xbe\xef" || key.Curve != "P-384" || key.Backend != "software" {
		t.Fatalf("unexpected key %+v", key)
	}

	// The key the token names is the key the service signs with.
	digest := sha256.Sum256([]byte("payload"))
	sig, err := f.service.Sign(ctx, &transport.SignRequest{Backend: key.Backend, KeyID: key.KeyID, Data: digest[:], Hash: "SHA-256", DataIsDigest: true})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(key.PublicKey, digest[:], sig.Signature) {
		t.Fatal("the provisioned public key does not verify the service's signature")
	}

	again, err := module.ProvisionECKeyPair(ctx, f.config, req)
	if err != nil {
		t.Fatalf("second ProvisionECKeyPair: %v", err)
	}
	if again.Created || again.KeyID != key.KeyID {
		t.Fatalf("an identical request must return the existing key, got %+v", again)
	}
}

func TestProvisionECKeyPair_Refusals(t *testing.T) {
	ctx := context.Background()
	f := newProvisionFixture(t, "ike")
	base := module.KeyPairRequest{Label: "vtep", ID: []byte{1}, Curve: "P-256", UserPIN: "user-pin-1234", SOPIN: "so-pin-5678"}
	if _, err := module.ProvisionECKeyPair(ctx, f.config, base); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		config module.ProvisionConfig
		mutate func(*module.KeyPairRequest)
		want   error
	}{
		"no client":       {module.ProvisionConfig{Storage: f.config.Storage}, nil, module.ErrProvisionClientRequired},
		"no storage":      {module.ProvisionConfig{Client: f.config.Client}, nil, module.ErrProvisionStorageRequired},
		"no label":        {f.config, func(r *module.KeyPairRequest) { r.Label = "" }, module.ErrProvisionLabelRequired},
		"no id":           {f.config, func(r *module.KeyPairRequest) { r.ID = nil }, module.ErrProvisionIDRequired},
		"no pin":          {f.config, func(r *module.KeyPairRequest) { r.UserPIN = "" }, module.ErrProvisionUserPINRequired},
		"curve":           {f.config, func(r *module.KeyPairRequest) { r.Curve = "P-521" }, module.ErrProvisionCurveUnsupported},
		"label reused":    {f.config, func(r *module.KeyPairRequest) { r.ID = []byte{2} }, module.ErrProvisionKeyConflict},
		"id reused":       {f.config, func(r *module.KeyPairRequest) { r.Label = "other" }, module.ErrProvisionKeyConflict},
		"curve differs":   {f.config, func(r *module.KeyPairRequest) { r.Curve = "P-384" }, module.ErrProvisionKeyConflict},
		"wrong user pin":  {f.config, func(r *module.KeyPairRequest) { r.UserPIN = "wrong-pin-0000" }, module.ErrPINIncorrect},
		"unknown backend": {module.ProvisionConfig{Client: f.config.Client, Storage: f.config.Storage, Backend: "tpm2"}, func(r *module.KeyPairRequest) { r.Label, r.ID = "new", []byte{3} }, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req := base
			if tt.mutate != nil {
				tt.mutate(&req)
			}
			_, err := module.ProvisionECKeyPair(ctx, tt.config, req)
			if err == nil {
				t.Fatal("expected an error")
			}
			var perr *module.ProvisionError
			if !errors.As(err, &perr) || perr.Error() == "" {
				t.Fatalf("error %v is not a *ProvisionError", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestProvisionECKeyPair_UninitializedTokenNeedsSOPIN(t *testing.T) {
	f := newProvisionFixture(t, "fresh")
	_, err := module.ProvisionECKeyPair(context.Background(), f.config, module.KeyPairRequest{
		Label: "k", ID: []byte{1}, Curve: "P-256", UserPIN: "user-pin-1234",
	})
	if !errors.Is(err, module.ErrProvisionSOPINRequired) {
		t.Fatalf("error = %v, want ErrProvisionSOPINRequired", err)
	}
}

func TestProvisionECKeyPair_CancelledContext(t *testing.T) {
	f := newProvisionFixture(t, "ike")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := module.ProvisionECKeyPair(ctx, f.config, module.KeyPairRequest{
		Label: "k", ID: []byte{1}, Curve: "P-256", UserPIN: "user-pin-1234", SOPIN: "so-pin-5678",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
