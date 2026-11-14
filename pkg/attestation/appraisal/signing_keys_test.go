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

package appraisal

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSigningKeys_BindingOverridesTheReleaseKeyForItsRepositoryOnly(t *testing.T) {
	w := newVerifierWorld(t)
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	w.app.now = func() time.Time { return at }

	binding, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{
		Repository: "acme/app", KeyID: "app-release", Backend: "pkcs8",
	})
	if err != nil {
		t.Fatalf("SetSigningKeyBinding: %v", err)
	}
	if binding.KeyID != "app-release" || binding.Backend != "pkcs8" || !binding.UpdatedAt.Equal(at) {
		t.Fatalf("binding = %+v", binding)
	}

	bound, err := w.app.ResolveSigningKey(w.ctx, w.tenant, &ResolveSigningKeyRequest{Repository: "acme/app"})
	if err != nil {
		t.Fatalf("ResolveSigningKey(bound): %v", err)
	}
	if bound.KeyID != "app-release" || bound.Backend != "pkcs8" || bound.Default {
		t.Fatalf("bound resolution = %+v, want the bound key", bound)
	}

	other, err := w.app.ResolveSigningKey(w.ctx, w.tenant, &ResolveSigningKeyRequest{Repository: "acme/other"})
	if err != nil {
		t.Fatalf("ResolveSigningKey(other): %v", err)
	}
	release := SigningKeyResolution{Repository: "acme/other", KeyID: ReleaseSigningKeyID, Default: true}
	if *other != release {
		t.Fatalf("other repository resolution = %+v, want the release key %+v", other, release)
	}

	elsewhere, err := w.app.ResolveSigningKey(w.ctx, "globex", &ResolveSigningKeyRequest{Repository: "acme/app"})
	if err != nil {
		t.Fatalf("ResolveSigningKey(other tenant): %v", err)
	}
	if !elsewhere.Default {
		t.Fatalf("another tenant's resolution = %+v, want the release key", elsewhere)
	}
}

func TestSigningKeys_GetListDelete(t *testing.T) {
	w := newVerifierWorld(t)
	for _, repo := range []string{"acme/web", "acme/api"} {
		if _, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: repo, KeyID: "k1"}); err != nil {
			t.Fatalf("SetSigningKeyBinding(%s): %v", repo, err)
		}
	}
	// Setting a repository again replaces its binding.
	if _, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: "acme/web", KeyID: "k2"}); err != nil {
		t.Fatalf("SetSigningKeyBinding(replace): %v", err)
	}

	got, err := w.app.GetSigningKeyBinding(w.ctx, w.tenant, &GetSigningKeyBindingRequest{Repository: "acme/web"})
	if err != nil || got.KeyID != "k2" {
		t.Fatalf("GetSigningKeyBinding = %+v, %v; want key k2", got, err)
	}

	list, err := w.app.ListSigningKeyBindings(w.ctx, w.tenant)
	if err != nil {
		t.Fatalf("ListSigningKeyBindings: %v", err)
	}
	if len(list.Bindings) != 2 || list.Bindings[0].Repository != "acme/api" || list.Bindings[1].Repository != "acme/web" {
		t.Fatalf("bindings = %+v, want acme/api then acme/web", list.Bindings)
	}
	if other, err := w.app.ListSigningKeyBindings(w.ctx, "globex"); err != nil || len(other.Bindings) != 0 {
		t.Fatalf("another tenant's bindings = %+v, %v; want none", other, err)
	}

	if err := w.app.DeleteSigningKeyBinding(w.ctx, w.tenant, &DeleteSigningKeyBindingRequest{Repository: "acme/web"}); err != nil {
		t.Fatalf("DeleteSigningKeyBinding: %v", err)
	}
	resolved, err := w.app.ResolveSigningKey(w.ctx, w.tenant, &ResolveSigningKeyRequest{Repository: "acme/web"})
	if err != nil || !resolved.Default {
		t.Fatalf("resolution after delete = %+v, %v; want the release key", resolved, err)
	}

	var notFound *RecordNotFoundError
	if _, err := w.app.GetSigningKeyBinding(w.ctx, w.tenant, &GetSigningKeyBindingRequest{Repository: "acme/web"}); !errors.As(err, &notFound) {
		t.Fatalf("Get after delete = %v, want *RecordNotFoundError", err)
	}
	if err := w.app.DeleteSigningKeyBinding(w.ctx, w.tenant, &DeleteSigningKeyBindingRequest{Repository: "acme/web"}); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("second delete = %v, want ErrRecordNotFound", err)
	}
}

func TestSigningKeys_RefusesInvalidRequests(t *testing.T) {
	w := newVerifierWorld(t)
	cases := map[string]struct {
		req  *SetSigningKeyBindingRequest
		want error
	}{
		"nil request":       {nil, ErrNilRequest},
		"empty repository":  {&SetSigningKeyBindingRequest{KeyID: "k"}, ErrInvalidRepository},
		"uppercase":         {&SetSigningKeyBindingRequest{Repository: "Acme/App", KeyID: "k"}, ErrInvalidRepository},
		"leading slash":     {&SetSigningKeyBindingRequest{Repository: "/acme", KeyID: "k"}, ErrInvalidRepository},
		"path traversal":    {&SetSigningKeyBindingRequest{Repository: "acme/../x", KeyID: "k"}, ErrInvalidRepository},
		"too long":          {&SetSigningKeyBindingRequest{Repository: strings.Repeat("a", maxRepositoryLen+1), KeyID: "k"}, ErrInvalidRepository},
		"empty key id":      {&SetSigningKeyBindingRequest{Repository: "acme/app"}, ErrInvalidSigningKey},
		"key id with slash": {&SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "a/b"}, ErrInvalidSigningKey},
		"bad backend":       {&SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "k", Backend: "no such/backend"}, ErrInvalidSigningKey},
	}
	for name, tc := range cases {
		if _, err := w.app.SetSigningKeyBinding(w.ctx, w.tenant, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: SetSigningKeyBinding = %v, want %v", name, err, tc.want)
		}
	}

	if _, err := w.app.GetSigningKeyBinding(w.ctx, w.tenant, nil); !errors.Is(err, ErrNilRequest) {
		t.Errorf("Get(nil) = %v, want ErrNilRequest", err)
	}
	if err := w.app.DeleteSigningKeyBinding(w.ctx, w.tenant, nil); !errors.Is(err, ErrNilRequest) {
		t.Errorf("Delete(nil) = %v, want ErrNilRequest", err)
	}
	if _, err := w.app.ResolveSigningKey(w.ctx, w.tenant, nil); !errors.Is(err, ErrNilRequest) {
		t.Errorf("Resolve(nil) = %v, want ErrNilRequest", err)
	}
	if _, err := w.app.ResolveSigningKey(w.ctx, w.tenant, &ResolveSigningKeyRequest{Repository: "Bad"}); !errors.Is(err, ErrInvalidRepository) {
		t.Errorf("Resolve(invalid) = %v, want ErrInvalidRepository", err)
	}
	if _, err := w.app.GetSigningKeyBinding(w.ctx, w.tenant, &GetSigningKeyBindingRequest{Repository: "Bad"}); !errors.Is(err, ErrInvalidRepository) {
		t.Errorf("Get(invalid) = %v, want ErrInvalidRepository", err)
	}
	if _, err := w.app.ResolveSigningKey(w.ctx, "a/b", &ResolveSigningKeyRequest{Repository: "acme/app"}); !errors.Is(err, ErrInvalidTenant) {
		t.Errorf("Resolve(no tenant) = %v, want ErrInvalidTenant", err)
	}
}

func TestSigningKeys_StoreFailures(t *testing.T) {
	w := newVerifierWorld(t)
	w.kv.failReads, w.kv.failWrites = true, true
	checks := map[string]error{}
	_, checks["set"] = w.app.SetSigningKeyBinding(w.ctx, w.tenant, &SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "k"})
	_, checks["get"] = w.app.GetSigningKeyBinding(w.ctx, w.tenant, &GetSigningKeyBindingRequest{Repository: "acme/app"})
	_, checks["list"] = w.app.ListSigningKeyBindings(w.ctx, w.tenant)
	checks["delete"] = w.app.DeleteSigningKeyBinding(w.ctx, w.tenant, &DeleteSigningKeyBindingRequest{Repository: "acme/app"})
	_, checks["resolve"] = w.app.ResolveSigningKey(w.ctx, w.tenant, &ResolveSigningKeyRequest{Repository: "acme/app"})
	for name, err := range checks {
		if !errors.Is(err, ErrStoreUnavailable) {
			t.Errorf("%s against a failing store = %v, want ErrStoreUnavailable", name, err)
		}
	}
}

func TestSigningKeyErrors_Messages(t *testing.T) {
	cause := errors.New("bad")
	cases := map[string]struct {
		err      error
		contains string
		is       error
	}{
		"repository":  {&RepositoryError{Repository: "Bad"}, `"Bad"`, ErrInvalidRepository},
		"signing key": {&SigningKeyError{KeyID: "a/b", Cause: cause}, `"a/b"`, ErrInvalidSigningKey},
	}
	for name, tc := range cases {
		if !strings.Contains(tc.err.Error(), tc.contains) || !errors.Is(tc.err, tc.is) {
			t.Errorf("%s: %q does not name %s or unwrap to %v", name, tc.err, tc.contains, tc.is)
		}
	}
	if !errors.Is(&SigningKeyError{KeyID: "a/b", Cause: cause}, cause) {
		t.Error("SigningKeyError does not unwrap its cause")
	}
}
