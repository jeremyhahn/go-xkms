// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// newUserTestTransport creates a REST transport connected to an httptest server
// whose chi router is configured by routeFn. The router always exposes the
// /health endpoint that Connect() probes; routeFn wires the user routes under
// /api/v1/users that the client methods exercise.
func newUserTestTransport(t *testing.T, routeFn func(r chi.Router)) *Transport {
	t.Helper()

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Route("/api/v1/users", routeFn)

	server := httptest.NewServer(r)
	t.Cleanup(server.Close)

	tr, err := NewWithConfig(&transport.Config{
		Address:    server.URL,
		TLSEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	return tr
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Logf("failed to encode response: %v", err)
	}
}

func TestTransport_CreateUser_Success(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, req *http.Request) {
			// map[string]any: the body now carries a bool alongside the strings,
			// and a string-valued map fails to decode it at all.
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			if body["username"] != "alice" {
				t.Errorf("expected username alice, got %q", body["username"])
			}
			if body["display_name"] != "Alice" {
				t.Errorf("expected display_name Alice, got %q", body["display_name"])
			}
			if body["role"] != "admin" {
				t.Errorf("expected role admin, got %q", body["role"])
			}
			if body["tenant_id"] != "acme" {
				t.Errorf("expected tenant_id acme, got %q", body["tenant_id"])
			}
			writeJSON(t, w, http.StatusCreated, transport.GetUserResponse{
				User: transport.UserInfo{
					Username:    "alice",
					DisplayName: "Alice",
					Role:        "admin",
					Enabled:     true,
				},
			})
		})
	})

	resp, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:    "alice",
		DisplayName: "Alice",
		Role:        "admin",
		TenantID:    "acme",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Username != "alice" {
		t.Errorf("expected username alice, got %q", resp.User.Username)
	}
	if !resp.User.Enabled {
		t.Error("expected user to be enabled")
	}
}

func TestTransport_CreateUser_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": "username already exists"})
		})
	})

	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "dup"})
	if err == nil {
		t.Fatal("expected error for 4xx response")
	}
}

func TestTransport_CreateUser_MalformedJSON(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("{not-json")); err != nil {
				t.Logf("write failed: %v", err)
			}
		})
	})

	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "x"})
	if err == nil {
		t.Fatal("expected parse error for malformed JSON")
	}
}

func TestTransport_CreateUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "x"})
	if err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

func TestTransport_ListUsers_Success(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, transport.ListUsersResponse{
				Users: []transport.UserInfo{
					{Username: "alice", Enabled: true},
					{Username: "bob", Enabled: false},
				},
			})
		})
	})

	resp, err := tr.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(resp.Users))
	}
	if resp.Users[0].Username != "alice" {
		t.Errorf("expected first user alice, got %q", resp.Users[0].Username)
	}
}

func TestTransport_ListUsers_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusInternalServerError, map[string]string{"error": "boom"})
		})
	})

	_, err := tr.ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestTransport_ListUsers_MalformedJSON(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("not-json")); err != nil {
				t.Logf("write failed: %v", err)
			}
		})
	})

	_, err := tr.ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestTransport_ListUsers_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.ListUsers(context.Background())
	if err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

func TestTransport_GetUser_Success(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}", func(w http.ResponseWriter, req *http.Request) {
			if got := chi.URLParam(req, "username"); got != "alice" {
				t.Errorf("expected username alice in path, got %q", got)
			}
			writeJSON(t, w, http.StatusOK, transport.UserInfo{Username: "alice", Role: "operator", Enabled: true})
		})
	})

	resp, err := tr.GetUser(context.Background(), "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Username != "alice" {
		t.Errorf("expected username alice, got %q", resp.User.Username)
	}
	if resp.User.Role != "operator" {
		t.Errorf("expected role operator, got %q", resp.User.Role)
	}
}

func TestTransport_GetUser_PathEscape(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}", func(w http.ResponseWriter, req *http.Request) {
			// chi decodes the escaped segment back to the original value.
			if got := chi.URLParam(req, "username"); got != "alice smith" {
				t.Errorf("expected decoded username 'alice smith', got %q", got)
			}
			writeJSON(t, w, http.StatusOK, transport.UserInfo{Username: "alice smith"})
		})
	})

	resp, err := tr.GetUser(context.Background(), "alice smith")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.User.Username != "alice smith" {
		t.Errorf("unexpected username %q", resp.User.Username)
	}
}

func TestTransport_GetUser_NotFound(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "user not found"})
		})
	})

	_, err := tr.GetUser(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestTransport_GetUser_MalformedJSON(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("<<<")); err != nil {
				t.Logf("write failed: %v", err)
			}
		})
	})

	_, err := tr.GetUser(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestTransport_GetUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.GetUser(context.Background(), "alice")
	if err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

func TestTransport_DeleteUser_Success(t *testing.T) {
	called := false
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Delete("/{username}", func(w http.ResponseWriter, req *http.Request) {
			called = true
			if got := chi.URLParam(req, "username"); got != "alice" {
				t.Errorf("expected username alice, got %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		})
	})

	if err := tr.DeleteUser(context.Background(), "alice"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected DELETE handler to be invoked")
	}
}

func TestTransport_DeleteUser_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Delete("/{username}", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusConflict, map[string]string{"error": "user has active sessions"})
		})
	})

	if err := tr.DeleteUser(context.Background(), "alice"); err == nil {
		t.Fatal("expected error for 409 response")
	}
}

func TestTransport_DeleteUser_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.DeleteUser(context.Background(), "alice"); err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

// TestTransport_EnableDisableUser_Success proves EnableUser/DisableUser hit
// their own per-direction route (POST .../enable, POST .../disable,
// go-xkms#1249) with no request body — the direction lives in the route,
// not in a JSON payload the static permission gate would have to decode
// before it could authorize the request.
func TestTransport_EnableDisableUser_Success(t *testing.T) {
	var lastVerb, lastMethod string
	var lastBodyLen int
	tr := newUserTestTransport(t, func(r chi.Router) {
		record := func(verb string) http.HandlerFunc {
			return func(w http.ResponseWriter, req *http.Request) {
				lastVerb = verb
				lastMethod = req.Method
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("failed to read body: %v", err)
				}
				lastBodyLen = len(body)
				w.WriteHeader(http.StatusOK)
			}
		}
		r.Post("/{username}/enable", record("enable"))
		r.Post("/{username}/disable", record("disable"))
	})

	if err := tr.EnableUser(context.Background(), "alice"); err != nil {
		t.Fatalf("EnableUser failed: %v", err)
	}
	if lastVerb != "enable" || lastMethod != http.MethodPost {
		t.Fatalf("expected POST .../enable, got %s %s", lastMethod, lastVerb)
	}
	if lastBodyLen != 0 {
		t.Fatalf("expected no request body, got %d bytes", lastBodyLen)
	}

	if err := tr.DisableUser(context.Background(), "alice"); err != nil {
		t.Fatalf("DisableUser failed: %v", err)
	}
	if lastVerb != "disable" || lastMethod != http.MethodPost {
		t.Fatalf("expected POST .../disable, got %s %s", lastMethod, lastVerb)
	}
	if lastBodyLen != 0 {
		t.Fatalf("expected no request body, got %d bytes", lastBodyLen)
	}
}

func TestTransport_EnableUser_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/{username}/enable", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		})
	})

	if err := tr.EnableUser(context.Background(), "alice"); err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestTransport_DisableUser_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/{username}/disable", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		})
	})

	if err := tr.DisableUser(context.Background(), "alice"); err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestTransport_SetUserEnabled_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.EnableUser(context.Background(), "alice"); err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
	if err := tr.DisableUser(context.Background(), "alice"); err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

func TestTransport_BindUserCert_Success(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/{username}/cert-bindings", func(w http.ResponseWriter, req *http.Request) {
			if got := chi.URLParam(req, "username"); got != "alice" {
				t.Errorf("expected username alice, got %q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode body: %v", err)
			}
			if body["thumbprint"] != "abc123" {
				t.Errorf("expected thumbprint abc123, got %v", body["thumbprint"])
			}
			// JSON numbers decode to float64.
			if v, ok := body["not_after_unix"].(float64); !ok || int64(v) != 1700000000 {
				t.Errorf("expected not_after_unix 1700000000, got %v", body["not_after_unix"])
			}
			w.WriteHeader(http.StatusCreated)
		})
	})

	if err := tr.BindUserCert(context.Background(), "alice", "abc123", 1700000000); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransport_BindUserCert_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/{username}/cert-bindings", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusBadRequest, map[string]string{"error": "invalid thumbprint"})
		})
	})

	if err := tr.BindUserCert(context.Background(), "alice", "bad", 0); err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestTransport_BindUserCert_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.BindUserCert(context.Background(), "alice", "abc", 1); err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

func TestTransport_ListUserCredentials_Success(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}/credentials", func(w http.ResponseWriter, req *http.Request) {
			if got := chi.URLParam(req, "username"); got != "alice" {
				t.Errorf("expected username alice, got %q", got)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"credentials": []map[string]string{
					{"id": "cred-1", "name": "YubiKey"},
					{"id": "cred-2", "name": "Phone"},
				},
			})
		})
	})

	resp, err := tr.ListUserCredentials(context.Background(), "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Credentials) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(resp.Credentials))
	}
	if resp.Credentials[0].ID != "cred-1" || resp.Credentials[0].DisplayName != "YubiKey" {
		t.Errorf("unexpected first credential: %+v", resp.Credentials[0])
	}
	if resp.Credentials[1].DisplayName != "Phone" {
		t.Errorf("expected second credential name Phone, got %q", resp.Credentials[1].DisplayName)
	}
}

func TestTransport_ListUserCredentials_Empty(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}/credentials", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"credentials": []any{}})
		})
	})

	resp, err := tr.ListUserCredentials(context.Background(), "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Credentials == nil {
		t.Fatal("expected non-nil (empty) credentials slice")
	}
	if len(resp.Credentials) != 0 {
		t.Fatalf("expected 0 credentials, got %d", len(resp.Credentials))
	}
}

func TestTransport_ListUserCredentials_ServerError(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}/credentials", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "user not found"})
		})
	})

	_, err := tr.ListUserCredentials(context.Background(), "ghost")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestTransport_ListUserCredentials_MalformedJSON(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Get("/{username}/credentials", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("{bad")); err != nil {
				t.Logf("write failed: %v", err)
			}
		})
	})

	_, err := tr.ListUserCredentials(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestTransport_ListUserCredentials_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.ListUserCredentials(context.Background(), "alice")
	if err != ErrNotConnected {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

// The no-email exemption must survive serialization.
//
// CreateUser built its body as map[string]string, which cannot carry a bool, so
// WithoutEmailLoginKey was silently dropped on the wire: the certificate-
// authenticated admin path worked over gRPC/unix and was rejected over REST as
// a missing login key (Codex, go-xkms #190). Asserting on the decoded body is
// the point — a client-side round trip would pass while the field never left.
func TestTransport_CreateUser_CarriesWithoutEmailLoginKey(t *testing.T) {
	tr := newUserTestTransport(t, func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, req *http.Request) {
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			if got, ok := body["without_email_login_key"].(bool); !ok || !got {
				t.Errorf("without_email_login_key did not reach the server: %#v", body["without_email_login_key"])
			}
			if body["email"] != "" {
				t.Errorf("expected an empty email for a cert-authenticated admin, got %v", body["email"])
			}
			writeJSON(t, w, http.StatusCreated, transport.UserInfo{Username: "root", Enabled: true})
		})
	})

	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:             "root",
		WithoutEmailLoginKey: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
