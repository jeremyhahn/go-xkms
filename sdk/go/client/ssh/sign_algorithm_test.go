package ssh_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// signCase is one signing call through a remote signer and the algorithm the
// sign request must carry: Sign names none, so the server keeps the key's
// default; SignWithAlgorithm names it (RFC 8332 §3).
type signCase struct {
	name string
	sign func(gossh.Signer) error
	want string
}

func signCases(t *testing.T) []signCase {
	t.Helper()
	return []signCase{
		{"Sign", func(s gossh.Signer) error {
			_, err := s.Sign(rand.Reader, []byte("digest"))
			return err
		}, ""},
		{"SignWithAlgorithm", func(s gossh.Signer) error {
			as, ok := s.(gossh.AlgorithmSigner)
			if !ok {
				t.Fatalf("remote signer %T does not implement ssh.AlgorithmSigner", s)
			}
			_, err := as.SignWithAlgorithm(rand.Reader, []byte("digest"), gossh.KeyAlgoRSASHA512)
			return err
		}, gossh.KeyAlgoRSASHA512},
	}
}

func TestGRPCSigner_SendsAlgorithm(t *testing.T) {
	for _, tc := range signCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			line, _ := testPublicKeyLine(t)
			fake := &fakeKeystore{
				pubResp:  &pb.SSHPublicKeyResponse{Algorithm: "ed25519", Line: line},
				signResp: &pb.SSHSignResponse{Format: "ssh-ed25519", Blob: []byte("sig-blob")},
			}
			client := newGRPCFixture(t, fake)
			signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			if err := tc.sign(signer); err != nil {
				t.Fatalf("sign: %v", err)
			}
			if got := fake.signReq.GetAlgorithm(); got != tc.want {
				t.Errorf("algorithm on the wire = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMCPSigner_SendsAlgorithm(t *testing.T) {
	for _, tc := range signCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			line, _ := testPublicKeyLine(t)
			srv := newFakeMCPServer(t)
			srv.ok("ssh.keys.export", map[string]interface{}{"line": line, "algorithm": "ed25519"})
			srv.ok("ssh.keys.sign", map[string]interface{}{"format": "ssh-ed25519", "blob": []byte("sig-blob")})
			client := newMCPFixture(t, srv)
			signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{Name: "laptop"})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			if err := tc.sign(signer); err != nil {
				t.Fatalf("sign: %v", err)
			}
			got, _ := paramsOf(t, srv, "ssh.keys.sign")["algorithm"].(string)
			if got != tc.want {
				t.Errorf("algorithm on the wire = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRESTSigner_SendsAlgorithm(t *testing.T) {
	for _, tc := range signCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			line, _ := testPublicKeyLine(t)
			var signBody struct {
				Algorithm *string `json:"algorithm"`
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/public"):
					_ = json.NewEncoder(w).Encode(map[string]any{"algorithm": "ed25519", "line": line})
				case strings.HasSuffix(r.URL.Path, "/sign"):
					if err := json.NewDecoder(r.Body).Decode(&signBody); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"format": "ssh-ed25519", "blob": []byte("sig-blob")})
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: srv.URL})
			if err != nil {
				t.Fatalf("NewREST: %v", err)
			}
			defer client.Close()
			signer, err := client.Keys().Signer(context.Background(), sdkssh.GetKeyRequest{
				Scope: "user", Owner: "alice", Name: "laptop",
			})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			if err := tc.sign(signer); err != nil {
				t.Fatalf("sign: %v", err)
			}
			// Sign omits the field, so a server that predates it sees the
			// request it always did.
			if tc.want == "" {
				if signBody.Algorithm != nil {
					t.Errorf("algorithm on the wire = %q, want it omitted", *signBody.Algorithm)
				}
				return
			}
			if signBody.Algorithm == nil || *signBody.Algorithm != tc.want {
				t.Errorf("algorithm on the wire = %v, want %q", signBody.Algorithm, tc.want)
			}
		})
	}
}
