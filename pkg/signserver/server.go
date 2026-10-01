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

// Package signserver is an embeddable, node-local xkms server: a unix socket
// that a remote-mode PKCS#11 module (libxkms_pkcs11.so) loaded by one named
// consumer -- an IKE daemon, say -- signs through, and nothing else.
//
// The embedding process (a CGO_ENABLED=0 daemon) runs it in process with the
// key backends it chooses, creates the keys the consumer may use through
// CreateKey, and serves the socket. Three gates stand between a process on the
// host and a signature:
//
//  1. The kernel-verified peer uid/gid (SO_PEERCRED) must be on the server's
//     allowlist. The daemon's own uid and root are not admitted implicitly.
//  2. Only the RPCs a remote-mode module needs to sign are served: Sign, the
//     token-record reads, and writes to the token's PIN-lockout counters.
//     Every other keystore RPC is refused with PermissionDenied.
//  3. Sign is admitted only for the private keys a slot names, by CKA_LABEL,
//     and token records only for a configured slot's token.
//
// The server owns its own key service instance (xkms.NewService); it never
// touches the process-wide one, so it can run beside anything else the
// embedding process composes.
package signserver

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport/embedded"
	"github.com/jeremyhahn/go-xkms/pkg/api/unix"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc"
)

// DefaultSocketMode is the socket file mode when Config.SocketMode is zero.
// The peer-credential allowlist, not the file mode, is the access gate; the
// mode only has to let the allowlisted consumer reach the socket.
const DefaultSocketMode os.FileMode = 0o660

// Slot is a sign-only view of one PKCS#11 token.
type Slot struct {
	// Token is the token label: the remote-mode module's
	// XKMS_PKCS11_TOKEN_LABEL, under which its records are stored.
	Token string

	// Keys are the CKA_LABELs of the private keys this slot may sign with.
	// CreateKey creates only these, and Sign is admitted only for them.
	Keys []string
}

// Config configures a Server.
type Config struct {
	// SocketPath is the unix socket the consumer's module connects to
	// (XKMS_PKCS11_TARGET=unix://<SocketPath>). Required.
	SocketPath string

	// SocketMode is the socket file mode. Zero selects DefaultSocketMode.
	SocketMode os.FileMode

	// AllowedUIDs and AllowedGIDs are the only peers admitted. At least one
	// entry across the two is required.
	AllowedUIDs []uint32
	AllowedGIDs []uint32

	// Backends are the key backends the server's key service uses, by name
	// ("tpm2", "software", "pkcs11", a cloud KMS). Required.
	Backends map[string]xkms.Backend

	// DefaultBackend names the backend CreateKey uses when a KeyRequest names
	// none. Empty selects the key service's default rule.
	DefaultBackend string

	// StateStorage holds the slots' token records (token state, PIN
	// verifiers, lockout counters, key objects). It must be durable for keys
	// to survive a restart. Required.
	StateStorage storage.Backend

	// Slots are the sign-only slots. At least one is required.
	Slots []Slot

	// Logger receives server logs. Nil selects slog.Default().
	Logger *slog.Logger
}

// Server is the node-local sign-only server.
type Server struct {
	config  Config
	service *xkms.XKMSService
	client  module.PKCS11Transport
	slots   map[string]map[string]struct{}
	keys    atomic.Pointer[keySet]
	grpc    *unix.GRPCServer

	// createMu serializes CreateKey: provisioning reads the token, then
	// writes it, and two concurrent creates of the same label must not both
	// see it absent.
	createMu sync.Mutex
}

// New builds a Server: it validates cfg, composes the key service over the
// backends and the token store, and loads the keys the slots already hold. It
// does not bind the socket; Serve does.
func New(ctx context.Context, cfg Config) (*Server, error) {
	slots, err := validateConfig(&cfg)
	if err != nil {
		return nil, err
	}

	service, err := xkms.NewService(&xkms.ServiceConfig{
		Backends:       cfg.Backends,
		DefaultBackend: cfg.DefaultBackend,
	})
	if err != nil {
		return nil, &Error{Op: "compose key service", Err: err}
	}
	state, err := pkcs11state.NewStore(cfg.StateStorage)
	if err != nil {
		return nil, &Error{Op: "open token store", Err: err}
	}
	service.SetPKCS11StateStore(state)

	client, err := embedded.New(service)
	if err != nil {
		return nil, &Error{Op: "open in-process transport", Err: err}
	}

	s := &Server{config: cfg, service: service, client: client, slots: slots}
	s.keys.Store(&keySet{})
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}

	policy := &policy{slots: slots, keys: &s.keys}
	s.grpc, err = unix.NewGRPCServer(&unix.GRPCConfig{
		SocketPath:         cfg.SocketPath,
		SocketMode:         cfg.SocketMode,
		ExclusivePeers:     true,
		AllowedUIDs:        cfg.AllowedUIDs,
		AllowedGIDs:        cfg.AllowedGIDs,
		XKMSService:        service,
		Logger:             cfg.Logger,
		UnaryInterceptors:  []grpc.UnaryServerInterceptor{policy.unary},
		StreamInterceptors: []grpc.StreamServerInterceptor{policy.stream},
	})
	if err != nil {
		return nil, &Error{Op: "build unix listener", Err: err}
	}
	return s, nil
}

// validateConfig checks cfg, applies defaults, and indexes the slots.
func validateConfig(cfg *Config) (map[string]map[string]struct{}, error) {
	switch {
	case cfg.SocketPath == "":
		return nil, &Error{Op: "config", Err: ErrSocketPathRequired}
	case len(cfg.AllowedUIDs) == 0 && len(cfg.AllowedGIDs) == 0:
		return nil, &Error{Op: "config", Err: ErrNoAllowedPeers}
	case len(cfg.Backends) == 0:
		return nil, &Error{Op: "config", Err: ErrBackendsRequired}
	case cfg.StateStorage == nil:
		return nil, &Error{Op: "config", Err: ErrStateStorageRequired}
	case len(cfg.Slots) == 0:
		return nil, &Error{Op: "config", Err: ErrSlotsRequired}
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = DefaultSocketMode
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	slots := make(map[string]map[string]struct{}, len(cfg.Slots))
	for _, slot := range cfg.Slots {
		if err := validateSlot(slot, slots); err != nil {
			return nil, err
		}
		labels := make(map[string]struct{}, len(slot.Keys))
		for _, label := range slot.Keys {
			labels[label] = struct{}{}
		}
		slots[slot.Token] = labels
	}
	return slots, nil
}

// validateSlot refuses a slot that cannot be served.
func validateSlot(slot Slot, seen map[string]map[string]struct{}) error {
	if slot.Token == "" {
		return &Error{Op: "config", Err: ErrSlotTokenRequired}
	}
	if _, dup := seen[slot.Token]; dup {
		return &Error{Op: "config", Err: &SlotError{Token: slot.Token, Err: ErrSlotDuplicate}}
	}
	if len(slot.Keys) == 0 {
		return &Error{Op: "config", Err: &SlotError{Token: slot.Token, Err: ErrSlotKeysRequired}}
	}
	for _, label := range slot.Keys {
		if label == "" {
			return &Error{Op: "config", Err: &SlotError{Token: slot.Token, Err: ErrSlotKeysRequired}}
		}
	}
	return nil
}

// Serve binds the socket and serves until Stop. It returns nil after Stop.
func (s *Server) Serve() error {
	if err := s.grpc.Start(); err != nil {
		return &Error{Op: "serve", Err: err}
	}
	return nil
}

// Stop stops serving and removes the socket.
func (s *Server) Stop(ctx context.Context) error {
	if err := s.grpc.Stop(ctx); err != nil {
		return &Error{Op: "stop", Err: err}
	}
	return nil
}

// SocketPath returns the socket the server binds.
func (s *Server) SocketPath() string { return s.config.SocketPath }

// KeyRequest describes a key to create in a slot.
type KeyRequest struct {
	// Token is the slot's token label.
	Token string
	// Label is the key's CKA_LABEL; it must be one of the slot's Keys.
	Label string
	// ID is the key's CKA_ID.
	ID []byte
	// Curve is "P-256" or "P-384".
	Curve string
	// Backend is the key backend that generates and holds the key. Empty
	// selects Config.DefaultBackend.
	Backend string
	// UserPIN is the token user PIN; the consumer's module logs in with it.
	UserPIN string
	// SOPIN initializes the token the first time a key is created in it.
	SOPIN string
}

// Key is a provisioned key.
type Key = module.ProvisionedKeyPair

// CreateKey creates the key req describes, with exactly the CKA_LABEL and
// CKA_ID the consumer's module will find it by, and admits it for signing. It
// is idempotent: an existing identical key is returned with Created false.
func (s *Server) CreateKey(ctx context.Context, req KeyRequest) (*Key, error) {
	labels, ok := s.slots[req.Token]
	if !ok {
		return nil, &Error{Op: "create key", Err: &SlotError{Token: req.Token, Err: ErrUnknownSlot}}
	}
	if _, named := labels[req.Label]; !named {
		return nil, &Error{Op: "create key", Err: &SlotError{Token: req.Token, Err: ErrKeyNotNamed}}
	}

	s.createMu.Lock()
	defer s.createMu.Unlock()

	store, err := module.NewRemoteStorage(s.service, "", req.Token)
	if err != nil {
		return nil, &Error{Op: "create key", Err: err}
	}
	backend := req.Backend
	if backend == "" {
		backend = s.config.DefaultBackend
	}
	key, err := module.ProvisionECKeyPair(ctx, module.ProvisionConfig{
		Client:  s.client,
		Storage: store,
		Backend: backend,
	}, module.KeyPairRequest{
		Label:      req.Label,
		ID:         req.ID,
		Curve:      req.Curve,
		UserPIN:    req.UserPIN,
		SOPIN:      req.SOPIN,
		TokenLabel: req.Token,
	})
	if err != nil {
		return nil, &Error{Op: "create key", Err: err}
	}
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return key, nil
}

// Refresh rebuilds the signing allowlist from the slots' token records. New
// and CreateKey call it; an embedder calls it after changing a token through
// another path.
func (s *Server) Refresh(ctx context.Context) error {
	next := &keySet{allowed: make(map[keyRef]struct{})}
	for token, labels := range s.slots {
		store, err := module.NewRemoteStorage(s.service, "", token)
		if err != nil {
			return &Error{Op: "refresh", Err: err}
		}
		objects, err := module.NewModuleStorage(store).LoadObjects(0)
		if err != nil {
			return &Error{Op: "refresh", Err: &SlotError{Token: token, Err: err}}
		}
		for _, obj := range objects {
			if module.ObjectClass(obj.Class) != module.CKO_PRIVATE_KEY {
				continue
			}
			if _, named := labels[persistedLabel(obj)]; named {
				next.allowed[keyRef{backend: obj.BackendName, keyID: obj.KeyID}] = struct{}{}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return &Error{Op: "refresh", Err: err}
	}
	s.keys.Store(next)
	return nil
}

// persistedLabel returns a persisted object's CKA_LABEL.
func persistedLabel(obj *module.PersistentObject) string {
	for _, attr := range obj.Attributes {
		if module.AttributeType(attr.Type) == module.CKA_LABEL {
			return string(attr.Value)
		}
	}
	return ""
}

// keyRef identifies a key the way a Sign request names it.
type keyRef struct {
	backend string
	keyID   string
}

// keySet is the immutable signing allowlist; Refresh swaps it atomically.
type keySet struct {
	allowed map[keyRef]struct{}
}

// admits reports whether backend/keyID may sign.
func (k *keySet) admits(backend, keyID string) bool {
	_, ok := k.allowed[keyRef{backend: backend, keyID: keyID}]
	return ok
}
