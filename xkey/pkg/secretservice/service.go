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

package secretservice

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// aliasStore is implemented by store backends that can persist a Secret
// Service alias name -> folder-path mapping (xkms.StaticPasswordBackendStore
// does; see pkg/staticpw/store.go SetAlias/GetAlias). It is not part of the
// narrower xkms.StaticPasswordStore interface, so Daemon probes for it with
// a type assertion: a store that lacks it still answers ReadAlias/SetAlias
// via the built-in default/login/CollectionFolderMap heuristics in
// PathMapper, it just cannot remember a caller-defined alias across a
// restart.
type aliasStore interface {
	SetAlias(name string, folderPath string) error
	GetAlias(name string) (string, bool, error)
}

// Daemon is the D-Bus Secret Service daemon that exposes go-xkms password
// storage via the org.freedesktop.secrets interface. Every collection is a
// go-xkms static-password folder and every item is a password entry; lock
// state is not tracked per object because there is exactly one lock in this
// storage model, the barrier: Collection/Item Locked properties, and every
// method that would otherwise touch a secret, read it directly from
// barrier.IsSealed().
type Daemon struct {
	mu      sync.RWMutex
	config  *ServiceConfig
	store   xkms.StaticPasswordStore
	barrier *xkms.Barrier
	conn    *dbus.Conn
	mapper  *PathMapper
	logger  *slog.Logger

	// unlockFn collects credentials for a Prompt-driven Unlock. See
	// UnlockFunc's doc comment.
	unlockFn atomic.Pointer[UnlockFunc]

	// sessions tracks active encryption sessions.
	sessions     map[dbus.ObjectPath]*SessionInfo
	sessionsMu   sync.RWMutex
	sessionCount atomic.Uint64

	// prompts tracks pending prompts.
	prompts     map[dbus.ObjectPath]*PromptInfo
	promptsMu   sync.Mutex
	promptCount atomic.Uint64

	// running indicates whether the service is running.
	running atomic.Bool

	// ctx is the service context for shutdown coordination.
	ctx    context.Context
	cancel context.CancelFunc

	// auditLog provides audit logging for security-relevant operations.
	auditLog atomic.Pointer[audit.Logger]
}

// NewDaemon creates a new Secret Service daemon. store and barrier must be
// non-nil: barrier is this process's lock (see Daemon's doc comment), so a
// daemon without one could not honor Lock/Unlock/the Locked property at all.
func NewDaemon(store xkms.StaticPasswordStore, barrier *xkms.Barrier, config *ServiceConfig, logger *slog.Logger) (*Daemon, error) {
	if store == nil {
		return nil, ErrNilPasswordStore
	}
	if barrier == nil {
		return nil, ErrNilBarrier
	}
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Daemon{
		config:   config,
		store:    store,
		barrier:  barrier,
		mapper:   NewPathMapper(config),
		logger:   logger,
		sessions: make(map[dbus.ObjectPath]*SessionInfo),
		prompts:  make(map[dbus.ObjectPath]*PromptInfo),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// SetUnlockFunc registers the callback Unlock's Prompt uses to collect
// credentials. See UnlockFunc's doc comment; passing nil disables
// interactive unlock (every Prompt then resolves dismissed).
func (d *Daemon) SetUnlockFunc(fn UnlockFunc) {
	d.unlockFn.Store(&fn)
}

// dialBus opens the underlying D-Bus connection for busKind ("session" or
// "system"). It is a seam -- swapped only in tests, the same pattern as
// fipsMode (fips.go) and barrierInputIsTerminal (xkey/cmd/xkey/cmd/barrier.go)
// -- so Start's post-connect steps (claiming the bus name, exportObjects,
// exporting the default and existing collections, flipping the running
// flag) are unit-testable against a fake, already-connected *dbus.Conn
// without a real D-Bus daemon to dial.
var dialBus = func(busKind string) (*dbus.Conn, error) {
	if busKind == "system" {
		return dbus.ConnectSystemBus()
	}
	return dbus.ConnectSessionBus()
}

// requestBusName claims BusName on conn and translates the outcome into the
// daemon's own startup error. It is a seam for the same reason as dialBus:
// a real RequestName call blocks awaiting a reply from an actual bus
// daemon, which a fake loopback connection (as used by the busDaemon test
// helper) never sends, so isolating it lets tests exercise everything
// downstream of "the bus name was claimed" without one.
var requestBusName = func(conn *dbus.Conn) error {
	reply, err := conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return err
	}
	return classifyRequestNameReply(reply)
}

// classifyRequestNameReply turns a raw RequestName reply into the daemon's
// startup outcome: nil when this process became the primary owner of
// BusName, ErrServiceAlreadyRunning for every other reply (already owned,
// queued, or already owned by this same connection -- none of which leave
// this process able to receive method calls for the name).
func classifyRequestNameReply(reply dbus.RequestNameReply) error {
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return ErrServiceAlreadyRunning
	}
	return nil
}

// Start connects to D-Bus and registers the Secret Service.
func (d *Daemon) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running.Load() {
		return ErrServiceAlreadyRunning
	}

	conn, err := dialBus(d.config.Bus)
	if err != nil {
		d.logger.Error("failed to connect to D-Bus",
			slog.String("bus", d.config.Bus),
			slog.String("error", err.Error()))
		return ErrDBusUnavailable
	}

	d.conn = conn

	if err := requestBusName(conn); err != nil {
		_ = conn.Close()
		if errors.Is(err, ErrServiceAlreadyRunning) {
			d.logger.Error("failed to become primary owner of D-Bus name",
				slog.String("name", BusName))
			return ErrServiceAlreadyRunning
		}
		d.logger.Error("failed to request D-Bus name",
			slog.String("name", BusName),
			slog.String("error", err.Error()))
		return ErrDBusUnavailable
	}

	// Export the service object
	if err := d.exportObjects(); err != nil {
		_ = conn.Close()
		return err
	}

	// The default collection is always addressable, even while sealed (its
	// Locked property then reads true and every method on it fails closed
	// with IsLocked): a client needs a collection object to call Unlock on
	// before anything else in the store can be enumerated.
	if _, err := d.exportCollection(""); err != nil {
		d.logger.Warn("failed to export default collection", slog.String("error", err.Error()))
	}
	if !d.barrier.IsSealed() {
		if err := d.exportExistingCollections(); err != nil {
			d.logger.Warn("failed to export existing collections", slog.String("error", err.Error()))
		}
	}

	d.running.Store(true)
	d.logger.Info("Secret Service daemon started",
		slog.String("bus", d.config.Bus),
		slog.String("name", BusName))

	return nil
}

// Stop shuts down the Secret Service daemon.
func (d *Daemon) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running.Load() {
		return nil
	}

	d.cancel()
	d.running.Store(false)

	// Close all sessions
	d.sessionsMu.Lock()
	d.sessions = make(map[dbus.ObjectPath]*SessionInfo)
	d.sessionsMu.Unlock()

	// Drop all pending prompts; their done channels are never closed, but
	// nothing can still be waiting on them once the bus connection below
	// goes away with them.
	d.promptsMu.Lock()
	d.prompts = make(map[dbus.ObjectPath]*PromptInfo)
	d.promptsMu.Unlock()

	// Close D-Bus connection
	if d.conn != nil {
		_, err := d.conn.ReleaseName(BusName)
		if err != nil {
			d.logger.Warn("failed to release D-Bus name",
				slog.String("error", err.Error()))
		}
		_ = d.conn.Close()
		d.conn = nil
	}

	d.logger.Info("Secret Service daemon stopped")
	return nil
}

// IsRunning returns whether the daemon is running.
func (d *Daemon) IsRunning() bool {
	return d.running.Load()
}

// exportObjects exports D-Bus objects and interfaces.
func (d *Daemon) exportObjects() error {
	// Export the main service object
	if err := d.conn.Export(d, ServicePath, ServiceInterface); err != nil {
		return &WrappedError{Msg: "failed to export Service", Err: err}
	}

	// Export introspection
	introNode := &introspect.Node{
		Name: string(ServicePath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name: ServiceInterface,
				Methods: []introspect.Method{
					{
						Name: "OpenSession",
						Args: []introspect.Arg{
							{Name: "algorithm", Type: "s", Direction: "in"},
							{Name: "input", Type: "v", Direction: "in"},
							{Name: "output", Type: "v", Direction: "out"},
							{Name: "result", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "CreateCollection",
						Args: []introspect.Arg{
							{Name: "properties", Type: "a{sv}", Direction: "in"},
							{Name: "alias", Type: "s", Direction: "in"},
							{Name: "collection", Type: "o", Direction: "out"},
							{Name: "prompt", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "SearchItems",
						Args: []introspect.Arg{
							{Name: "attributes", Type: "a{ss}", Direction: "in"},
							{Name: "unlocked", Type: "ao", Direction: "out"},
							{Name: "locked", Type: "ao", Direction: "out"},
						},
					},
					{
						Name: "Unlock",
						Args: []introspect.Arg{
							{Name: "objects", Type: "ao", Direction: "in"},
							{Name: "unlocked", Type: "ao", Direction: "out"},
							{Name: "prompt", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "Lock",
						Args: []introspect.Arg{
							{Name: "objects", Type: "ao", Direction: "in"},
							{Name: "locked", Type: "ao", Direction: "out"},
							{Name: "prompt", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "GetSecrets",
						Args: []introspect.Arg{
							{Name: "items", Type: "ao", Direction: "in"},
							{Name: "session", Type: "o", Direction: "in"},
							{Name: "secrets", Type: "a{o(oayays)}", Direction: "out"},
						},
					},
					{
						Name: "ReadAlias",
						Args: []introspect.Arg{
							{Name: "name", Type: "s", Direction: "in"},
							{Name: "collection", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "SetAlias",
						Args: []introspect.Arg{
							{Name: "name", Type: "s", Direction: "in"},
							{Name: "collection", Type: "o", Direction: "in"},
						},
					},
				},
				Properties: []introspect.Property{
					{Name: "Collections", Type: "ao", Access: "read"},
				},
				Signals: []introspect.Signal{
					{
						Name: "CollectionCreated",
						Args: []introspect.Arg{
							{Name: "collection", Type: "o"},
						},
					},
					{
						Name: "CollectionDeleted",
						Args: []introspect.Arg{
							{Name: "collection", Type: "o"},
						},
					},
					{
						Name: "CollectionChanged",
						Args: []introspect.Arg{
							{Name: "collection", Type: "o"},
						},
					},
				},
			},
		},
	}

	if err := d.conn.Export(introspect.NewIntrospectable(introNode), ServicePath,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		return &WrappedError{Msg: "failed to export introspection", Err: err}
	}

	return nil
}

// ============================================================================
// org.freedesktop.Secret.Service Interface Implementation
// ============================================================================

// OpenSession opens a session for encrypted communication.
// Returns the server's public output and the session object path.
//
// sender is supplied by the D-Bus message dispatcher and carries the unique
// connection name of the calling client (for example ":1.42"). godbus strips
// parameters of type dbus.Sender from the wire signature, so the method is
// still exported as OpenSession(sv) -> (vo). It is recorded on the session
// and in the audit trail so a session can be attributed to its client.
func (d *Daemon) OpenSession(sender dbus.Sender, algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	client := string(sender)

	d.logger.Debug("OpenSession called",
		slog.String("algorithm", algorithm),
		slog.String("client", client))

	if algorithm == AlgorithmDH && fipsMode() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSessionOpened, false, ErrAlgorithmNotFIPSApproved,
			map[string]any{"algorithm": algorithm, "client": client}); auditErr != nil {
			return dbus.Variant{}, "/", dbus.MakeFailedError(auditErr)
		}
		return dbus.Variant{}, "/", dbus.MakeFailedError(ErrAlgorithmNotFIPSApproved)
	}

	sessionID := strconv.FormatUint(d.sessionCount.Add(1), 10)
	sessionPath := d.mapper.SessionPath(sessionID)

	session := &SessionInfo{
		Path:       sessionPath,
		Algorithm:  algorithm,
		CreatedAt:  time.Now(),
		ClientPath: client,
	}

	var output dbus.Variant

	switch algorithm {
	case AlgorithmPlain:
		// Plain text - no encryption, return empty output
		output = dbus.MakeVariant("")

	case AlgorithmDH:
		// Diffie-Hellman key exchange
		inputBytes, ok := input.Value().([]byte)
		if !ok {
			return dbus.Variant{}, "/", dbus.MakeFailedError(ErrInvalidAlgorithm)
		}

		// Parse client's public key
		clientPubKey := PublicKeyFromBytes(inputBytes)

		// Generate our key pair
		keyPair, err := GenerateDHKeyPair()
		if err != nil {
			return dbus.Variant{}, "/", dbus.MakeFailedError(err)
		}

		// Compute shared secret and derive AES key
		sharedSecret := ComputeSharedSecret(keyPair.Private, clientPubKey)
		session.AESKey = DeriveAESKey(sharedSecret)

		// Return our public key
		output = dbus.MakeVariant(PublicKeyToBytes(keyPair.Public))

	default:
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSessionOpened, false, ErrInvalidAlgorithm,
			map[string]any{"algorithm": algorithm, "client": client}); auditErr != nil {
			return dbus.Variant{}, "/", dbus.MakeFailedError(auditErr)
		}
		return dbus.Variant{}, "/", dbus.MakeFailedError(ErrInvalidAlgorithm)
	}

	// Store the session
	d.sessionsMu.Lock()
	d.sessions[sessionPath] = session
	d.sessionsMu.Unlock()

	if err := d.exportSession(sessionPath); err != nil {
		d.logger.Warn("failed to export session object", slog.String("error", err.Error()))
	}

	d.logger.Debug("session opened",
		slog.String("path", string(sessionPath)),
		slog.String("algorithm", algorithm),
		slog.String("client", client))

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSessionOpened, true, nil,
		map[string]any{"algorithm": algorithm, "client": client}); auditErr != nil {
		return dbus.Variant{}, "/", dbus.MakeFailedError(auditErr)
	}
	return output, sessionPath, nil
}

// CreateCollection creates a new collection, persisting it as a go-xkms
// static-password folder so it survives a restart (the previous revision of
// this daemon minted a D-Bus path but never called store.CreateFolder,
// silently discarding the collection).
func (d *Daemon) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("CreateCollection called",
		slog.String("alias", alias))

	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionCreated, false, ErrCollectionLocked,
			map[string]any{"alias": alias}); auditErr != nil {
			return "/", "/", dbus.MakeFailedError(auditErr)
		}
		return "/", "/", dbusIsLockedError(ErrCollectionLocked)
	}

	// Extract label from properties
	label := ""
	if labelVar, ok := properties["org.freedesktop.Secret.Collection.Label"]; ok {
		if l, ok := labelVar.Value().(string); ok {
			label = l
		}
	}

	// Determine folder path
	var folderPath string
	if alias != "" {
		folderPath = d.mapper.FolderFromAlias(alias)
	} else if label != "" {
		folderPath = label
	}

	if folderPath != "" {
		if err := d.store.CreateFolder(folderPath); err != nil {
			if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionCreated, false, err,
				map[string]any{"folder": folderPath}); auditErr != nil {
				return "/", "/", dbus.MakeFailedError(auditErr)
			}
			return "/", "/", dbus.MakeFailedError(err)
		}
	}

	collectionPath, exportErr := d.exportCollection(folderPath)
	if exportErr != nil {
		return "/", "/", dbus.MakeFailedError(exportErr)
	}

	if alias != "" {
		if as, ok := d.store.(aliasStore); ok {
			if err := as.SetAlias(alias, folderPath); err != nil {
				d.logger.Warn("failed to persist collection alias",
					slog.String("alias", alias), slog.String("error", err.Error()))
			}
		}
	}

	// Emit CollectionCreated signal
	if err := d.conn.Emit(ServicePath, ServiceInterface+".CollectionCreated", collectionPath); err != nil {
		d.logger.Warn("failed to emit CollectionCreated signal",
			slog.String("error", err.Error()))
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceCollectionCreated, true, nil,
		map[string]any{"folder": folderPath}); auditErr != nil {
		return "/", "/", dbus.MakeFailedError(auditErr)
	}

	// No prompt needed
	return collectionPath, "/", nil
}

// SearchItems searches for items matching the given attributes across every
// collection. It fails closed while the barrier is sealed: the underlying
// store cannot be listed at all in that state (see Daemon's doc comment),
// so there is no partial answer to give -- only IsLocked.
func (d *Daemon) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("SearchItems called",
		slog.Any("attributes", attributes))

	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSearch, false, ErrCollectionLocked, nil); auditErr != nil {
			return nil, nil, dbus.MakeFailedError(auditErr)
		}
		return nil, nil, dbusIsLockedError(ErrCollectionLocked)
	}

	// Get all passwords
	passwords, err := d.store.List()
	if err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSearch, false, err, nil); auditErr != nil {
			return nil, nil, dbus.MakeFailedError(auditErr)
		}
		return nil, nil, dbus.MakeFailedError(err)
	}

	search := ItemAttributes(attributes)
	var unlocked []dbus.ObjectPath

	for _, pw := range passwords {
		if MatchAttributes(ItemAttributesFromPassword(pw), search) {
			collectionPath := d.mapper.CollectionPathFromFolder(pw.FolderPath)
			unlocked = append(unlocked, d.mapper.ItemPathFromPassword(collectionPath, pw.ID))
		}
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSearch, true, nil, map[string]any{"result_count": len(unlocked)}); auditErr != nil {
		return nil, nil, dbus.MakeFailedError(auditErr)
	}
	return unlocked, nil, nil
}

// Unlock unlocks the barrier on behalf of the given objects. Objects are
// returned immediately only when the barrier is already unsealed; otherwise
// a Prompt is created (see resolveUnlockPrompt) and the caller must invoke
// Prompt on it and wait for Completed.
func (d *Daemon) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("Unlock called",
		slog.Int("count", len(objects)))

	if !d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, true, nil,
			map[string]any{"already_unlocked": true, "object_count": len(objects)}); auditErr != nil {
			return nil, "/", dbus.MakeFailedError(auditErr)
		}
		return objects, "/", nil
	}

	promptPath, err := d.createPrompt(PromptTypeUnlock, objects)
	if err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceUnlock, false, err, nil); auditErr != nil {
			return nil, "/", dbus.MakeFailedError(auditErr)
		}
		return nil, "/", dbus.MakeFailedError(err)
	}

	return nil, promptPath, nil
}

// Lock seals the barrier. Because there is exactly one barrier behind every
// collection and item (see Daemon's doc comment), Lock always locks
// everything regardless of which objects were named, matching the fail-safe
// direction: a caller that asked to lock one thing and got everything locked
// has lost nothing it was relying on staying unlocked.
func (d *Daemon) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("Lock called",
		slog.Int("count", len(objects)))

	if err := d.barrier.Seal(); err != nil {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceLock, false, err, nil); auditErr != nil {
			return nil, "/", dbus.MakeFailedError(auditErr)
		}
		return nil, "/", dbus.MakeFailedError(err)
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceLock, true, nil,
		map[string]any{"object_count": len(objects)}); auditErr != nil {
		return nil, "/", dbus.MakeFailedError(auditErr)
	}
	return objects, "/", nil
}

// GetSecrets retrieves the secrets for the specified items. Fails closed
// with IsLocked while the barrier is sealed; never returns a secret in that
// state.
func (d *Daemon) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (map[dbus.ObjectPath]SecretStruct, *dbus.Error) {
	d.logger.Debug("GetSecrets called",
		slog.Int("items", len(items)),
		slog.String("session", string(session)))

	if d.barrier.IsSealed() {
		if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, false, ErrCollectionLocked, nil); auditErr != nil {
			return nil, dbus.MakeFailedError(auditErr)
		}
		return nil, dbusIsLockedError(ErrCollectionLocked)
	}

	// Get session
	d.sessionsMu.RLock()
	sess, exists := d.sessions[session]
	d.sessionsMu.RUnlock()

	if !exists {
		return nil, dbusNoSuchObjectError(ErrSessionNotFound)
	}

	result := make(map[dbus.ObjectPath]SecretStruct, len(items))

	for _, itemPath := range items {
		// Parse item path to get password ID
		_, passwordID, err := d.mapper.PasswordIDFromItemPath(itemPath)
		if err != nil {
			d.logger.Warn("failed to parse item path",
				slog.String("path", string(itemPath)),
				slog.String("error", err.Error()))
			continue
		}

		// Get the password
		pw, err := d.store.Get(passwordID)
		if err != nil {
			d.logger.Warn("failed to get password",
				slog.String("id", passwordID),
				slog.String("error", err.Error()))
			continue
		}

		// Build secret struct
		secret := SecretStruct{
			Session:     session,
			ContentType: "text/plain; charset=utf8",
		}

		// Encrypt if using DH session, otherwise plaintext
		if sess.Algorithm == AlgorithmDH && len(sess.AESKey) > 0 {
			crypto := NewSessionCryptoFromKey(sess.AESKey)
			iv, ciphertext, err := crypto.Encrypt([]byte(pw.Password))
			if err != nil {
				d.logger.Warn("failed to encrypt secret",
					slog.String("id", passwordID),
					slog.String("error", err.Error()))
				continue
			}
			secret.Parameters = iv
			secret.Value = ciphertext
		} else {
			// Plain session
			secret.Parameters = []byte{}
			secret.Value = []byte(pw.Password)
		}

		result[itemPath] = secret
	}

	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, true, nil, map[string]any{"item_count": len(items)}); auditErr != nil {
		return nil, dbus.MakeFailedError(auditErr)
	}
	return result, nil
}

// ReadAlias returns the collection for the given alias, preferring a
// persisted mapping (see aliasStore) over the built-in
// default/login/CollectionFolderMap heuristics in PathMapper.
func (d *Daemon) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("ReadAlias called",
		slog.String("alias", name))

	if as, ok := d.store.(aliasStore); ok && !d.barrier.IsSealed() {
		if folder, found, err := as.GetAlias(name); err == nil && found {
			return d.mapper.CollectionPathFromFolder(folder), nil
		}
	}

	folderPath := d.mapper.FolderFromAlias(name)
	return d.mapper.CollectionPathFromFolder(folderPath), nil
}

// SetAlias sets an alias for a collection, persisting it when the store
// supports it (see aliasStore).
func (d *Daemon) SetAlias(name string, collection dbus.ObjectPath) *dbus.Error {
	d.logger.Debug("SetAlias called",
		slog.String("alias", name),
		slog.String("collection", string(collection)))

	if d.barrier.IsSealed() {
		return dbusIsLockedError(ErrCollectionLocked)
	}

	as, ok := d.store.(aliasStore)
	if !ok {
		return nil
	}

	folder := d.mapper.FolderFromCollectionPath(collection)
	if err := as.SetAlias(name, folder); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

// Collections returns the list of available collections.
// This is a D-Bus property getter. While sealed, only the default
// collection is reported: the store cannot be listed at all in that state
// (see Daemon's doc comment).
func (d *Daemon) Collections() ([]dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("Collections property accessed")

	collections := []dbus.ObjectPath{d.mapper.CollectionPathFromFolder("")}

	if d.barrier.IsSealed() {
		return collections, nil
	}

	// Get all folders
	folders, err := d.store.ListFolders()
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	// Add a collection for each folder
	for _, folder := range folders {
		collections = append(collections, d.mapper.CollectionPathFromFolder(folder))
	}

	return collections, nil
}

// CloseSession closes an encryption session.
func (d *Daemon) CloseSession(sessionPath dbus.ObjectPath) *dbus.Error {
	d.sessionsMu.Lock()
	defer d.sessionsMu.Unlock()

	if _, exists := d.sessions[sessionPath]; !exists {
		return dbusNoSuchObjectError(ErrSessionNotFound)
	}

	delete(d.sessions, sessionPath)
	d.logger.Debug("session closed",
		slog.String("path", string(sessionPath)))
	if auditErr := d.logSecretServiceEvent(audit.OpSecretServiceSessionClosed, true, nil, nil); auditErr != nil {
		return dbus.MakeFailedError(auditErr)
	}

	return nil
}

// getSession retrieves a session by path.
func (d *Daemon) getSession(path dbus.ObjectPath) (*SessionInfo, bool) {
	d.sessionsMu.RLock()
	defer d.sessionsMu.RUnlock()
	sess, ok := d.sessions[path]
	return sess, ok
}

// decryptSecret extracts the plaintext value from secret, using the session
// it names to decrypt it when that session negotiated the DH algorithm.
func (d *Daemon) decryptSecret(secret SecretStruct) ([]byte, error) {
	sess, exists := d.getSession(secret.Session)
	if !exists {
		return nil, ErrSessionNotFound
	}
	if sess.Algorithm == AlgorithmDH && len(sess.AESKey) > 0 {
		crypto := NewSessionCryptoFromKey(sess.AESKey)
		return crypto.Decrypt(secret.Parameters, secret.Value)
	}
	return secret.Value, nil
}

// mapSecretError maps an error from decryptSecret onto the matching D-Bus
// Secret.Error name.
func mapSecretError(err error) *dbus.Error {
	if errors.Is(err, ErrSessionNotFound) {
		return dbusNoSuchObjectError(err)
	}
	return dbus.MakeFailedError(err)
}

// SetAuditLogger sets the audit logger for the Secret Service daemon.
func (d *Daemon) SetAuditLogger(l audit.Logger) {
	d.auditLog.Store(&l)
}

// logSecretServiceEvent logs an audit event for Secret Service operations.
// Callers must propagate a non-nil return (typically via
// dbus.MakeFailedError, since every D-Bus method here returns *dbus.Error):
// op.Severity() (audit package) decides whether that failure is required
// to fail the caller.
func (d *Daemon) logSecretServiceEvent(op audit.OperationType, success bool, err error, details map[string]any) error {
	p := d.auditLog.Load()
	if p == nil {
		return nil
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	return (*p).Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: op,
		Success:   success,
		Error:     errStr,
		Details:   details,
	})
}
