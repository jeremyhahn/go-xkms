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
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"

	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// Daemon is the D-Bus Secret Service daemon that exposes go-xkms password
// storage via the org.freedesktop.secrets interface.
type Daemon struct {
	mu     sync.RWMutex
	config *ServiceConfig
	store  staticpw.Store
	conn   *dbus.Conn
	mapper *PathMapper
	logger *slog.Logger

	// sessions tracks active encryption sessions.
	sessions     map[dbus.ObjectPath]*SessionInfo
	sessionsMu   sync.RWMutex
	sessionCount atomic.Uint64

	// prompts tracks pending prompts.
	prompts     map[dbus.ObjectPath]*PromptInfo
	promptsMu   sync.RWMutex
	promptCount atomic.Uint64

	// running indicates whether the service is running.
	running atomic.Bool

	// ctx is the service context for shutdown coordination.
	ctx    context.Context
	cancel context.CancelFunc

	// auditLog provides audit logging for security-relevant operations.
	auditLog atomic.Pointer[audit.Logger]
}

// NewDaemon creates a new Secret Service daemon.
func NewDaemon(store staticpw.Store, config *ServiceConfig, logger *slog.Logger) (*Daemon, error) {
	if store == nil {
		return nil, ErrNilPasswordStore
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
		mapper:   NewPathMapper(config),
		logger:   logger,
		sessions: make(map[dbus.ObjectPath]*SessionInfo),
		prompts:  make(map[dbus.ObjectPath]*PromptInfo),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Start connects to D-Bus and registers the Secret Service.
func (d *Daemon) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running.Load() {
		return ErrServiceAlreadyRunning
	}

	// Connect to D-Bus
	var conn *dbus.Conn
	var err error

	if d.config.Bus == "system" {
		conn, err = dbus.ConnectSystemBus()
	} else {
		conn, err = dbus.ConnectSessionBus()
	}
	if err != nil {
		d.logger.Error("failed to connect to D-Bus",
			slog.String("bus", d.config.Bus),
			slog.String("error", err.Error()))
		return ErrDBusUnavailable
	}

	d.conn = conn

	// Request the well-known name
	reply, err := conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		d.logger.Error("failed to request D-Bus name",
			slog.String("name", BusName),
			slog.String("error", err.Error()))
		conn.Close()
		return ErrDBusUnavailable
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		d.logger.Error("failed to become primary owner of D-Bus name",
			slog.String("name", BusName),
			slog.Int("reply", int(reply)))
		conn.Close()
		return ErrServiceAlreadyRunning
	}

	// Export the service object
	if err := d.exportObjects(); err != nil {
		conn.Close()
		return err
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

	// Close D-Bus connection
	if d.conn != nil {
		_, err := d.conn.ReleaseName(BusName)
		if err != nil {
			d.logger.Warn("failed to release D-Bus name",
				slog.String("error", err.Error()))
		}
		d.conn.Close()
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
		return fmt.Errorf("failed to export Service: %w", err)
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
		return fmt.Errorf("failed to export introspection: %w", err)
	}

	return nil
}

// ============================================================================
// org.freedesktop.Secret.Service Interface Implementation
// ============================================================================

// OpenSession opens a session for encrypted communication.
// Returns the server's public output and the session object path.
func (d *Daemon) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("OpenSession called",
		slog.String("algorithm", algorithm))

	sessionID := strconv.FormatUint(d.sessionCount.Add(1), 10)
	sessionPath := d.mapper.SessionPath(sessionID)

	session := &SessionInfo{
		Path:       sessionPath,
		Algorithm:  algorithm,
		CreatedAt:  time.Now(),
		ClientPath: "", // TODO: get sender
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
		return dbus.Variant{}, "/", dbus.MakeFailedError(ErrInvalidAlgorithm)
		d.logSecretServiceEvent(audit.OpSecretServiceSessionOpened, false, ErrInvalidAlgorithm, map[string]any{"algorithm": algorithm})
	}

	// Store the session
	d.sessionsMu.Lock()
	d.sessions[sessionPath] = session
	d.sessionsMu.Unlock()

	d.logger.Debug("session opened",
		slog.String("path", string(sessionPath)),
		slog.String("algorithm", algorithm))

	d.logSecretServiceEvent(audit.OpSecretServiceSessionOpened, true, nil, map[string]any{"algorithm": algorithm})
	return output, sessionPath, nil
}

// CreateCollection creates a new collection with the given properties.
func (d *Daemon) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("CreateCollection called",
		slog.String("alias", alias))

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

	// Generate collection path
	collectionPath := d.mapper.CollectionPathFromFolder(folderPath)

	// Emit CollectionCreated signal
	if err := d.conn.Emit(ServicePath, ServiceInterface+".CollectionCreated", collectionPath); err != nil {
		d.logger.Warn("failed to emit CollectionCreated signal",
			slog.String("error", err.Error()))
	}

	// No prompt needed
	return collectionPath, "/", nil
}

// SearchItems searches for items matching the given attributes.
func (d *Daemon) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("SearchItems called",
		slog.Any("attributes", attributes))

	searchCriteria := AttributesToSearchCriteria(attributes)

	// Get all passwords
	passwords, err := d.store.List()
	if err != nil {
		d.logSecretServiceEvent(audit.OpSecretServiceSearch, false, err, nil)
		return nil, nil, dbus.MakeFailedError(err)
	}

	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath

	for _, pw := range passwords {
		// Build item attributes
		itemAttrs := PasswordToItemAttributes(pw.Name, pw.Username, pw.URL)

		// Check if attributes match
		if MatchAttributes(itemAttrs, searchCriteria) {
			collectionPath := d.mapper.CollectionPathFromFolder(pw.FolderPath)
			itemPath := d.mapper.ItemPathFromPassword(collectionPath, pw.ID)

			// Items are always "unlocked" since go-xkms handles encryption
			unlocked = append(unlocked, itemPath)
		}
	}

	d.logSecretServiceEvent(audit.OpSecretServiceSearch, true, nil, map[string]any{"result_count": len(unlocked) + len(locked)})
	return unlocked, locked, nil
}

// Unlock unlocks the specified objects (collections or items).
// Since go-xkms handles encryption internally, this is mostly a no-op.
func (d *Daemon) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("Unlock called",
		slog.Int("count", len(objects)))

	// All objects are considered unlocked
	d.logSecretServiceEvent(audit.OpSecretServiceUnlock, true, nil, nil)
	return objects, "/", nil
}

// Lock locks the specified objects.
// Since go-xkms handles encryption internally, this is mostly a no-op.
func (d *Daemon) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("Lock called",
		slog.Int("count", len(objects)))

	// We don't actually lock individual items
	d.logSecretServiceEvent(audit.OpSecretServiceLock, true, nil, nil)
	return nil, "/", nil
}

// GetSecrets retrieves the secrets for the specified items.
func (d *Daemon) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (map[dbus.ObjectPath]SecretStruct, *dbus.Error) {
	d.logger.Debug("GetSecrets called",
		slog.Int("items", len(items)),
		slog.String("session", string(session)))

	// Get session
	d.sessionsMu.RLock()
	sess, exists := d.sessions[session]
	d.sessionsMu.RUnlock()

	if !exists {
		return nil, dbus.MakeFailedError(ErrSessionNotFound)
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

	d.logSecretServiceEvent(audit.OpSecretServiceSecretAccessed, true, nil, map[string]any{"item_count": len(items)})
	return result, nil
}

// ReadAlias returns the collection for the given alias.
func (d *Daemon) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("ReadAlias called",
		slog.String("alias", name))

	folderPath := d.mapper.FolderFromAlias(name)
	return d.mapper.CollectionPathFromFolder(folderPath), nil
}

// SetAlias sets an alias for a collection.
func (d *Daemon) SetAlias(name string, collection dbus.ObjectPath) *dbus.Error {
	d.logger.Debug("SetAlias called",
		slog.String("alias", name),
		slog.String("collection", string(collection)))

	// Aliases are managed through config, this is a no-op for now
	return nil
}

// Collections returns the list of available collections.
// This is a D-Bus property getter.
func (d *Daemon) Collections() ([]dbus.ObjectPath, *dbus.Error) {
	d.logger.Debug("Collections property accessed")

	// Get all folders
	folders, err := d.store.ListFolders()
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	// Always include default collection
	collections := []dbus.ObjectPath{
		d.mapper.CollectionPathFromFolder(""),
	}

	// Add a collection for each folder
	for _, folder := range folders {
		path := d.mapper.CollectionPathFromFolder(folder)
		collections = append(collections, path)
	}

	return collections, nil
}

// CloseSession closes an encryption session.
func (d *Daemon) CloseSession(sessionPath dbus.ObjectPath) *dbus.Error {
	d.sessionsMu.Lock()
	defer d.sessionsMu.Unlock()

	if _, exists := d.sessions[sessionPath]; !exists {
		return dbus.MakeFailedError(ErrSessionNotFound)
	}

	delete(d.sessions, sessionPath)
	d.logger.Debug("session closed",
		slog.String("path", string(sessionPath)))
	d.logSecretServiceEvent(audit.OpSecretServiceSessionClosed, true, nil, nil)

	return nil
}

// getSession retrieves a session by path.
func (d *Daemon) getSession(path dbus.ObjectPath) (*SessionInfo, bool) {
	d.sessionsMu.RLock()
	defer d.sessionsMu.RUnlock()
	sess, ok := d.sessions[path]
	return sess, ok
}

// SetAuditLogger sets the audit logger for the Secret Service daemon.
func (d *Daemon) SetAuditLogger(l audit.Logger) {
	d.auditLog.Store(&l)
}

// logSecretServiceEvent logs an audit event for Secret Service operations.
func (d *Daemon) logSecretServiceEvent(op audit.OperationType, success bool, err error, details map[string]any) {
	if p := d.auditLog.Load(); p != nil {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		(*p).Log(audit.Entry{
			Timestamp: time.Now(),
			Operation: op,
			Success:   success,
			Error:     errStr,
			Details:   details,
		})
	}
}
