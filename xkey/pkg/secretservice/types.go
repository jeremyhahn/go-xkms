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
	"time"

	"github.com/godbus/dbus/v5"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// D-Bus interface names and paths
const (
	// ServiceInterface is the main Secret Service D-Bus interface.
	ServiceInterface = "org.freedesktop.Secret.Service"

	// CollectionInterface is the D-Bus interface for collections.
	CollectionInterface = "org.freedesktop.Secret.Collection"

	// ItemInterface is the D-Bus interface for items.
	ItemInterface = "org.freedesktop.Secret.Item"

	// SessionInterface is the D-Bus interface for sessions.
	SessionInterface = "org.freedesktop.Secret.Session"

	// PromptInterface is the D-Bus interface for prompts.
	PromptInterface = "org.freedesktop.Secret.Prompt"

	// ServicePath is the D-Bus object path for the service.
	ServicePath = dbus.ObjectPath("/org/freedesktop/secrets")

	// CollectionPathPrefix is the prefix for collection object paths.
	CollectionPathPrefix = "/org/freedesktop/secrets/collection/"

	// AliasPathPrefix is the prefix for alias object paths.
	AliasPathPrefix = "/org/freedesktop/secrets/aliases/"

	// SessionPathPrefix is the prefix for session object paths.
	SessionPathPrefix = "/org/freedesktop/secrets/session/"

	// PromptPathPrefix is the prefix for prompt object paths.
	PromptPathPrefix = "/org/freedesktop/secrets/prompt/"

	// BusName is the well-known D-Bus name for the Secret Service.
	BusName = "org.freedesktop.secrets"

	// DBusPropertiesInterface is the standard D-Bus properties interface
	// that Collection and Item objects implement (Get/GetAll/Set) instead
	// of the godbus prop package's static value cache, so Locked always
	// reflects live barrier state rather than a snapshot that must be
	// re-broadcast on every seal/unseal.
	DBusPropertiesInterface = "org.freedesktop.DBus.Properties"
)

// Algorithm identifiers for session encryption.
const (
	// AlgorithmPlain indicates no encryption (secrets sent in plaintext).
	AlgorithmPlain = "plain"

	// AlgorithmDH is the Diffie-Hellman algorithm for session encryption.
	// Uses DH group 14 (2048-bit MODP) with AES-128-CBC encryption.
	AlgorithmDH = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

// Default collection names.
const (
	// DefaultCollection is the alias for the default collection.
	DefaultCollection = "default"

	// LoginCollection is the alias for the login collection.
	LoginCollection = "login"

	// SessionCollection is a volatile collection for session secrets.
	SessionCollection = "session"
)

// SecretStruct represents the D-Bus secret structure (a(oayays)).
// This is the wire format for secrets transmitted over D-Bus.
type SecretStruct struct {
	// Session is the object path of the session used for encryption.
	Session dbus.ObjectPath

	// Parameters contains encryption parameters (e.g., IV for AES-CBC).
	Parameters []byte

	// Value is the secret value (encrypted or plaintext depending on session).
	Value []byte

	// ContentType is the MIME type of the secret (e.g., "text/plain; charset=utf8").
	ContentType string
}

// ItemAttributes represents searchable attributes for an item.
// Keys and values are strings; common attributes include:
// - "service": application or service name
// - "username": account username
// - "xdg:schema": schema identifier
type ItemAttributes map[string]string

// CollectionInfo holds metadata about a collection.
type CollectionInfo struct {
	// Path is the D-Bus object path.
	Path dbus.ObjectPath

	// Label is the human-readable display name.
	Label string

	// Locked indicates whether the collection requires unlocking.
	Locked bool

	// Created is the creation timestamp (Unix seconds).
	Created uint64

	// Modified is the last modification timestamp (Unix seconds).
	Modified uint64

	// FolderPath is the corresponding password folder path in go-xkms.
	FolderPath string
}

// ItemInfo holds metadata about an item.
type ItemInfo struct {
	// Path is the D-Bus object path.
	Path dbus.ObjectPath

	// Label is the human-readable display name.
	Label string

	// Locked indicates whether the item requires unlocking.
	Locked bool

	// Created is the creation timestamp (Unix seconds).
	Created uint64

	// Modified is the last modification timestamp (Unix seconds).
	Modified uint64

	// Attributes are the searchable item attributes.
	Attributes ItemAttributes

	// PasswordID is the corresponding password ID in go-xkms.
	PasswordID string
}

// SessionInfo holds state for an active session.
type SessionInfo struct {
	// Path is the D-Bus object path.
	Path dbus.ObjectPath

	// Algorithm is the encryption algorithm ("plain" or "dh-ietf1024-sha256-aes128-cbc-pkcs7").
	Algorithm string

	// AESKey is the derived AES key for encrypted sessions (nil for plain).
	AESKey []byte

	// CreatedAt is when the session was established.
	CreatedAt time.Time

	// ClientPath is the D-Bus unique name of the client that opened this session.
	ClientPath string
}

// PromptInfo holds state for a pending prompt. The only prompted operation
// this daemon issues is unlocking the barrier (see Daemon.Unlock):
// Collection/Item Delete and Collection CreateItem execute immediately and
// never return a prompt path, so PromptType is always PromptTypeUnlock
// today. The field is kept for the same reason the Secret Service API keeps
// a "prompt" out-parameter on every method that can require one: a future
// prompted operation (e.g. a delete confirmation) adds a case here rather
// than a parallel mechanism.
type PromptInfo struct {
	// Path is the D-Bus object path.
	Path dbus.ObjectPath

	// Type indicates what the prompt is for.
	Type PromptType

	// Objects are the object paths involved in the prompted operation.
	// For PromptTypeUnlock, these are the collections that were locked
	// when Unlock was called.
	Objects []dbus.ObjectPath

	// CreatedAt is when the prompt was created.
	CreatedAt time.Time

	// done is closed once Prompt or Dismiss has resolved this prompt, so a
	// second call is rejected instead of re-running the unlock flow or
	// re-emitting Completed.
	done chan struct{}
}

// PromptType indicates the type of operation requiring a prompt.
type PromptType int

const (
	// PromptTypeUnlock is for unlocking the barrier on behalf of one or
	// more locked collections.
	PromptTypeUnlock PromptType = iota
)

// UnlockFunc collects the credentials needed to unseal the barrier -- a
// terminal password prompt, a GUI dialog, or a configured auto-unseal
// factor -- and returns them. It is supplied by the code that wires the
// daemon (the `xkey secret-service` CLI verb or a GUI toggle) so this
// package stays free of terminal/GUI dependencies; see
// xkey/cmd/xkey/cmd/secret_service.go for the CLI implementation, which
// reuses the same --barrier-password/--barrier-password-file/
// XKEY_BARRIER_PASSWORD resolution as `xkey barrier unseal`.
//
// A nil UnlockFunc means the daemon can service Unlock only when the
// barrier is already open by some other means (e.g. TPM auto-unseal run
// before the daemon started): every Prompt created while sealed then
// resolves as dismissed.
type UnlockFunc func(ctx context.Context) (xkms.SealCredentials, error)

// ServiceConfig holds configuration for the Secret Service daemon.
type ServiceConfig struct {
	// Bus specifies which D-Bus bus to use ("session" or "system").
	// Defaults to "session".
	Bus string

	// DefaultCollectionFolder is the folder path for the default/login collections.
	// Defaults to "" (root folder).
	DefaultCollectionFolder string

	// CollectionFolderMap maps collection names to folder paths.
	// e.g., {"ssh": "ssh", "wifi": "wifi"}
	CollectionFolderMap map[string]string
}

// DefaultConfig returns a ServiceConfig with sensible defaults.
func DefaultConfig() *ServiceConfig {
	return &ServiceConfig{
		Bus:                     "session",
		DefaultCollectionFolder: "",
		CollectionFolderMap: map[string]string{
			"ssh":  "ssh",
			"wifi": "wifi",
		},
	}
}
