package config

import (
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// DatastoreEngines lists the accepted datastore.engine values: go-qrdb's
// local database backends, taken from its SDK. The SDK exposes the backend
// constants but no list of them, so the list is kept here, once.
var DatastoreEngines = []string{
	string(qrdbsdk.BackendMemory),
	string(qrdbsdk.BackendFile),
	string(qrdbsdk.BackendPebble),
}

// DatastoreModes lists the accepted datastore.mode values.
var DatastoreModes = []string{"standalone", "remote"}

// ErrUnknownDatastoreEngine is returned for a datastore.engine value that
// is not one of DatastoreEngines.
type ErrUnknownDatastoreEngine struct {
	// Engine is the configured value, as written.
	Engine string
}

func (e *ErrUnknownDatastoreEngine) Error() string {
	return "config: unknown datastore.engine " + strconv.Quote(e.Engine) +
		" (must be one of: " + strings.Join(DatastoreEngines, ", ") + ")"
}

// ErrUnknownDatastoreMode is returned for a datastore.mode value that is
// not one of DatastoreModes.
type ErrUnknownDatastoreMode struct {
	// Mode is the configured value, as written.
	Mode string
}

func (e *ErrUnknownDatastoreMode) Error() string {
	return "config: unknown datastore.mode " + strconv.Quote(e.Mode) +
		" (must be one of: " + strings.Join(DatastoreModes, ", ") + ")"
}

// NormalizeDatastoreEngine trims and lowercases engine and checks it
// against DatastoreEngines. An empty engine returns "" with no error, so
// the caller applies its documented default.
func NormalizeDatastoreEngine(engine string) (string, error) {
	return normalizeChoice(engine, DatastoreEngines, &ErrUnknownDatastoreEngine{Engine: engine})
}

// NormalizeDatastoreMode trims and lowercases mode and checks it against
// DatastoreModes. An empty mode returns "" with no error, so the caller
// applies its documented default.
func NormalizeDatastoreMode(mode string) (string, error) {
	return normalizeChoice(mode, DatastoreModes, &ErrUnknownDatastoreMode{Mode: mode})
}

// normalizeChoice returns value trimmed and lowercased when it is empty or
// one of allowed, and unknown otherwise.
func normalizeChoice(value string, allowed []string, unknown error) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "", nil
	}
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", unknown
}
