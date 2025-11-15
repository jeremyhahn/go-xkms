# Storage Abstraction

The storage abstraction layer provides pluggable persistence for keychain backends.

## Overview

Benefits:
- **Flexibility**: Switch storage backends without changing keychain code
- **Testability**: Use memory storage for tests, file storage for production
- **Extensibility**: Implement custom storage backends (database, cloud, etc.)
- **Separation**: Keystore logic independent of persistence details

## Storage Interface

```go
type Backend interface {
    Get(key string) ([]byte, error)
    Put(key string, data []byte, opts *Options) error
    Delete(key string) error
    List(prefix string) ([]string, error)
    Exists(key string) (bool, error)
    Close() error
}
```

## File Storage

Persistent file-based storage using go-keychain's filesystem abstraction (compatible with go-objstore).

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// Create file storage
storage, err := file.New("/var/lib/keychain")
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Store data
err = storage.Put("my-key", []byte("key-data"), nil)

// Store with custom permissions
err = storage.Put("secure-key", []byte("data"), &storage.Options{
    Permissions: 0600,
})

// Retrieve data
data, err := storage.Get("my-key")

// List keys
keys, err := storage.List("")

// Check existence
exists, err := storage.Exists("my-key")

// Delete key
err = storage.Delete("my-key")
```

## Memory Storage

Ephemeral in-memory storage for testing.

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/storage"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
    "github.com/jeremyhahn/go-keychain/pkg/storage/fs"
)

// Create memory storage using in-memory filesystem
memFs := fs.NewMemFs()
storage, err := file.NewWithFS(memFs, &storage.Options{
    Path: "/test",
})
if err != nil {
    log.Fatal(err)
}
defer storage.Close()

// Same API as file storage
storage.Put("test-key", []byte("test-data"), nil)
data, _ := storage.Get("test-key")
```

## Custom Storage Backends

Implement the `Backend` interface:

```go
package custom

import "github.com/jeremyhahn/go-keychain/pkg/storage"

type CustomStorage struct {
    // Your implementation
}

func New(opts *storage.Options) (storage.Backend, error) {
    return &CustomStorage{}, nil
}

func (s *CustomStorage) Get(key string) ([]byte, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Put(key string, data []byte) error {
    // Implement
    return nil
}

func (s *CustomStorage) Delete(key string) error {
    // Implement
    return nil
}

func (s *CustomStorage) List(prefix string) ([]string, error) {
    // Implement
    return nil, nil
}

func (s *CustomStorage) Exists(key string) (bool, error) {
    // Implement
    return false, nil
}

func (s *CustomStorage) Close() error {
    // Cleanup
    return nil
}
```

## Database Storage Example

```go
package database

import (
    "database/sql"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
)

type DBStorage struct {
    db *sql.DB
}

func New(connectionString string) (storage.Backend, error) {
    db, err := sql.Open("postgres", connectionString)
    if err != nil {
        return nil, err
    }
    return &DBStorage{db: db}, nil
}

func (s *DBStorage) Put(key string, data []byte) error {
    _, err := s.db.Exec(
        "INSERT INTO keys (key, data) VALUES ($1, $2) "+
        "ON CONFLICT (key) DO UPDATE SET data = $2",
        key, data,
    )
    return err
}

func (s *DBStorage) Get(key string) ([]byte, error) {
    var data []byte
    err := s.db.QueryRow(
        "SELECT data FROM keys WHERE key = $1",
        key,
    ).Scan(&data)
    return data, err
}

func (s *DBStorage) Delete(key string) error {
    _, err := s.db.Exec("DELETE FROM keys WHERE key = $1", key)
    return err
}

func (s *DBStorage) List(prefix string) ([]string, error) {
    rows, err := s.db.Query(
        "SELECT key FROM keys WHERE key LIKE $1",
        prefix+"%",
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var keys []string
    for rows.Next() {
        var key string
        if err := rows.Scan(&key); err != nil {
            return nil, err
        }
        keys = append(keys, key)
    }
    return keys, rows.Err()
}

func (s *DBStorage) Exists(key string) (bool, error) {
    var exists bool
    err := s.db.QueryRow(
        "SELECT EXISTS(SELECT 1 FROM keys WHERE key = $1)",
        key,
    ).Scan(&exists)
    return exists, err
}

func (s *DBStorage) Close() error {
    return s.db.Close()
}
```

## PKCS#8 Integration

The PKCS#8 backend uses storage abstraction via the adapter pattern:

```go
import (
    "github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
    "github.com/jeremyhahn/go-keychain/pkg/storage"
    "github.com/jeremyhahn/go-keychain/pkg/storage/file"
)

// Create storage backend
keyStorage, err := file.New(&storage.Options{
    Path: "/var/lib/keychain/keys",
})
certStorage, err := file.New(&storage.Options{
    Path: "/var/lib/keychain/certs",
})

// PKCS#8 backend configuration
config := &pkcs8.Config{
    CN:          "my-app",
    Password:    []byte("secure-password"),
    KeyStorage:  keyStorage,
    CertStorage: certStorage,
}

// Create PKCS#8 backend (uses storage internally)
backend, err := pkcs8.New(config)
```

## Thread Safety

Storage implementations must be thread-safe:

```go
type SafeStorage struct {
    mu   sync.RWMutex
    data map[string][]byte
}

func (s *SafeStorage) Put(key string, data []byte) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data[key] = data
    return nil
}

func (s *SafeStorage) Get(key string) ([]byte, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    data, exists := s.data[key]
    if !exists {
        return nil, storage.ErrNotFound
    }
    return data, nil
}
```

## Error Handling

Standard errors:

```go
var (
    ErrNotFound       = errors.New("storage: key not found")
    ErrAlreadyExists  = errors.New("storage: key already exists")
    ErrInvalidKey     = errors.New("storage: invalid key")
)
```

Usage:

```go
data, err := storage.Get("nonexistent-key")
if errors.Is(err, storage.ErrNotFound) {
    // Handle missing key
}
```

## Performance Considerations

- **File Storage**: ~1ms writes, ~0.5ms reads
- **Memory Storage**: ~10µs writes, ~5µs reads
- **Database**: Varies by database and configuration
- Use buffering for bulk operations
- Consider caching for read-heavy workloads

## See Also

- [Getting Started Guide](getting-started.md)
- [Backend Registry](backend-registry.md)
- [Architecture Overview](architecture/overview.md)
