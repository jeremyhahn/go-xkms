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

package wire

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Key-version REST paths. The server's route table (pkg/api/rest/routes.go)
// registers the same paths with {id} and {version} placeholders.
const (
	// RotateScopeKeysPath rotates every key of a tenant.
	RotateScopeKeysPath = "/api/v1/keys/rotate-all"

	// Key version actions, the last path segment of a version route.
	KeyVersionEnable  = "enable"
	KeyVersionDisable = "disable"
	KeyVersionRetire  = "retire"

	// Bulk key version actions, the last path segment of a key's versions
	// route.
	KeyVersionsEnableAll  = "enable-all"
	KeyVersionsDisableAll = "disable-all"
)

// KeyVersionsPath returns the path of a key's versions, followed by an
// optional sub-path ("enable-all", "disable-all").
func KeyVersionsPath(keyID string, sub ...string) string {
	path := "/api/v1/keys/" + url.PathEscape(keyID) + "/versions"
	for _, s := range sub {
		path += "/" + s
	}
	return path
}

// KeyVersionPath returns the path of an action on one version of a key.
func KeyVersionPath(keyID string, version uint32, action string) string {
	return KeyVersionsPath(keyID, strconv.FormatUint(uint64(version), 10), action)
}

// withBackend appends the backend query parameter the key routes read.
func withBackend(path, backend string) string {
	return withQuery(path, map[string]string{"backend": backend})
}

// Compile-time check that the client serves the whole key-version API.
var _ transport.KeyVersionService = KeyVersionClient{}

// KeyVersionClient serves transport.KeyVersionService over the REST routes.
// The REST and QUIC transports (QUIC serves the same router over HTTP/3)
// delegate to it with their own Requester. The tenant of every call but
// RotateScopeKeys is the caller's, which the server takes from the
// authenticated identity.
type KeyVersionClient struct {
	// Do performs the requests.
	Do Requester
}

// ListKeyVersions lists a key's versions.
func (c KeyVersionClient) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.ListKeyVersionsResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, withBackend(KeyVersionsPath(req.KeyID), req.Backend), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnableKeyVersion enables a version of a key.
func (c KeyVersionClient) EnableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return c.versionAction(ctx, req, KeyVersionEnable)
}

// DisableKeyVersion disables a version of a key.
func (c KeyVersionClient) DisableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return c.versionAction(ctx, req, KeyVersionDisable)
}

// RetireKeyVersion retires a version of a key.
func (c KeyVersionClient) RetireKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	return c.versionAction(ctx, req, KeyVersionRetire)
}

// versionAction posts action on the version req names.
func (c KeyVersionClient) versionAction(ctx context.Context, req *transport.KeyVersionRequest, action string) (*transport.KeyVersionStateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.KeyVersionStateResponse
	path := withBackend(KeyVersionPath(req.KeyID, req.Version, action), req.Backend)
	if err := callJSON(ctx, c.Do, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnableAllKeyVersions enables every disabled version of a key.
func (c KeyVersionClient) EnableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return c.allAction(ctx, req, KeyVersionsEnableAll)
}

// DisableAllKeyVersions disables every non-current version of a key.
func (c KeyVersionClient) DisableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	return c.allAction(ctx, req, KeyVersionsDisableAll)
}

// allAction posts a bulk action on the versions of the key req names.
func (c KeyVersionClient) allAction(ctx context.Context, req *transport.AllKeyVersionsRequest, action string) (*transport.AllKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AllKeyVersionsResponse
	path := withBackend(KeyVersionsPath(req.KeyID, action), req.Backend)
	if err := callJSON(ctx, c.Do, http.MethodPost, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RotateScopeKeys rotates every key of a tenant.
func (c KeyVersionClient) RotateScopeKeys(ctx context.Context, req *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.RotateScopeKeysResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, RotateScopeKeysPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
