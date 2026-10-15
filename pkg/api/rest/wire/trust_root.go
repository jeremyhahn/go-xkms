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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TrustRootsPath is the collection of the platform trust roots.
const TrustRootsPath = "/api/v1/trust-roots"

// TrustRootPath returns the path of the trust root fingerprint, followed by
// an optional action segment ("quarantine").
func TrustRootPath(fingerprint string, action ...string) string {
	path := TrustRootsPath + "/" + url.PathEscape(fingerprint)
	for _, a := range action {
		path += "/" + a
	}
	return path
}

// Compile-time check that the client serves the whole trust-root API.
var _ transport.TrustRootService = TrustRootClient{}

// TrustRootClient serves transport.TrustRootService over the REST routes.
// The REST and QUIC transports delegate to it with their own Requester.
type TrustRootClient struct {
	// Do performs the requests.
	Do Requester
}

// root performs a request answered by a trust root.
func (c TrustRootClient) root(ctx context.Context, method, path string) (*transport.TrustRoot, error) {
	var resp transport.TrustRoot
	if err := callJSON(ctx, c.Do, method, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TrustRootList lists the trust roots, optionally of one purpose.
func (c TrustRootClient) TrustRootList(ctx context.Context, req *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TrustRootListResponse
	path := withQuery(TrustRootsPath, map[string]string{"purpose": req.Purpose})
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TrustRootGet returns one trust root, its PEM included.
func (c TrustRootClient) TrustRootGet(ctx context.Context, req *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.root(ctx, http.MethodGet, TrustRootPath(req.Fingerprint))
}

// TrustRootImport adds the certificates of a PEM bundle.
func (c TrustRootClient) TrustRootImport(ctx context.Context, req *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.TrustRootImportResponse
	if err := callJSON(ctx, c.Do, http.MethodPost, TrustRootsPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// TrustRootQuarantine reclassifies a trust root as synced.
func (c TrustRootClient) TrustRootQuarantine(ctx context.Context, req *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.root(ctx, http.MethodPost, TrustRootPath(req.Fingerprint, "quarantine"))
}

// TrustRootRemove deletes a trust root.
func (c TrustRootClient) TrustRootRemove(ctx context.Context, req *transport.TrustRootRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callJSON(ctx, c.Do, http.MethodDelete, TrustRootPath(req.Fingerprint), nil, nil)
}
