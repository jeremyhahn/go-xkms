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

package pbconv

import (
	"math"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The key-version messages carry a version number as int32, the type the
// proto declared them with before the API was implemented; the service and
// every other transport count versions as uint32.

// versionToProto converts a version number to its wire form. A number past
// int32's range, which no key reaches, is clamped rather than wrapped to a
// negative number.
func versionToProto(v uint32) int32 {
	if v > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(v) // #nosec G115 -- bounded above
}

// versionFromProto converts a wire version number. A negative number names
// no version and becomes 0, which the service refuses as an invalid version.
func versionFromProto(v int32) uint32 {
	if v < 0 {
		return 0
	}
	return uint32(v) // #nosec G115 -- non-negative
}

// versionsToProto converts a list of version numbers to its wire form.
func versionsToProto(in []uint32) []int32 {
	out := make([]int32, 0, len(in))
	for _, v := range in {
		out = append(out, versionToProto(v))
	}
	return out
}

// versionsFromProto converts a wire list of version numbers.
func versionsFromProto(in []int32) []uint32 {
	out := make([]uint32, 0, len(in))
	for _, v := range in {
		out = append(out, versionFromProto(v))
	}
	return out
}

// ListKeyVersionsResponseToProto converts a key's version listing to its
// wire form.
func ListKeyVersionsResponseToProto(r *transport.ListKeyVersionsResponse) *pb.ListKeyVersionsResponse {
	out := &pb.ListKeyVersionsResponse{
		KeyId:          r.KeyID,
		Backend:        r.Backend,
		CurrentVersion: versionToProto(r.CurrentVersion),
		Versions:       make([]*pb.KeyVersionInfo, 0, len(r.Versions)),
		Total:          int32(min(len(r.Versions), math.MaxInt32)), // #nosec G115 -- bounded above
	}
	for _, v := range r.Versions {
		out.Versions = append(out.Versions, &pb.KeyVersionInfo{
			Version:      versionToProto(v.Version),
			Status:       v.State,
			CreatedAt:    v.CreatedAt,
			CreatedBy:    v.CreatedBy,
			Current:      v.Current,
			PublicKeyPem: v.PublicKeyPEM,
		})
	}
	return out
}

// ListKeyVersionsResponseFromProto converts a wire version listing.
func ListKeyVersionsResponseFromProto(r *pb.ListKeyVersionsResponse) *transport.ListKeyVersionsResponse {
	out := &transport.ListKeyVersionsResponse{
		KeyID:          r.GetKeyId(),
		Backend:        r.GetBackend(),
		CurrentVersion: versionFromProto(r.GetCurrentVersion()),
		Versions:       make([]transport.KeyVersionInfo, 0, len(r.GetVersions())),
	}
	for _, v := range r.GetVersions() {
		out.Versions = append(out.Versions, transport.KeyVersionInfo{
			Version:      versionFromProto(v.GetVersion()),
			State:        v.GetStatus(),
			Current:      v.GetCurrent(),
			CreatedAt:    v.GetCreatedAt(),
			CreatedBy:    v.GetCreatedBy(),
			PublicKeyPEM: v.GetPublicKeyPem(),
		})
	}
	return out
}

// EnableKeyVersionResponseToProto converts an enable result to its wire form.
func EnableKeyVersionResponseToProto(r *transport.KeyVersionStateResponse) *pb.EnableKeyVersionResponse {
	return &pb.EnableKeyVersionResponse{KeyId: r.KeyID, Version: versionToProto(r.Version), Status: r.State, Changed: r.Changed}
}

// DisableKeyVersionResponseToProto converts a disable result to its wire
// form.
func DisableKeyVersionResponseToProto(r *transport.KeyVersionStateResponse) *pb.DisableKeyVersionResponse {
	return &pb.DisableKeyVersionResponse{KeyId: r.KeyID, Version: versionToProto(r.Version), Status: r.State, Changed: r.Changed}
}

// RetireKeyVersionResponseToProto converts a retire result to its wire form.
func RetireKeyVersionResponseToProto(r *transport.KeyVersionStateResponse) *pb.RetireKeyVersionResponse {
	return &pb.RetireKeyVersionResponse{KeyId: r.KeyID, Version: versionToProto(r.Version), Status: r.State, Changed: r.Changed}
}

// versionStateMessage is the accessor set every generated version state
// response shares.
type versionStateMessage interface {
	GetKeyId() string
	GetVersion() int32
	GetStatus() string
	GetChanged() bool
}

// KeyVersionStateResponseFromProto converts any wire version state response
// (enable, disable, retire).
func KeyVersionStateResponseFromProto(r versionStateMessage) *transport.KeyVersionStateResponse {
	return &transport.KeyVersionStateResponse{
		KeyID:   r.GetKeyId(),
		Version: versionFromProto(r.GetVersion()),
		State:   r.GetStatus(),
		Changed: r.GetChanged(),
	}
}

// KeyVersionFromProto converts a wire version number named by a request.
func KeyVersionFromProto(v int32) uint32 { return versionFromProto(v) }

// KeyVersionToProto converts a version number for a request.
func KeyVersionToProto(v uint32) int32 { return versionToProto(v) }

// EnableAllKeyVersionsResponseToProto converts a bulk enable result to its
// wire form.
func EnableAllKeyVersionsResponseToProto(r *transport.AllKeyVersionsResponse) *pb.EnableAllKeyVersionsResponse {
	return &pb.EnableAllKeyVersionsResponse{
		KeyId:    r.KeyID,
		Count:    int32(min(r.Count, math.MaxInt32)), // #nosec G115 -- bounded above
		Versions: versionsToProto(r.Versions),
		State:    r.State,
	}
}

// DisableAllKeyVersionsResponseToProto converts a bulk disable result to its
// wire form.
func DisableAllKeyVersionsResponseToProto(r *transport.AllKeyVersionsResponse) *pb.DisableAllKeyVersionsResponse {
	return &pb.DisableAllKeyVersionsResponse{
		KeyId:    r.KeyID,
		Count:    int32(min(r.Count, math.MaxInt32)), // #nosec G115 -- bounded above
		Versions: versionsToProto(r.Versions),
		State:    r.State,
	}
}

// allVersionsMessage is the accessor set both generated bulk responses
// share.
type allVersionsMessage interface {
	GetKeyId() string
	GetVersions() []int32
	GetState() string
}

// AllKeyVersionsResponseFromProto converts either wire bulk response.
func AllKeyVersionsResponseFromProto(r allVersionsMessage) *transport.AllKeyVersionsResponse {
	versions := versionsFromProto(r.GetVersions())
	return &transport.AllKeyVersionsResponse{
		KeyID:    r.GetKeyId(),
		State:    r.GetState(),
		Versions: versions,
		Count:    len(versions),
	}
}

// RotateScopeKeysResponseToProto converts a scope rotation report to its
// wire form.
func RotateScopeKeysResponseToProto(r *transport.RotateScopeKeysResponse) *pb.RotateScopeKeysResponse {
	out := &pb.RotateScopeKeysResponse{
		TenantId: r.TenantID,
		Results:  make([]*pb.KeyRotationResult, 0, len(r.Results)),
		Rotated:  int32(min(r.Rotated, math.MaxInt32)), // #nosec G115 -- bounded above
		Failed:   int32(min(r.Failed, math.MaxInt32)),  // #nosec G115 -- bounded above
	}
	for _, result := range r.Results {
		out.Results = append(out.Results, &pb.KeyRotationResult{
			Backend:    result.Backend,
			KeyId:      result.KeyID,
			KeyVersion: result.KeyVersion,
			Error:      result.Error,
		})
	}
	return out
}

// RotateScopeKeysResponseFromProto converts a wire scope rotation report.
func RotateScopeKeysResponseFromProto(r *pb.RotateScopeKeysResponse) *transport.RotateScopeKeysResponse {
	out := &transport.RotateScopeKeysResponse{
		TenantID: r.GetTenantId(),
		Results:  make([]transport.KeyRotationResult, 0, len(r.GetResults())),
		Rotated:  int(r.GetRotated()),
		Failed:   int(r.GetFailed()),
	}
	for _, result := range r.GetResults() {
		out.Results = append(out.Results, transport.KeyRotationResult{
			Backend:    result.GetBackend(),
			KeyID:      result.GetKeyId(),
			KeyVersion: result.GetKeyVersion(),
			Error:      result.GetError(),
		})
	}
	return out
}
