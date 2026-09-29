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

package authzscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// grpcSeams mirrors the gRPC transport's gate shape:
// authorize(ctx, resource, action, resourceID). The second seam exercises the
// FixedResource pinning capability against a wrapper that hard-codes its
// resource.
var grpcSeams = []Seam{
	{Method: "authorize", Args: 4, ResourceArg: 1, ActionArg: 2},
	{Method: "authorizePinned", Args: 3, ResourceArg: -1, ActionArg: 1, FixedResource: "ResourceAdmin"},
}

// writePkg materializes a single-file Go package in a temp dir and returns it.
func writePkg(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
	}
	return dir
}

func TestScan_ResolvesConstantsToWireValues(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"svc.go": `package svc

func (s *Service) GetKey() error {
	return s.authorize(ctx, auth.ResourceKeys, auth.ActionGet, "id")
}

func (s *Service) UpdateThing() error {
	return s.authorizePinned(ctx, auth.ActionUpdate, "thing")
}

// authorize is the seam itself; its arguments are parameters, so it must not
// be reported as a gate.
func (s *Service) authorize(ctx context.Context, resource, action, id string) error {
	return nil
}

func (s *Service) authorizePinned(ctx context.Context, action, id string) error {
	return s.authorize(ctx, auth.ResourceAdmin, action, id)
}
`,
		// A _test.go file must be ignored entirely.
		"svc_test.go": `package svc

func TestSomething() error {
	return s.authorize(ctx, "keys", "delete", "id")
}
`,
	})

	sites, err := Scan(dir, grpcSeams)
	require.NoError(t, err)
	require.Len(t, sites, 2)

	got := map[string]string{}
	for _, s := range sites {
		got[s.Key] = s.Pair()
		assert.NotEmpty(t, s.Pos, "every site must carry a source position")
	}
	assert.Equal(t, map[string]string{
		"GetKey":      auth.ResourceKeys + ":" + auth.ActionGet,
		"UpdateThing": auth.ResourceAdmin + ":" + auth.ActionUpdate,
	}, got)
}

func TestScan_DisambiguatesRepeatedGatesAndRecordsIndirection(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"routes.go": `package svc

func (s *Server) setupRoutes() {
	s.authorize(w, r, auth.ResourcePasswords, operationForMethod(r.Method))
	s.authorize(w, r, auth.ResourcePasswords, auth.ActionUnlock)
	s.authorize(w, r, auth.ResourcePasswords, dynamicAction)
}
`,
	})

	sites, err := Scan(dir, []Seam{{Method: "authorize", Args: 4, ResourceArg: 2, ActionArg: 3}})
	require.NoError(t, err)
	require.Len(t, sites, 3)

	assert.Equal(t, "setupRoutes#0", sites[0].Key)
	assert.Equal(t, auth.ResourcePasswords+":<operationForMethod>", sites[0].Pair())
	assert.Equal(t, "setupRoutes#1", sites[1].Key)
	assert.Equal(t, auth.ResourcePasswords+":"+auth.ActionUnlock, sites[1].Pair())
	assert.Equal(t, "setupRoutes#2", sites[2].Key)
	assert.Equal(t, auth.ResourcePasswords+":<dynamicAction>", sites[2].Pair())
}

func TestScan_RecordsEveryIndirectionShape(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"routes.go": `package svc

func (s *Server) gates() {
	// Selector on a package that is not pkg/auth.
	s.authorize(w, r, other.ResourceKeys, auth.ActionGet)
	// Call through a package selector.
	s.authorize(w, r, auth.ResourceKeys, other.ActionFor(r))
	// Call through a non-identifier function expression.
	s.authorize(w, r, auth.ResourceKeys, table[0](r))
	// An expression that is none of the above.
	s.authorize(w, r, auth.ResourceKeys, actions[0])
}
`,
	})

	sites, err := Scan(dir, []Seam{{Method: "authorize", Args: 4, ResourceArg: 2, ActionArg: 3}})
	require.NoError(t, err, "an indirection must be recorded, not rejected")
	require.Len(t, sites, 4)

	assert.Equal(t, "<ResourceKeys>:"+auth.ActionGet, sites[0].Pair(),
		"a selector outside pkg/auth must be marked as an indirection, not resolved")
	assert.Equal(t, auth.ResourceKeys+":<ActionFor>", sites[1].Pair())
	assert.Equal(t, auth.ResourceKeys+":<call>", sites[2].Pair())
	assert.Equal(t, auth.ResourceKeys+":<expr>", sites[3].Pair())
}

func TestScan_RejectsRawLiteral(t *testing.T) {
	for name, src := range map[string]string{
		"resource literal": `package svc

func (s *Service) GetKey() error {
	return s.authorize(ctx, "keys", auth.ActionGet, "id")
}
`,
		"action literal": `package svc

func (s *Service) GetKey() error {
	return s.authorize(ctx, auth.ResourceKeys, "get", "id")
}
`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := writePkg(t, map[string]string{"svc.go": src})

			sites, err := Scan(dir, grpcSeams)
			require.Error(t, err, "a raw literal at a gate must be rejected, not scanned")
			assert.Nil(t, sites)

			var rawErr *RawLiteralError
			require.True(t, errors.As(err, &rawErr), "want *RawLiteralError, got %T", err)
			assert.Contains(t, rawErr.Error(), "use the pkg/auth constant")
			assert.Contains(t, rawErr.Pos, "svc.go:")
		})
	}
}

func TestScan_RejectsUnknownConstant(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"svc.go": `package svc

func (s *Service) GetKey() error {
	return s.authorize(ctx, auth.ResourceInvented, auth.ActionGet, "id")
}
`,
	})

	sites, err := Scan(dir, grpcSeams)
	require.Error(t, err)
	assert.Nil(t, sites)

	var unknown *UnknownConstantError
	require.True(t, errors.As(err, &unknown), "want *UnknownConstantError, got %T", err)
	assert.Equal(t, "ResourceInvented", unknown.Name)
}

func TestScan_RejectsUnknownFixedResource(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"svc.go": `package svc

func (s *Service) UpdateThing() error {
	return s.authorizePinned(ctx, auth.ActionUpdate, "thing")
}
`,
	})

	sites, err := Scan(dir, []Seam{
		{Method: "authorizePinned", Args: 3, ResourceArg: -1, ActionArg: 1, FixedResource: "ResourceNotReal"},
	})
	require.Error(t, err, "a seam pinned to a constant this package does not know must fail")
	assert.Nil(t, sites)

	var unknown *UnknownConstantError
	require.True(t, errors.As(err, &unknown), "want *UnknownConstantError, got %T", err)
	assert.Equal(t, "ResourceNotReal", unknown.Name)
}

func TestScan_RejectsUnparseableSource(t *testing.T) {
	dir := writePkg(t, map[string]string{"broken.go": "package svc\n\nfunc (s *Service) Oops( {\n"})

	sites, err := Scan(dir, grpcSeams)
	require.Error(t, err)
	assert.Nil(t, sites)

	var parseErr *ParseError
	require.True(t, errors.As(err, &parseErr), "want *ParseError, got %T", err)
	assert.Contains(t, parseErr.File, "broken.go")
	assert.NotNil(t, parseErr.Unwrap())
}

func TestScan_RejectsMissingDirectory(t *testing.T) {
	sites, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"), grpcSeams)
	require.Error(t, err)
	assert.Nil(t, sites)

	var parseErr *ParseError
	require.True(t, errors.As(err, &parseErr), "want *ParseError, got %T", err)
	assert.True(t, errors.Is(err, os.ErrNotExist), "the underlying os error must stay unwrappable")
}

func TestScan_IgnoresNonSeamCallsAndDeclarations(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"svc.go": `package svc

import "fmt"

type Service struct{}

var notAFunction = fmt.Sprintf("keys", "get")

func (s *Service) GetKey() error {
	// Wrong arity for the seam, so not a gate.
	s.authorize(ctx, auth.ResourceKeys)
	// A different method entirely.
	s.authenticate(ctx, auth.ResourceKeys, auth.ActionGet, "id")
	// Not a selector call.
	authorize(ctx, auth.ResourceKeys, auth.ActionGet, "id")
	return nil
}
`,
		"nobody.go": `package svc

func Declared() error
`,
	})

	sites, err := Scan(dir, grpcSeams)
	require.NoError(t, err)
	assert.Empty(t, sites)
}

func TestConstants_CoverTheCanonicalVocabulary(t *testing.T) {
	constants := Constants()

	// Spot-check that values come from pkg/auth rather than being retyped.
	assert.Equal(t, auth.ResourceKeys, constants["ResourceKeys"])
	assert.Equal(t, auth.ActionUnsealShare, constants["ActionUnsealShare"])
	assert.Equal(t, auth.ResourceCA, constants["ResourceCA"])

	// No name may map to an empty string: an empty resource or action would
	// authorize against a permission qrdb can never match.
	for name, value := range constants {
		assert.NotEmpty(t, value, "constant %q resolves to the empty string", name)
	}

	// Constants() must return an independent map so a caller cannot poison the
	// vocabulary for a later scan.
	constants["ResourceKeys"] = "poisoned"
	assert.Equal(t, auth.ResourceKeys, Constants()["ResourceKeys"])
}

func TestSite_Pair(t *testing.T) {
	assert.Equal(t, "keys:get", Site{Resource: "keys", Action: "get"}.Pair())
	assert.Equal(t, ":", Site{}.Pair(), "a zero Site must not pretend to be a valid pair")
}

func TestErrorMessages(t *testing.T) {
	assert.Contains(t, (&ParseError{File: "a.go", Err: errors.New("boom")}).Error(), "parse a.go: boom")
	assert.Contains(t, (&RawLiteralError{Pos: "a.go:1", Literal: `"keys"`}).Error(), `raw authorization literal "keys"`)
	assert.Contains(t, (&UnknownConstantError{Pos: "a.go:1", Name: "Nope"}).Error(), `unknown pkg/auth constant "Nope"`)
	assert.Contains(t, (&VarNotFoundError{Dir: "pkg/x", Name: "table"}).Error(), `pkg/x: variable "table" not found`)
	assert.Contains(t, (&MapEntryError{Pos: "a.go:1", Msg: "boom"}).Error(), "a.go:1: boom")
	assert.Contains(t, (&LabelArgError{Pos: "a.go:1", Index: 2}).Error(), "label argument index 2")
}

// restLikeSeams mirrors pkg/api/rest's route-table shape: a bare local
// closure call (not a method selector) whose literal HTTP method and path
// arguments build the Key instead of the enclosing function's name.
var restLikeSeams = []Seam{
	{Method: "perm", Args: 4, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
}

func TestScan_BareCallMatchesLocalClosure(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"routes.go": `package rest

func Routes() {
	perm := func(method, pattern, resource, action string) {}
	perm("GET", "/backends", auth.ResourceBackends, auth.ActionList)
	perm("POST", "/keys", auth.ResourceKeys, auth.ActionCreate)
}
`,
	})

	sites, err := Scan(dir, restLikeSeams)
	require.NoError(t, err)
	require.Len(t, sites, 2)

	got := map[string]string{}
	for _, s := range sites {
		got[s.Key] = s.Pair()
	}
	assert.Equal(t, map[string]string{
		"GET /api/v1/backends": auth.ResourceBackends + ":" + auth.ActionList,
		"POST /api/v1/keys":    auth.ResourceKeys + ":" + auth.ActionCreate,
	}, got)
}

func TestScan_NonBareSeamIgnoresIdentifierCall(t *testing.T) {
	// grpcSeams' "authorize" seam does not set Bare, so a bare identifier
	// call of the same name and arity must not be treated as a gate — only
	// x.authorize(...) may. This is the regression the Bare field exists to
	// opt out of by default: without it, every package's existing seams
	// would start matching an unrelated free function of the same name.
	dir := writePkg(t, map[string]string{
		"svc.go": `package svc

func (s *Service) GetKey() error {
	return authorize(ctx, auth.ResourceKeys, auth.ActionGet, "id")
}
`,
	})

	sites, err := Scan(dir, grpcSeams)
	require.NoError(t, err, "a bare identifier call must not match a seam that does not opt into Bare")
	assert.Empty(t, sites)
}

func TestScan_LabelArgsRejectsUnresolvableArgument(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"routes.go": `package rest

func Routes() {
	perm := func(method, pattern, resource, action string) {}
	perm(methodVar, "/backends", auth.ResourceBackends, auth.ActionList)
}
`,
	})

	sites, err := Scan(dir, restLikeSeams)
	require.Error(t, err, "a label argument that is neither a literal nor a selector must be rejected")
	assert.Nil(t, sites)

	var labelErr *LabelArgError
	require.True(t, errors.As(err, &labelErr), "want *LabelArgError, got %T", err)
	assert.Equal(t, 0, labelErr.Index)
}

func TestScanMap_ResolvesPositionalMapLiteral(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"authz.go": `package mcp

var methodPermissions = map[string]permission{
	"xkms.sign": {auth.ResourceKeys, auth.ActionSign},
	"xkms.get":  {auth.ResourceKeys, auth.ActionGet},
}
`,
	})

	sites, err := ScanMap(dir, "methodPermissions")
	require.NoError(t, err)
	require.Len(t, sites, 2)

	got := map[string]string{}
	for _, s := range sites {
		got[s.Key] = s.Pair()
		assert.NotEmpty(t, s.Pos)
	}
	assert.Equal(t, map[string]string{
		"xkms.sign": auth.ResourceKeys + ":" + auth.ActionSign,
		"xkms.get":  auth.ResourceKeys + ":" + auth.ActionGet,
	}, got)
}

func TestScanMap_RejectsRawLiteralValue(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"authz.go": `package mcp

var methodPermissions = map[string]permission{
	"xkms.sign": {auth.ResourceKeys, "sign"},
}
`,
	})

	sites, err := ScanMap(dir, "methodPermissions")
	require.Error(t, err, "a raw literal action in the map must be rejected, not scanned")
	assert.Nil(t, sites)

	var rawErr *RawLiteralError
	require.True(t, errors.As(err, &rawErr), "want *RawLiteralError, got %T", err)
}

func TestScanMap_ReturnsVarNotFoundErrorWhenVariableIsAbsent(t *testing.T) {
	dir := writePkg(t, map[string]string{
		"authz.go": `package mcp

var somethingElse = 1
`,
	})

	sites, err := ScanMap(dir, "methodPermissions")
	require.Error(t, err)
	assert.Nil(t, sites)

	var notFound *VarNotFoundError
	require.True(t, errors.As(err, &notFound), "want *VarNotFoundError, got %T", err)
	assert.Equal(t, "methodPermissions", notFound.Name)
}

func TestMapSite_Pair(t *testing.T) {
	assert.Equal(t, "keys:get", MapSite{Resource: "keys", Action: "get"}.Pair())
	assert.Equal(t, ":", MapSite{}.Pair(), "a zero MapSite must not pretend to be a valid pair")
}
