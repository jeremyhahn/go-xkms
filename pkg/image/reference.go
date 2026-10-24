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

package image

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

const (
	// DefaultRegistry is the registry of a reference that names none.
	DefaultRegistry = "docker.io"

	// DefaultTag is the tag of a reference that names neither a tag nor a
	// digest.
	DefaultTag = "latest"

	// officialRepositoryPrefix is the Docker Hub namespace of single-name
	// images such as "nginx".
	officialRepositoryPrefix = "library/"

	// attestationTagSuffix ends the tag cosign stores attestations under.
	attestationTagSuffix = ".att"

	// maxTagLength is the longest tag the OCI distribution specification
	// allows.
	maxTagLength = 128
)

var (
	// registryRegex matches a registry host with an optional port.
	registryRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]+)?$`)

	// tagRegex is the OCI distribution specification's tag grammar, less
	// the length limit.
	tagRegex = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)
)

// Reference is a parsed container image reference.
type Reference struct {
	// Registry is the registry host, with an optional port.
	Registry string

	// Repository is the repository path within the registry.
	Repository string

	// Tag is the image tag; empty when the reference names only a digest.
	Tag string

	// Digest is the manifest digest, "sha256:<hex>" or "sha512:<hex>".
	Digest string
}

// ParseReference parses an image reference of the form
// [registry/]repository[:tag][@digest]. A reference without a registry
// names Docker Hub, a single-name Docker Hub repository is in "library/",
// and a reference with neither tag nor digest gets DefaultTag.
func ParseReference(ref string) (*Reference, error) {
	name := strings.TrimSpace(ref)
	if name == "" {
		return nil, &errs.Detail{Err: ErrInvalidReference, Detail: "empty reference"}
	}

	result := &Reference{}
	if at := strings.LastIndex(name, "@"); at != -1 {
		result.Digest = name[at+1:]
		name = name[:at]
		if !validDigest(result.Digest) {
			return nil, &errs.Detail{Err: ErrInvalidDigest, Detail: strconv.Quote(result.Digest)}
		}
	}
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		result.Tag = name[colon+1:]
		name = name[:colon]
		if !validTag(result.Tag) {
			return nil, &errs.Detail{Err: ErrInvalidReference, Detail: "invalid tag " + strconv.Quote(result.Tag)}
		}
	}
	if result.Tag == "" && result.Digest == "" {
		result.Tag = DefaultTag
	}

	result.Registry, result.Repository = splitName(name)
	if err := result.Validate(); err != nil {
		return nil, err
	}
	return result, nil
}

// splitName splits name into its registry and repository. The first path
// component is the registry when it has a dot or a port or is "localhost".
func splitName(name string) (string, string) {
	registry, repository := DefaultRegistry, name
	if first, rest, found := strings.Cut(name, "/"); found && isRegistry(first) {
		registry, repository = first, rest
	}
	if registry == DefaultRegistry && !strings.Contains(repository, "/") {
		repository = officialRepositoryPrefix + repository
	}
	return registry, repository
}

// isRegistry reports whether a reference's first path component names a
// registry rather than a repository namespace.
func isRegistry(component string) bool {
	return strings.ContainsAny(component, ".:") || component == "localhost"
}

// validTag reports whether tag is a well-formed OCI tag.
func validTag(tag string) bool {
	return len(tag) <= maxTagLength && tagRegex.MatchString(tag)
}

// Validate checks every field of r against the OCI grammar. A reference
// must name a tag, a digest or both.
func (r *Reference) Validate() error {
	if !registryRegex.MatchString(r.Registry) {
		return &errs.Detail{Err: ErrInvalidReference, Detail: "invalid registry " + strconv.Quote(r.Registry)}
	}
	if !validation.ValidOCIRepository(r.Repository) {
		return &errs.Detail{Err: ErrInvalidReference, Detail: "invalid repository " + strconv.Quote(r.Repository)}
	}
	if r.Tag == "" && r.Digest == "" {
		return &errs.Detail{Err: ErrInvalidReference, Detail: "no tag or digest"}
	}
	if r.Tag != "" && !validTag(r.Tag) {
		return &errs.Detail{Err: ErrInvalidReference, Detail: "invalid tag " + strconv.Quote(r.Tag)}
	}
	if r.Digest != "" && !validDigest(r.Digest) {
		return &errs.Detail{Err: ErrInvalidDigest, Detail: strconv.Quote(r.Digest)}
	}
	return nil
}

// Name returns the registry and repository, as in "ghcr.io/org/app".
func (r *Reference) Name() string {
	return r.Registry + "/" + r.Repository
}

// String returns the reference as name[:tag][@digest].
func (r *Reference) String() string {
	var sb strings.Builder
	sb.WriteString(r.Name())
	if r.Tag != "" {
		sb.WriteString(":")
		sb.WriteString(r.Tag)
	}
	if r.Digest != "" {
		sb.WriteString("@")
		sb.WriteString(r.Digest)
	}
	return sb.String()
}

// WithDigest returns a reference to the same repository that names digest
// and no tag.
func (r *Reference) WithDigest(digest string) (*Reference, error) {
	if !validDigest(digest) {
		return nil, &errs.Detail{Err: ErrInvalidDigest, Detail: strconv.Quote(digest)}
	}
	return &Reference{Registry: r.Registry, Repository: r.Repository, Digest: digest}, nil
}

// AttestationTag returns the tag cosign stores the image's attestations
// under: the digest with its ":" replaced by "-", plus ".att", as in
// "sha256-<hex>.att". Only a sha256 digest makes a valid tag.
func (r *Reference) AttestationTag() (string, error) {
	if r.Digest == "" {
		return "", ErrDigestRequired
	}
	algorithm, _, ok := splitDigest(r.Digest)
	if !ok {
		return "", &errs.Detail{Err: ErrInvalidDigest, Detail: strconv.Quote(r.Digest)}
	}
	// Any longer digest makes a tag longer than an OCI tag may be.
	if algorithm != "sha256" {
		return "", &errs.Detail{Err: ErrInvalidDigest, Detail: "the attestation tag needs a sha256 digest"}
	}
	return strings.Replace(r.Digest, ":", "-", 1) + attestationTagSuffix, nil
}

// manifestReference returns what the registry addresses r's manifest by:
// the digest when r has one, otherwise the tag.
func (r *Reference) manifestReference() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}
