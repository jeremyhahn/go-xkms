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

package handlers

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// oidExtensionSubjectAltName is the SubjectAltName extension OID (2.5.29.17).
var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// sanGeneralNameURITag is the context-specific tag of a
// uniformResourceIdentifier GeneralName inside a SubjectAltName extension
// (RFC 5280 section 4.2.1.6).
const sanGeneralNameURITag = 6

// ErrURISANNotIA5 is returned when a pre-sign hook URI contains non-ASCII
// characters and therefore cannot be encoded as an IA5String GeneralName.
type ErrURISANNotIA5 struct {
	URI string
}

// Error implements the error interface.
func (e ErrURISANNotIA5) Error() string {
	return "acme: uri san is not an IA5 (ASCII) string: " + e.URI
}

// NewPermanentIdentifierURISANHook returns an OrderPreSignHook that embeds a
// uniformResourceIdentifier SubjectAltName extension in certificates issued
// through the TCG-CSR-IDEVID (enroll-01) path. The URI is derived from the
// ACME order's permanent-identifier value by the caller-supplied uriFor
// function, keeping identity policy at the composition root — for example, a
// cluster server maps a Raft node's advertised address to its SPIFFE node URI
// (spiffe://<trust-domain>/node/<raftAddr>) and returns "" for identifiers
// that are not cluster members.
//
// The hook leaves the certificate unchanged (returns nil, nil) when:
//   - the order is not a TCG-CSR-IDEVID enrollment (standard CSR paths carry
//     their SANs in the CSR itself; appending a second SubjectAltName
//     extension would produce an invalid duplicate),
//   - the order carries no permanent-identifier, or
//   - uriFor returns "" (the identifier is outside the caller's policy).
//
// It returns an error — aborting issuance — only when the URI cannot be
// encoded as an IA5String.
func NewPermanentIdentifierURISANHook(uriFor func(permanentIdentifier string) string) OrderPreSignHook {
	return func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		if ctx == nil || !ctx.IsTCGCSR || ctx.Order == nil {
			return nil, nil
		}
		permanentID := orderPermanentIdentifier(ctx.Order)
		if permanentID == "" {
			return nil, nil
		}
		uri := uriFor(permanentID)
		if uri == "" {
			return nil, nil
		}
		ext, err := buildURISANExtension(uri)
		if err != nil {
			return nil, err
		}
		return []pkix.Extension{ext}, nil
	}
}

// orderPermanentIdentifier returns the order's first permanent-identifier
// value, or "" when the order carries none.
func orderPermanentIdentifier(order *entities.ACMEOrder) string {
	for _, identifier := range order.Identifiers {
		if identifier.Type == common.AuthzTypePermanentIdentifier {
			return identifier.Value
		}
	}
	return ""
}

// buildURISANExtension marshals a SubjectAltName extension containing a single
// uniformResourceIdentifier GeneralName.
func buildURISANExtension(uri string) (pkix.Extension, error) {
	for i := 0; i < len(uri); i++ {
		if uri[i] > 127 {
			return pkix.Extension{}, ErrURISANNotIA5{URI: uri}
		}
	}

	uriName, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   sanGeneralNameURITag,
		Bytes: []byte(uri),
	})
	if err != nil {
		return pkix.Extension{}, err
	}

	generalNames, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      uriName,
	})
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: false,
		Value:    generalNames,
	}, nil
}
