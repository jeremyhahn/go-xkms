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

	"github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"

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

// NewClusterNodeURISANHook returns an OrderPreSignHook that stamps a cluster
// node's SPIFFE identity, spiffe://<trustDomain>/node/<raftAddr>, as a
// uniformResourceIdentifier SubjectAltName in the IDevID issued through the
// TCG-CSR-IDEVID (enroll-01) path. Peers trust that URI to name a cluster
// member, so it is granted only on two conditions:
//
//   - the order's permanent-identifier is exactly one of the members' Raft
//     addresses (host:port, as configured; a different port is a different
//     identifier), and
//   - enroll-01, and no other challenge, validated the order: the dial that
//     proved a genuine TPM activated a credential reached the address the
//     identifier names.
//
// members maps replica ID to Raft address; the hook copies it, so later
// changes to the map do not affect it.
//
// Otherwise the hook leaves the certificate unchanged (returns nil, nil):
// standard CSR paths carry their SANs in the CSR itself, and appending a
// second SubjectAltName extension would produce an invalid duplicate. It
// returns an error — aborting issuance — only when the URI cannot be encoded
// as an IA5String.
func NewClusterNodeURISANHook(trustDomain string, members map[uint64]string) OrderPreSignHook {
	memberAddrs := make(map[string]struct{}, len(members))
	for _, addr := range members {
		if addr != "" {
			memberAddrs[addr] = struct{}{}
		}
	}
	return func(ctx *OrderPreSignHookContext) ([]pkix.Extension, error) {
		if ctx == nil || !ctx.IsTCGCSR || ctx.Order == nil || !validatedByEnroll01Only(ctx.ValidatedChallenges) {
			return nil, nil
		}
		permanentID := orderPermanentIdentifier(ctx.Order)
		if _, member := memberAddrs[permanentID]; !member {
			return nil, nil
		}
		ext, err := buildURISANExtension(clusterenroll.NodeURI(trustDomain, permanentID))
		if err != nil {
			return nil, err
		}
		return []pkix.Extension{ext}, nil
	}
}

// validatedByEnroll01Only reports whether enroll-01 is the one attestation
// challenge that validated the order.
func validatedByEnroll01Only(validatedChallenges []string) bool {
	return len(validatedChallenges) == 1 && validatedChallenges[0] == common.ChallengeTypeEnroll01
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
