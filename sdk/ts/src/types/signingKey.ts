// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * Repository signing-key bindings (go-xkms#1697): which key signs a
 * repository's CoRIM and images. A repository with no binding is signed by
 * its tenant's release key. Mirrors pkg/attestation/appraisal/signing_keys.go.
 */

import type { Base64, RFC3339 } from './common.js';

/** Mirrors transport.SigningKeyBinding: the key that signs a repository. */
export interface SigningKeyBinding {
  /** An OCI repository path, e.g. "acme/app". */
  repository: string;
  key_id: string;
  /** The backend holding the key; empty is the tenant's default. */
  backend?: string;
  updated_at: RFC3339;
}

/** Mirrors transport.SetSigningKeyBindingRequest. */
export interface SetSigningKeyBindingRequest {
  repository: string;
  key_id: string;
  backend?: string;
}

/** Mirrors transport.ListSigningKeyBindingsResponse. */
export interface ListSigningKeyBindingsResponse {
  bindings: SigningKeyBinding[];
}

/** Mirrors transport.SigningKeyResolution: the key that signs a repository. */
export interface SigningKeyResolution {
  repository: string;
  key_id: string;
  backend?: string;
  /** True when no binding names the repository: the key is the tenant's release key. */
  default: boolean;
}

/**
 * Mirrors transport.SignCoRIMRequest: a repository's CoRIM to sign with the
 * key the repository resolves to, draft-ietf-rats-corim-11 §4.2.
 */
export interface SignCoRIMRequest {
  repository: string;
  /** The CBOR unsigned-corim-map, tagged #6.501 or not. */
  corim: Base64;
  /** corim-meta signer-name, §4.2.3.1. */
  signer_name: string;
  /** corim-meta signer-uri, §4.2.3.1. */
  signer_uri?: string;
  /** corim-meta signature-validity, §7.3; not_before needs not_after. */
  not_before?: RFC3339;
  not_after?: RFC3339;
}

/** Mirrors transport.SignedCoRIM: the COSE_Sign1 signed-corim and its key. */
export interface SignedCoRIM {
  key: SigningKeyResolution;
  corim: Base64;
}

/**
 * Mirrors transport.SignImageRequest: an image to sign with the key its
 * repository resolves to, as a DSSE in-toto attestation pushed to its
 * registry.
 */
export interface SignImageRequest {
  /** registry/repository[:tag][@digest]; its repository picks the key. */
  reference: string;
  /** The in-toto predicate type; cosign's when absent. */
  predicate_type?: string;
  /** The statement's predicate, a JSON value; optional only for cosign's type. */
  predicate?: unknown;
  /** Credentials the service pushes the attestation with; absent sends none. */
  registry?: ImageRegistryCredentials;
}

/**
 * Mirrors transport.ImageRegistryCredentials. The password is sent only to
 * the service, which wipes it after the push.
 */
export interface ImageRegistryCredentials {
  username: string;
  password?: string;
}

/** Mirrors transport.SignedImage: the pushed attestation and its key. */
export interface SignedImage {
  key: SigningKeyResolution;
  /** The signed manifest digest. */
  digest: string;
  /** The pushed DSSE envelope JSON. */
  envelope: Base64;
  /** The PEM code-signing certificate the tenant's CA issued for the key. */
  certificate: Base64;
  /** The OCI 1.1 referrer manifest digest holding the attestation. */
  referrer: string;
  referrer_indexed: boolean;
  /** The cosign ".att" tag the attestation was added to. */
  attestation_tag: string;
}
