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

// Helpers for the SSH Sign view: the key label, the request digest and the
// sign call over the SDK. The server's "digest" field holds the raw bytes to
// sign (the key's signer hashes them), so the message bytes are sent as is.

import type { SSHKey, SSHSignResponse } from "@go-xkms/sdk";
import { getSDKClient } from "$stores/sdkClient.ts";
import { isB64, textToB64 } from "./b64.ts";

/** Option label for a key: scope/owner/name (algorithm). */
export function signLabel(key: SSHKey): string {
  return `${keyId(key)} (${key.algorithm})`;
}

/** Stable identifier of a key, used as the select value. */
export function keyId(key: SSHKey): string {
  return `${key.scope}/${key.owner}/${key.name}`;
}

/**
 * The base64 digest to send for a message, or null when the message is empty
 * or, in base64 mode, not valid base64.
 */
export function signDigest(message: string, isBase64: boolean): string | null {
  if (message === "") return null;
  if (isBase64) return isB64(message) ? message : null;
  return textToB64(message);
}

/** Sign the digest with the stored key; the private key stays on the server. */
export function signWithKey(key: SSHKey, digest: string): Promise<SSHSignResponse> {
  return getSDKClient().ssh.sign(key.scope, key.owner, key.name, { digest });
}
