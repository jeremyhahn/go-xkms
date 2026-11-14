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

// Key metadata over GET and PUT /api/v1/keys/{id}/metadata. sdk/ts has no
// method for these routes, so the console calls them through the client's
// HTTP core. The wire types mirror pkg/api/transport/types_keymgmt.go.

import { getSDKClient } from "$stores/sdkClient.ts";

export type KeyStatus = "enabled" | "disabled" | "pending_deletion" | "deleted" | "rotating" | "compromised";

export interface KeyRotationPolicy {
  enabled: boolean;
  interval_seconds: number;
  next_rotation?: number;
  retain_versions?: number;
  auto_rotate?: boolean;
}

export interface KeyMetadata {
  key_id: string;
  name?: string;
  description?: string;
  algorithm?: string;
  status: KeyStatus;
  usage?: string[];
  version: number;
  exportable: boolean;
  deletion_protection: boolean;
  /** Unix seconds. */
  created_at?: number;
  /** Unix seconds. */
  updated_at?: number;
  /** Unix seconds. */
  last_used_at?: number;
  rotation_policy?: KeyRotationPolicy;
  tags?: Record<string, string>;
  owner?: string;
}

export interface KeyMetadataResponse {
  metadata: KeyMetadata;
  timestamp: number;
}

/** The changeable part of a PUT body: an empty name or description leaves it unchanged. */
export interface KeyMetadataChanges {
  name?: string;
  description?: string;
  tags?: Record<string, string>;
  remove_tags?: string[];
}

export interface UpdateKeyMetadataRequest extends KeyMetadataChanges {
  backend: string;
  key_id: string;
}

/** The editable fields as the view holds them. */
export interface EditableMetadata {
  name: string;
  description: string;
  tags: Record<string, string>;
}

function path(id: string): string {
  return `/api/v1/keys/${encodeURIComponent(id)}/metadata`;
}

export async function getKeyMetadata(id: string, backend: string): Promise<KeyMetadata> {
  const res = await getSDKClient().http.request<KeyMetadataResponse>("GET", path(id), { query: { backend } });
  return res.metadata;
}

export async function updateKeyMetadata(id: string, backend: string, changes: KeyMetadataChanges): Promise<KeyMetadata> {
  const body: UpdateKeyMetadataRequest = { backend, key_id: id, ...changes };
  const res = await getSDKClient().http.request<KeyMetadataResponse>("PUT", path(id), { body });
  return res.metadata;
}

/**
 * diffMetadata builds the PUT changes from the loaded and the edited fields:
 * a changed name or description, added or changed tags in `tags`, deleted
 * tags in `remove_tags`. It returns an empty object when nothing changed.
 */
export function diffMetadata(before: EditableMetadata, after: EditableMetadata): KeyMetadataChanges {
  const changes: KeyMetadataChanges = {};
  // The server ignores an empty name or description, so an emptied field is no change.
  if (after.name !== "" && after.name !== before.name) changes.name = after.name;
  if (after.description !== "" && after.description !== before.description) changes.description = after.description;
  const tags: Record<string, string> = {};
  for (const [k, v] of Object.entries(after.tags)) {
    if (before.tags[k] !== v) tags[k] = v;
  }
  if (Object.keys(tags).length > 0) changes.tags = tags;
  const removed = Object.keys(before.tags).filter((k) => !(k in after.tags));
  if (removed.length > 0) changes.remove_tags = removed;
  return changes;
}
