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

import type { UserInfo } from "@go-xkms/sdk";
import { getSDKClient } from "$stores/sdkClient.ts";

/** Fetches one user record (GET /api/v1/users/{username}) by trimmed name. */
export function loadUser(username: string): Promise<UserInfo> {
  return getSDKClient().users.get(username.trim());
}

/** Reports whether err is an API error carrying HTTP status 404. */
export function isNotFound(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { status?: unknown }).status === 404;
}
