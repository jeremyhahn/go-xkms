// Key rotation policy: typed calls over the SDK's HTTP core for
// GET, PUT and DELETE /api/v1/keys/{id}/rotation-policy
// (pkg/api/rest/handlers_keymgmt.go). sdk/ts has no method for these yet.
import { getSDKClient } from "$stores/sdkClient.ts";

/** Wire shape of transport.RotationPolicy (pkg/api/transport/types_keymgmt.go). */
export interface RotationPolicy {
  enabled: boolean;
  interval_seconds: number;
  /** Unix seconds; computed by the server, never sent. */
  next_rotation?: number;
  retain_versions?: number;
  auto_rotate?: boolean;
}

export interface SetKeyRotationPolicyRequest {
  backend: string;
  key_id: string;
  policy: RotationPolicy;
}

export interface KeyRotationPolicyResponse {
  key_id: string;
  policy?: RotationPolicy;
  timestamp: string;
}

export interface KeyManagementResponse {
  key_id: string;
  timestamp: string;
  [field: string]: unknown;
}

export type IntervalUnit = "hours" | "days";

const UNIT_SECONDS: Record<IntervalUnit, number> = { hours: 3600, days: 86400 };

function policyPath(id: string): string {
  return `/api/v1/keys/${encodeURIComponent(id)}/rotation-policy`;
}

export function getRotationPolicy(id: string, backend: string): Promise<KeyRotationPolicyResponse> {
  return getSDKClient().http.request<KeyRotationPolicyResponse>("GET", policyPath(id), { query: { backend } });
}

export function setRotationPolicy(id: string, backend: string, policy: RotationPolicy): Promise<KeyRotationPolicyResponse> {
  const body: SetKeyRotationPolicyRequest = { backend, key_id: id, policy };
  return getSDKClient().http.request<KeyRotationPolicyResponse>("PUT", policyPath(id), { body });
}

export function deleteRotationPolicy(id: string, backend: string): Promise<KeyManagementResponse> {
  return getSDKClient().http.request<KeyManagementResponse>("DELETE", policyPath(id), { query: { backend } });
}

/** Converts an interval in hours or days to seconds. */
export function toSeconds(n: number, unit: IntervalUnit): number {
  return n * UNIT_SECONDS[unit];
}

/** Splits seconds into the largest whole unit: days when exact, else hours. */
export function fromSeconds(s: number): { value: number; unit: IntervalUnit } {
  if (s > 0 && s % UNIT_SECONDS.days === 0) return { value: s / UNIT_SECONDS.days, unit: "days" };
  return { value: s / UNIT_SECONDS.hours, unit: "hours" };
}

/** Human form of an interval, e.g. "30 days" or "12 hours". */
export function formatInterval(s: number): string {
  const { value, unit } = fromSeconds(s);
  return `${value} ${value === 1 ? unit.slice(0, -1) : unit}`;
}
