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

/**
 * Helpers for composite TPM policies: the editable draft of one branch in
 * the create dialog's advanced mode, its conversion to the API form, and
 * readable summaries of stored policies for tables and pickers.
 */

import type { TPMPolicyBranch, TPMPolicyCondition, TPMPolicyInfo } from '$lib/api/backend';

/** PCR banks a pcr condition may select. */
export const BANKS = ['sha256', 'sha384', 'sha512', 'sha1'];

/** PCR indices a pcr condition may select. */
export const PCR_INDICES = Array.from({ length: 24 }, (_, i) => i);

/** TPM localities a locality condition may allow. */
export const LOCALITIES = [0, 1, 2, 3, 4];

/** The editable form of one branch: each condition switched on or off. */
export interface BranchDraft {
  pcr: boolean;
  bank: string;
  pcrs: number[];
  authValue: boolean;
  locality: boolean;
  localities: number[];
}

/** Returns a new draft: a pcr condition over PCRs 0 and 7 of sha256. */
export function newBranchDraft(): BranchDraft {
  return { pcr: true, bank: 'sha256', pcrs: [0, 7], authValue: false, locality: false, localities: [0] };
}

/** Returns values with value added or removed, ascending. */
export function toggleIndex(values: number[], value: number): number[] {
  return values.includes(value) ? values.filter((v) => v !== value) : [...values, value].sort((a, b) => a - b);
}

/**
 * Returns why draft cannot be sent, or '': a branch needs at least one
 * condition, a pcr condition at least one PCR, a locality condition at least
 * one locality.
 */
export function draftError(draft: BranchDraft): string {
  if (!draft.pcr && !draft.authValue && !draft.locality) {
    return 'Choose at least one condition.';
  }
  if (draft.pcr && draft.pcrs.length === 0) {
    return 'Select at least one PCR.';
  }
  if (draft.locality && draft.localities.length === 0) {
    return 'Select at least one locality.';
  }
  return '';
}

/** Converts a draft to the API form, its conditions in the order shown. */
export function draftToBranch(draft: BranchDraft): TPMPolicyBranch {
  const conditions: TPMPolicyCondition[] = [];
  if (draft.pcr) conditions.push({ type: 'pcr', bank: draft.bank, pcrs: draft.pcrs });
  if (draft.authValue) conditions.push({ type: 'auth_value' });
  if (draft.locality) conditions.push({ type: 'locality', localities: draft.localities });
  return { conditions };
}

/** Returns the one branch approving the PCRs of bank. */
export function pcrBranch(bank: string, pcrs: number[]): TPMPolicyBranch {
  return { conditions: [{ type: 'pcr', bank, pcrs }] };
}

/** Summarizes one condition, e.g. "sha256 PCR 0, 7". */
function describeCondition(c: TPMPolicyCondition): string {
  switch (c.type) {
    case 'pcr':
      return `${c.bank ?? ''} PCR ${(c.pcrs ?? []).join(', ')}`;
    case 'locality':
      return `locality ${(c.localities ?? []).join(', ')}`;
    default:
      return 'password';
  }
}

/** Summarizes a branch: its conditions joined by " + ". */
export function describeBranch(branch: TPMPolicyBranch): string {
  return branch.conditions.map(describeCondition).join(' + ');
}

/** Summarizes a policy: its branches joined by " or ". */
export function policySummary(policy: TPMPolicyInfo): string {
  if (policy.builtin) {
    return 'platform PCR or password';
  }
  return (policy.branches ?? []).map(describeBranch).join(' or ');
}
