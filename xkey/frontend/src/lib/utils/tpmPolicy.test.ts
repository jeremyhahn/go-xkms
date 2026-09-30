import { describe, it, expect } from 'vitest';
import {
  describeBranch, draftError, draftToBranch, newBranchDraft, pcrBranch, policySummary, toggleIndex,
} from './tpmPolicy';

describe('tpmPolicy helpers', () => {
  it('converts a draft to the conditions switched on', () => {
    const draft = { ...newBranchDraft(), authValue: true, locality: true, localities: [0, 3] };
    expect(draftToBranch(draft)).toEqual({
      conditions: [
        { type: 'pcr', bank: 'sha256', pcrs: [0, 7] },
        { type: 'auth_value' },
        { type: 'locality', localities: [0, 3] },
      ],
    });
    expect(draftToBranch({ ...draft, pcr: false, locality: false })).toEqual({ conditions: [{ type: 'auth_value' }] });
  });

  it('reports why a draft cannot be sent', () => {
    expect(draftError(newBranchDraft())).toBe('');
    expect(draftError({ ...newBranchDraft(), pcr: false })).toBe('Choose at least one condition.');
    expect(draftError({ ...newBranchDraft(), pcrs: [] })).toBe('Select at least one PCR.');
    expect(draftError({ ...newBranchDraft(), locality: true, localities: [] })).toBe('Select at least one locality.');
  });

  it('toggles an index, keeping the list ascending', () => {
    expect(toggleIndex([0, 7], 3)).toEqual([0, 3, 7]);
    expect(toggleIndex([0, 3, 7], 3)).toEqual([0, 7]);
  });

  it('summarizes branches and policies', () => {
    expect(pcrBranch('sha384', [7])).toEqual({ conditions: [{ type: 'pcr', bank: 'sha384', pcrs: [7] }] });
    expect(describeBranch({ conditions: [{ type: 'locality', localities: [0] }, { type: 'auth_value' }] }))
      .toBe('locality 0 + password');
    expect(policySummary({
      name: 'boot', builtin: false, approved: true, auto_unseal: false, object_count: 0,
      branches: [pcrBranch('sha256', [0, 7]), { conditions: [{ type: 'auth_value' }] }],
    })).toBe('sha256 PCR 0, 7 or password');
    expect(policySummary({ name: 'platform', builtin: true, approved: true, auto_unseal: false, object_count: 0 }))
      .toBe('platform PCR or password');
  });
});
