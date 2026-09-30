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

import { describe, it, expect } from "vitest";
import {
  describeBranch,
  draftError,
  draftToBranch,
  newBranchDraft,
  toggleIndex,
} from "../src/lib/tpmPolicy.ts";

describe("tpmPolicy helpers", () => {
  it("converts a draft to the conditions switched on", () => {
    const draft = { ...newBranchDraft(), authValue: true, locality: true, localities: [0, 3] };
    expect(draftToBranch(draft)).toEqual({
      conditions: [
        { type: "pcr", bank: "sha256", pcrs: [0, 7] },
        { type: "auth_value" },
        { type: "locality", localities: [0, 3] },
      ],
    });
    expect(draftToBranch({ ...draft, pcr: false, locality: false })).toEqual({ conditions: [{ type: "auth_value" }] });
  });

  it("reports why a draft cannot be sent", () => {
    expect(draftError(newBranchDraft())).toBeNull();
    expect(draftError({ ...newBranchDraft(), pcr: false })).toBe("Choose at least one condition");
    expect(draftError({ ...newBranchDraft(), pcrs: [] })).toBe("Select at least one PCR");
    expect(draftError({ ...newBranchDraft(), locality: true, localities: [] })).toBe("Select at least one locality");
  });

  it("toggles an index in or out, keeping the list ascending", () => {
    expect(toggleIndex([0, 7], 3)).toEqual([0, 3, 7]);
    expect(toggleIndex([0, 3, 7], 3)).toEqual([0, 7]);
  });

  it("summarizes a stored branch", () => {
    expect(
      describeBranch({
        conditions: [{ type: "locality", localities: [0] }, { type: "pcr", bank: "sha384", pcrs: [7] }, { type: "auth_value" }],
      }),
    ).toBe("locality 0 + PCR sha384 [7] + password");
  });
});
