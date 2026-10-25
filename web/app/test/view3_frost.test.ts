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

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/svelte";
import userEvent from "@testing-library/user-event";
import type {
  AuthMeResponse,
  FrostGenerateKeyResponse,
  FrostListKeysResponse,
  FrostVerifyResponse,
} from "@go-xkms/sdk";

const listKeys = vi.fn<() => Promise<FrostListKeysResponse>>();
const generateKey = vi.fn<() => Promise<FrostGenerateKeyResponse>>();
const deleteKey = vi.fn<() => Promise<{ success: boolean; message: string }>>();
const verify = vi.fn<() => Promise<FrostVerifyResponse>>();
const authMe = vi.fn<() => Promise<AuthMeResponse>>();

const toasts: { kind: string; message: string }[] = [];

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    frost: { listKeys, generateKey, deleteKey, verify },
    auth: { me: authMe },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import { clearSession, loadSession } from "../src/stores/session.svelte.ts";
import FrostView from "../src/views/FrostView.svelte";

const GROUP_KEY = "aabbccddeeff00112233445566778899";

function key(over: Record<string, unknown> = {}) {
  return {
    key_id: "frost-1",
    algorithm: "ed25519",
    threshold: 2,
    total: 3,
    participant_id: 1,
    group_public_key: GROUP_KEY,
    created_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

// FrostView gates its controls on the real session store's can(); drive it
// through loadSession against a mocked /auth/me rather than duplicating the
// permission map.
async function withPermissions(perms: Record<string, boolean>): Promise<void> {
  authMe.mockResolvedValue({
    subject: "op-1",
    username: "operator",
    roles: ["admin"],
    permissions: perms,
    capabilities: { frost: true },
  } as AuthMeResponse);
  await loadSession();
}

const ALL = {
  "keys:list": true,
  "keys:create": true,
  "keys:delete": true,
  "keys:verify": true,
};

beforeEach(async () => {
  vi.clearAllMocks();
  toasts.length = 0;
  clearSession();
  listKeys.mockResolvedValue({
    keys: [],
    total: 0,
    pagination: { page: 1, page_size: 50, total: 0, has_more: false },
  });
});

describe("FrostView listing", () => {
  it("renders each threshold key with its N-of-M quorum", async () => {
    await withPermissions(ALL);
    listKeys.mockResolvedValue({
      keys: [key(), key({ key_id: "frost-2", threshold: 3, total: 5, participant_id: 2 })],
      total: 2,
      pagination: { page: 1, page_size: 50, total: 2, has_more: false },
    });

    render(FrostView);

    await waitFor(() => expect(screen.getByText("frost-1")).toBeInTheDocument());
    expect(screen.getByText("frost-2")).toBeInTheDocument();
    // The quorum is the whole point of a threshold key — assert the rendered
    // pairing, not just that two numbers appear somewhere.
    expect(screen.getByText("2-of-3")).toBeInTheDocument();
    expect(screen.getByText("3-of-5")).toBeInTheDocument();
  });

  it("truncates the group public key rather than printing 64 hex chars", async () => {
    await withPermissions(ALL);
    listKeys.mockResolvedValue({
      keys: [key()],
      total: 1,
      pagination: { page: 1, page_size: 50, total: 1, has_more: false },
    });

    render(FrostView);

    await waitFor(() => expect(screen.getByText("frost-1")).toBeInTheDocument());
    expect(screen.getByText(/aabbccddeeff…66778899/)).toBeInTheDocument();
    expect(screen.queryByText(GROUP_KEY)).toBeNull();
  });

  it("shows the empty message when no keys exist", async () => {
    await withPermissions(ALL);

    render(FrostView);

    expect(await screen.findByText("No FROST keys.")).toBeInTheDocument();
  });

  it("surfaces a listing failure instead of an empty table", async () => {
    await withPermissions(ALL);
    listKeys.mockRejectedValue(new Error("frost backend unavailable"));

    render(FrostView);

    expect(await screen.findByText("frost backend unavailable")).toBeInTheDocument();
    expect(screen.queryByText("No FROST keys.")).toBeNull();
  });
});

describe("FrostView generation", () => {
  it("sends the threshold, total, and dealer flag the server expects", async () => {
    await withPermissions(ALL);
    generateKey.mockResolvedValue({
      key_id: "frost-9",
      algorithm: "ed25519",
      threshold: 2,
      total: 3,
      group_public_key: GROUP_KEY,
      created_at: "2026-01-01T00:00:00Z",
    });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    const dialog = screen.getByText("Generate FROST key").closest(".modal-box") as HTMLElement;
    // Pasted rather than typed: the values are what is under test, and typing
    // 25 characters one keystroke at a time (a Svelte flush and a timer tick
    // each) took 0.4 s on an idle host and past 5 s on a loaded CI runner.
    await userEvent.click(dialog.querySelector('input[placeholder="Key ID (optional)"]') as HTMLElement);
    await userEvent.paste("frost-9");
    await userEvent.click(dialog.querySelector('input[placeholder^="Participants"]') as HTMLElement);
    await userEvent.paste("alice, bob , carol");
    await userEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await waitFor(() => expect(generateKey).toHaveBeenCalled());
    expect(generateKey).toHaveBeenCalledWith({
      key_id: "frost-9",
      algorithm: "ed25519",
      threshold: 2,
      total: 3,
      dealer_mode: true,
      // Free-text participants are split and trimmed; blanks dropped.
      participants: ["alice", "bob", "carol"],
    });
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("omits an empty key id and empty participants rather than sending blanks", async () => {
    await withPermissions(ALL);
    generateKey.mockResolvedValue({
      key_id: "auto",
      algorithm: "ed25519",
      threshold: 2,
      total: 3,
      group_public_key: GROUP_KEY,
      created_at: "2026-01-01T00:00:00Z",
    });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await userEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await waitFor(() => expect(generateKey).toHaveBeenCalled());
    expect(generateKey).toHaveBeenCalledWith(
      expect.objectContaining({ key_id: undefined, participants: undefined }),
    );
  });

  it("refuses a threshold larger than the participant count", async () => {
    await withPermissions(ALL);

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    const dialog = screen.getByText("Generate FROST key").closest(".modal-box") as HTMLElement;
    const total = dialog.querySelectorAll('input[type="number"]')[1] as HTMLInputElement;
    await userEvent.clear(total);
    await userEvent.type(total, "1");

    // A 2-of-1 quorum can never be satisfied; the button must not submit it.
    expect(screen.getByRole("button", { name: "Generate", hidden: true })).toBeDisabled();
    expect(generateKey).not.toHaveBeenCalled();
  });

  it("keeps the dialog open and shows the reason when generation fails", async () => {
    await withPermissions(ALL);
    generateKey.mockRejectedValue(new Error("dealer mode disabled"));

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await userEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    expect(await screen.findByText("dealer mode disabled")).toBeInTheDocument();
    expect(screen.getByText("Generate FROST key")).toBeInTheDocument();
  });
});

describe("FrostView dealer packages", () => {
  it("masks every secret share until the operator reveals it", async () => {
    await withPermissions(ALL);
    generateKey.mockResolvedValue({
      key_id: "frost-9",
      algorithm: "ed25519",
      threshold: 2,
      total: 3,
      group_public_key: GROUP_KEY,
      created_at: "2026-01-01T00:00:00Z",
      packages: [
        {
          key_id: "frost-9",
          algorithm: "ed25519",
          threshold: 2,
          total: 3,
          participant_id: 1,
          participant_name: "alice",
          secret_share: "deadbeefsecretshare1",
          group_public_key: GROUP_KEY,
          verification_shares: {},
        },
      ],
    });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await userEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await screen.findByText("Dealer packages");
    // The share is a secret: it must NOT be in the DOM before an explicit
    // reveal, and the warning must be present.
    expect(screen.queryByText("deadbeefsecretshare1")).toBeNull();
    expect(screen.getByText(/Distribute them over separate confidential channels/)).toBeInTheDocument();
    expect(screen.getByText("1 (alice)")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Reveal" }));
    expect(await screen.findByText("deadbeefsecretshare1")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Hide" }));
    await waitFor(() => expect(screen.queryByText("deadbeefsecretshare1")).toBeNull());
  });

  it("discards the packages on request so shares do not linger", async () => {
    await withPermissions(ALL);
    generateKey.mockResolvedValue({
      key_id: "frost-9",
      algorithm: "ed25519",
      threshold: 2,
      total: 3,
      group_public_key: GROUP_KEY,
      created_at: "2026-01-01T00:00:00Z",
      packages: [
        {
          key_id: "frost-9",
          algorithm: "ed25519",
          threshold: 2,
          total: 3,
          participant_id: 1,
          secret_share: "deadbeefsecretshare1",
          group_public_key: GROUP_KEY,
          verification_shares: {},
        },
      ],
    });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await userEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await screen.findByText("Dealer packages");
    await userEvent.click(screen.getByRole("button", { name: "Discard" }));

    await waitFor(() => expect(screen.queryByText("Dealer packages")).toBeNull());
  });
});

describe("FrostView verify and delete", () => {
  it("sends the key id, message, and signature to verify", async () => {
    await withPermissions(ALL);
    verify.mockResolvedValue({ valid: true, message: "signature verified" });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    const dialog = screen.getByText("Verify FROST signature").closest(".modal-box") as HTMLElement;
    await userEvent.type(dialog.querySelector('input[placeholder="Key ID"]') as HTMLElement, "frost-1");
    await userEvent.type(dialog.querySelector('input[placeholder^="Message"]') as HTMLElement, "abcd");
    await userEvent.type(dialog.querySelector('input[placeholder^="Signature"]') as HTMLElement, "ef01");
    await userEvent.click(screen.getAllByRole("button", { name: "Verify", hidden: true }).at(-1) as HTMLElement);

    await waitFor(() => expect(verify).toHaveBeenCalled());
    expect(verify).toHaveBeenCalledWith({
      key_id: "frost-1",
      message: "abcd",
      signature: "ef01",
    });
    expect(toasts.at(-1)?.kind).toBe("success");
  });

  it("reports an invalid signature as a warning, not a success", async () => {
    await withPermissions(ALL);
    verify.mockResolvedValue({ valid: false, message: "signature mismatch" });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("No FROST keys.")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    const dialog = screen.getByText("Verify FROST signature").closest(".modal-box") as HTMLElement;
    await userEvent.type(dialog.querySelector('input[placeholder="Key ID"]') as HTMLElement, "frost-1");
    await userEvent.type(dialog.querySelector('input[placeholder^="Message"]') as HTMLElement, "abcd");
    await userEvent.type(dialog.querySelector('input[placeholder^="Signature"]') as HTMLElement, "bad0");
    await userEvent.click(screen.getAllByRole("button", { name: "Verify", hidden: true }).at(-1) as HTMLElement);

    await waitFor(() => expect(toasts.at(-1)?.kind).toBe("warning"));
    expect(toasts.at(-1)?.message).toContain("INVALID");
  });

  it("deletes a key by id and reloads", async () => {
    await withPermissions(ALL);
    listKeys.mockResolvedValue({
      keys: [key()],
      total: 1,
      pagination: { page: 1, page_size: 50, total: 1, has_more: false },
    });
    deleteKey.mockResolvedValue({ success: true, message: "deleted" });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("frost-1")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(deleteKey).toHaveBeenCalledWith("frost-1"));
    expect(listKeys).toHaveBeenCalledTimes(2);
  });

  it("toasts the failure when a delete is refused", async () => {
    await withPermissions(ALL);
    listKeys.mockResolvedValue({
      keys: [key()],
      total: 1,
      pagination: { page: 1, page_size: 50, total: 1, has_more: false },
    });
    deleteKey.mockRejectedValue(new Error("key in use"));

    render(FrostView);
    await waitFor(() => expect(screen.getByText("frost-1")).toBeInTheDocument());

    await userEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(toasts.at(-1)).toEqual({ kind: "error", message: "key in use" }));
  });
});

describe("FrostView RBAC gating", () => {
  it("hides generate, verify, and delete without the matching permissions", async () => {
    await withPermissions({ "keys:list": true });
    listKeys.mockResolvedValue({
      keys: [key()],
      total: 1,
      pagination: { page: 1, page_size: 50, total: 1, has_more: false },
    });

    render(FrostView);
    await waitFor(() => expect(screen.getByText("frost-1")).toBeInTheDocument());

    expect(screen.queryByRole("button", { name: "+ Generate" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Verify" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
    // Read-only actions stay available.
    expect(screen.getByRole("button", { name: "Copy key" })).toBeInTheDocument();
  });
});
