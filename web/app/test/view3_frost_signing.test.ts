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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type {
  FrostGenerateNoncesResponse,
  FrostSignRoundRequest,
  FrostSignRoundResponse,
  FrostAggregateRequest,
  FrostAggregateResponse,
} from "@go-xkms/sdk";

const generateNonces = vi.fn<(id: string) => Promise<FrostGenerateNoncesResponse>>();
const signRound = vi.fn<(id: string, req: FrostSignRoundRequest) => Promise<FrostSignRoundResponse>>();
const aggregate = vi.fn<(req: FrostAggregateRequest) => Promise<FrostAggregateResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ frost: { generateNonces, signRound, aggregate } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import FrostSigningView from "../src/views/FrostSigningView.svelte";

const HIDING_NONCE = "aa11secretnoncehiding";
const BINDING_NONCE = "bb22secretnoncebinding";

const nonces: FrostGenerateNoncesResponse = {
  participant_id: 2,
  session_id: "sess-42",
  hiding_nonce: HIDING_NONCE,
  binding_nonce: BINDING_NONCE,
  hiding_commitment: "c0ffee01",
  binding_commitment: "c0ffee02",
};
const own = { participant_id: 2, hiding_commitment: "c0ffee01", binding_commitment: "c0ffee02" };
const other = { participant_id: 1, hiding_commitment: "d00d01", binding_commitment: "d00d02" };
const otherShare = { participant_id: 1, session_id: "sess-42", share: "5ha2e1" };

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  // Secret hygiene: no toast in any test may carry a nonce value.
  for (const t of toasts) {
    expect(t.message).not.toContain(HIDING_NONCE);
    expect(t.message).not.toContain(BINDING_NONCE);
  }
});

function assertNoNonces(): void {
  const text = document.body.innerHTML;
  expect(text).not.toContain(HIDING_NONCE);
  expect(text).not.toContain(BINDING_NONCE);
}

async function genNonces(): Promise<void> {
  generateNonces.mockResolvedValue(nonces);
  render(FrostSigningView);
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "fk-1" } });
  await fireEvent.input(screen.getByLabelText("Message"), { target: { value: "hi" } });
  await fireEvent.click(screen.getByRole("button", { name: "Generate nonces" }));
  await waitFor(() => expect(generateNonces).toHaveBeenCalledOnce());
  await screen.findByText("sess-42");
}

async function sign(): Promise<void> {
  signRound.mockResolvedValue({ participant_id: 2, session_id: "sess-42", signature_share: "0wn5hare" });
  await fireEvent.input(screen.getByLabelText("Other commitments (JSON)"), {
    target: { value: JSON.stringify([other]) },
  });
  await fireEvent.click(screen.getByRole("button", { name: "Sign" }));
  await waitFor(() => expect(signRound).toHaveBeenCalledOnce());
  await screen.findByText(/0wn5hare/);
}

describe("FrostSigningView", () => {
  it("generates nonces and shows this node's commitment but no nonce", async () => {
    await genNonces();

    expect(generateNonces).toHaveBeenCalledWith("fk-1");
    expect(screen.getByText("Participant 2")).toBeInTheDocument();
    expect(document.body.textContent).toContain("c0ffee01");
    expect(document.body.textContent).toContain("c0ffee02");
    assertNoNonces();
  });

  it("signs a round with the hex message, both nonces and all commitments, then clears the nonces", async () => {
    await genNonces();
    await sign();

    const [id, req] = signRound.mock.calls[0]!;
    expect(id).toBe("fk-1");
    expect(req).toEqual({
      key_id: "fk-1",
      message: "6869",
      session_id: "sess-42",
      hiding_nonce: HIDING_NONCE,
      binding_nonce: BINDING_NONCE,
      hiding_commitment: "c0ffee01",
      binding_commitment: "c0ffee02",
      commitments: [other, own],
    });
    assertNoNonces();
    // The nonces are single-use: a second Sign needs new nonces.
    expect(screen.getByRole("button", { name: "Sign" })).toBeDisabled();
  });

  it("aggregates the shares with this node's share and shows the verified signature", async () => {
    aggregate.mockResolvedValue({ signature: "516a7e", verified: true });
    await genNonces();
    await sign();

    await fireEvent.input(screen.getByLabelText("Other shares (JSON)"), {
      target: { value: JSON.stringify([otherShare]) },
    });
    expect(screen.getByLabelText("Verify signature")).toBeChecked();
    await fireEvent.click(screen.getByRole("button", { name: "Aggregate" }));

    await waitFor(() => expect(aggregate).toHaveBeenCalledOnce());
    expect(aggregate.mock.calls[0]![0]).toEqual({
      key_id: "fk-1",
      message: "6869",
      commitments: [other, own],
      shares: [otherShare, { participant_id: 2, session_id: "sess-42", share: "0wn5hare" }],
      verify: true,
    });
    expect(await screen.findByText("516a7e")).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
    assertNoNonces();
  });

  it("rejects invalid commitments JSON inline without a call", async () => {
    await genNonces();
    await fireEvent.input(screen.getByLabelText("Other commitments (JSON)"), { target: { value: "{not json" } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    expect(await screen.findByText("Commitments must be a JSON array.")).toBeInTheDocument();
    expect(signRound).not.toHaveBeenCalled();
  });

  it("rejects invalid shares JSON inline without a call", async () => {
    await genNonces();
    await sign();
    await fireEvent.input(screen.getByLabelText("Other shares (JSON)"), { target: { value: "[oops" } });
    await fireEvent.click(screen.getByRole("button", { name: "Aggregate" }));

    expect(await screen.findByText("Shares must be a JSON array.")).toBeInTheDocument();
    expect(aggregate).not.toHaveBeenCalled();
  });

  it("shows a nonce generation failure in an alert", async () => {
    generateNonces.mockRejectedValue(new Error("frost not available"));
    render(FrostSigningView);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "fk-1" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate nonces" }));

    expect(await screen.findByText("frost not available")).toBeInTheDocument();
  });

  it("clears the nonces after a failed sign round and shows the error", async () => {
    await genNonces();
    signRound.mockRejectedValue(new Error("bad commitments"));
    await fireEvent.input(screen.getByLabelText("Other commitments (JSON)"), {
      target: { value: JSON.stringify([other]) },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    expect(await screen.findByText("bad commitments")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign" })).toBeDisabled();
    assertNoNonces();
  });
});
