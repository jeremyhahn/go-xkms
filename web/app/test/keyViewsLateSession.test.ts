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

// A key view can mount before /auth/me resolves (a direct route on a fresh
// load). Its permission gates must follow the session when it arrives, not
// keep the snapshot taken at mount.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

const me = vi.fn();
vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { me } }),
  resetSDKClient: () => {},
}));

import { clearSession, loadSession } from "../src/stores/session.svelte.ts";
import KeyBatchView from "../src/views/KeyBatchView.svelte";
import KeyHmacView from "../src/views/KeyHmacView.svelte";
import KeyLifecycleView from "../src/views/KeyLifecycleView.svelte";

/** Mounts with the session pending; returns a resolver for /auth/me. */
function pendingSession(): (perms: string[]) => Promise<void> {
  let resolve: (v: unknown) => void = () => {};
  me.mockReturnValue(new Promise((r) => (resolve = r)));
  const loading = loadSession();
  return async (perms: string[]) => {
    resolve({ subject: "op", roles: [], permissions: Object.fromEntries(perms.map((p) => [p, true])), capabilities: {} });
    await loading;
    await tick();
  };
}

describe("key views follow permissions that arrive after mount", () => {
  beforeEach(() => {
    cleanup();
    clearSession();
    me.mockReset();
  });

  it("Batch Crypto: a decrypt-only session moves the view to decrypt and disables Encrypt", async () => {
    const arrive = pendingSession();
    render(KeyBatchView);
    await arrive(["keys:decrypt"]);
    expect(screen.getByRole("button", { name: "Decrypt" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Encrypt" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Decrypt" })).toBeEnabled();
  });

  it("HMAC: a verify-only session disables Compute", async () => {
    const arrive = pendingSession();
    render(KeyHmacView);
    await arrive(["keys:verify"]);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    await fireEvent.input(screen.getByLabelText("Data"), { target: { value: "hello" } });
    await fireEvent.input(screen.getByLabelText("MAC"), { target: { value: "abcd" } });
    expect(screen.getByRole("button", { name: "Compute" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Verify" })).toBeEnabled();
  });

  it("Key Lifecycle: a delete-only session disables Enable and Disable", async () => {
    const arrive = pendingSession();
    render(KeyLifecycleView);
    await arrive(["keys:delete"]);
    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    await fireEvent.input(screen.getByLabelText("Confirm key ID"), { target: { value: "k1" } });
    expect(screen.getByRole("button", { name: "Enable" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Disable" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeEnabled();
  });
});
