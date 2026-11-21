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

const request = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ http: { request } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

// A caller holding every permission of the page's routes; per-operation
// gating is tested in view3_key_policy_permissions.test.ts.
vi.mock("../src/stores/session.svelte.ts", async (orig) => ({
  ...(await orig<typeof import("../src/stores/session.svelte.ts")>()),
  can: () => true,
}));

import KeyAccessPolicyView from "../src/views/KeyAccessPolicyView.svelte";

const PATH = "/api/v1/keys/k1/policy";
// 2100-01-01T00:00:00Z: always in the future for these tests.
const FUTURE = 4102444800;

let confirmSpy: { mockRestore(): void } | null = null;

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  confirmSpy?.mockRestore();
  confirmSpy = null;
});

async function selectKey(): Promise<void> {
  await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k1" } });
  await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
}

async function addPrincipal(kind: "Allowed" | "Denied", name: string): Promise<void> {
  await fireEvent.input(screen.getByPlaceholderText(`${kind} principal`), { target: { value: name } });
  await fireEvent.click(screen.getByRole("button", { name: `Add ${kind.toLowerCase()}` }));
}

describe("KeyAccessPolicyView", () => {
  it("keeps the newly selected key's form when an earlier delete completes", async () => {
    let finish: (v: unknown) => void = () => {};
    request.mockReturnValue(new Promise((resolve) => (finish = resolve)));
    confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove policy" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith("DELETE", PATH, expect.anything()));

    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k2" } });
    await fireEvent.click(screen.getByLabelText("verify"));
    await addPrincipal("Allowed", "svc-k2");

    finish({ timestamp: 1 });
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
    expect(screen.getByLabelText("verify")).toBeChecked();
    expect(screen.getByText("svc-k2")).toBeInTheDocument();
    expect(screen.queryByText("No access policy set (default applies)")).toBeNull();
  });

  it("loads a key's policy into the form and shows its version", async () => {
    request.mockResolvedValue({
      policy: {
        key_id: "k1",
        version: 2,
        allowed_operations: ["sign"],
        allowed_principals: ["svc-a"],
        denied_principals: ["svc-b"],
        expires_at: FUTURE,
        require_mfa: true,
      },
      timestamp: 1,
    });

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    await waitFor(() => expect(request).toHaveBeenCalledWith("GET", PATH, { query: { backend: "software" } }));
    expect(await screen.findByText("Version 2")).toBeInTheDocument();
    expect(screen.getByLabelText("sign")).toBeChecked();
    expect(screen.getByLabelText("verify")).not.toBeChecked();
    expect(screen.getByText("svc-a")).toBeInTheDocument();
    expect(screen.getByText("svc-b")).toBeInTheDocument();
    expect(screen.getByLabelText("Expiry")).toHaveValue("2100-01-01");
    expect(screen.getByLabelText("Require MFA")).toBeChecked();
    expect(screen.getByLabelText("Rotation required")).not.toBeChecked();
  });

  it("says the default applies when the key has no policy", async () => {
    request.mockResolvedValue({ timestamp: 1 });

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    expect(await screen.findByText("No access policy set (default applies)")).toBeInTheDocument();
  });

  it("saves the policy with empty fields omitted", async () => {
    request.mockResolvedValue({ key_id: "k1", policy_version: 3, timestamp: 1 });

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByLabelText("sign"));
    await fireEvent.click(screen.getByLabelText("verify"));
    await addPrincipal("Allowed", "svc-a");
    await addPrincipal("Denied", "svc-b");
    await fireEvent.input(screen.getByLabelText("Max usage count"), { target: { value: "500" } });
    // SetKeyPolicy refuses require_mfa (UnenforceablePolicyError), so the
    // control is disabled and a saved policy never carries it.
    expect(screen.getByLabelText("Require MFA")).toBeDisabled();
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("PUT", PATH, {
      body: {
        backend: "software",
        key_id: "k1",
        policy: {
          allowed_operations: ["sign", "verify"],
          allowed_principals: ["svc-a"],
          denied_principals: ["svc-b"],
          max_usage_count: 500,
        },
      },
    });
    expect(await screen.findByText("Version 3")).toBeInTheDocument();
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("removes a principal from a list before saving", async () => {
    request.mockResolvedValue({ key_id: "k1", policy_version: 1, timestamp: 1 });

    render(KeyAccessPolicyView);
    await selectKey();
    await addPrincipal("Allowed", "svc-a");
    await addPrincipal("Allowed", "svc-c");
    await fireEvent.click(screen.getByRole("button", { name: "Remove svc-c" }));
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request.mock.calls[0]![2].body.policy).toEqual({ allowed_principals: ["svc-a"] });
  });

  it("removes the policy after a confirm", async () => {
    confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    request.mockResolvedValue({ key_id: "k1", timestamp: 1 });

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove policy" }));

    await waitFor(() => expect(request).toHaveBeenCalledWith("DELETE", PATH, { query: { backend: "software" } }));
    expect(await screen.findByText("No access policy set (default applies)")).toBeInTheDocument();
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });

  it("sends nothing when the remove confirm is declined", async () => {
    confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove policy" }));

    expect(confirmSpy).toHaveBeenCalledOnce();
    expect(request).not.toHaveBeenCalled();
  });

  it("keeps Load, Save and Remove disabled until key ID and backend are set", async () => {
    render(KeyAccessPolicyView);
    const buttons = ["Load", "Save", "Remove policy"].map((name) => screen.getByRole("button", { name }));
    for (const b of buttons) expect(b).toBeDisabled();

    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k1" } });
    for (const b of buttons) expect(b).toBeDisabled();

    await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "software" } });
    for (const b of buttons) expect(b).toBeEnabled();
  });

  it("rejects a principal that is both allowed and denied", async () => {
    render(KeyAccessPolicyView);
    await selectKey();
    await addPrincipal("Allowed", "svc-a");
    await addPrincipal("Denied", "svc-a");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText(/both allowed and denied: svc-a/)).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it.each(["-1", "2.5"])("rejects the usage cap %s", async (value) => {
    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.input(screen.getByLabelText("Max usage count"), { target: { value } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("Max usage count must be a whole number, 0 or more.")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects an expiry in the past", async () => {
    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.input(screen.getByLabelText("Expiry"), { target: { value: "2000-01-01" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("Expiry must be in the future.")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it.each([
    ["a future afternoon", FUTURE + 15 * 3600 + 37 * 60 + 11],
    ["later today", Math.floor(Date.now() / 1000) + 60],
  ])("keeps a loaded non-midnight expiry (%s) when another field is edited", async (_label, at) => {
    request.mockImplementation((method: string) =>
      Promise.resolve(
        method === "GET"
          ? { policy: { key_id: "k1", version: 2, expires_at: at }, timestamp: 1 }
          : { key_id: "k1", policy_version: 3, timestamp: 1 },
      ),
    );

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    expect(await screen.findByText("Version 2")).toBeInTheDocument();
    await addPrincipal("Allowed", "svc-a");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request.mock.calls[1]![2].body.policy).toEqual({ allowed_principals: ["svc-a"], expires_at: at });
  });

  it("shows a load failure in an error alert", async () => {
    request.mockRejectedValue(new Error("key not found"));

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    expect(await screen.findByText("key not found")).toBeInTheDocument();
  });

  it("shows a save failure in an error alert", async () => {
    request.mockRejectedValue(new Error("permission denied"));

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByLabelText("sign"));
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    expect(toasts).toHaveLength(0);
  });
});

describe("KeyAccessPolicyView target binding", () => {
  it("never saves a policy loaded for one key to another key", async () => {
    let resolveGet: (v: unknown) => void = () => {};
    request.mockImplementation((method: string) => {
      if (method === "GET") return new Promise((r) => (resolveGet = r));
      return Promise.resolve({ key_id: "k2", policy_version: 1, timestamp: 1 });
    });

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith("GET", PATH, { query: { backend: "software" } }));

    // The target changes to k2 before k1's policy arrives.
    await fireEvent.input(screen.getByPlaceholderText("Key ID"), { target: { value: "k2" } });
    resolveGet({
      policy: { key_id: "k1", version: 4, allowed_principals: ["svc-a"], denied_principals: ["svc-b"] },
      timestamp: 1,
    });
    await new Promise((r) => setTimeout(r, 0));

    expect(screen.queryByText("svc-a")).toBeNull();
    expect(screen.queryByText("Version 4")).toBeNull();

    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request).toHaveBeenLastCalledWith("PUT", "/api/v1/keys/k2/policy", {
      body: { backend: "software", key_id: "k2", policy: {} },
    });
  });

  it("clears a loaded policy when the target changes", async () => {
    request.mockResolvedValue({
      policy: { key_id: "k1", version: 2, denied_principals: ["svc-b"] },
      timestamp: 1,
    });

    render(KeyAccessPolicyView);
    await selectKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    expect(await screen.findByText("svc-b")).toBeInTheDocument();

    await fireEvent.input(screen.getByPlaceholderText("Backend"), { target: { value: "tpm2" } });

    expect(screen.queryByText("svc-b")).toBeNull();
    expect(screen.queryByText("Version 2")).toBeNull();
  });
});
