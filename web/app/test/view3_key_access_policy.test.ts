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
    await fireEvent.click(screen.getByLabelText("Require MFA"));
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
          require_mfa: true,
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
