// KeyRotationPolicyView: shows, sets and removes a key's automatic rotation
// policy through GET, PUT and DELETE /api/v1/keys/{id}/rotation-policy.
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

import KeyRotationPolicyView from "../src/views/KeyRotationPolicyView.svelte";

const PATH = "/api/v1/keys/k1/rotation-policy";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function fillKey(): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
  await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
}

async function fillForm(interval: string, unit: "hours" | "days"): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Interval"), { target: { value: interval } });
  await fireEvent.change(screen.getByLabelText("Interval unit"), { target: { value: unit } });
}

describe("KeyRotationPolicyView", () => {
  it("loads a policy with the backend as a query parameter", async () => {
    request.mockResolvedValue({
      key_id: "k1",
      timestamp: "2026-11-12T00:00:00Z",
      policy: { enabled: true, interval_seconds: 2592000, retain_versions: 3, auto_rotate: true, next_rotation: 1800000000 },
    });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("GET", PATH, { query: { backend: "software" } });
    expect(await screen.findByText("30 days")).toBeInTheDocument();
    expect(screen.getByText("3 versions")).toBeInTheDocument();
    expect(screen.getByText(new Date(1800000000 * 1000).toLocaleString())).toBeInTheDocument();
  });

  it("shows the empty state when the key has no policy", async () => {
    request.mockResolvedValue({ key_id: "k1", timestamp: "2026-11-12T00:00:00Z" });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    expect(await screen.findByText("No rotation policy")).toBeInTheDocument();
  });

  it("saves a policy in seconds and shows the returned policy", async () => {
    request.mockResolvedValue({
      key_id: "k1",
      timestamp: "2026-11-12T00:00:00Z",
      policy: { enabled: true, interval_seconds: 604800, retain_versions: 5, auto_rotate: true, next_rotation: 1800000000 },
    });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByLabelText("Enabled"));
    await fillForm("7", "days");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("PUT", PATH, {
      body: {
        backend: "software",
        key_id: "k1",
        policy: { enabled: true, interval_seconds: 604800 },
      },
    });
    expect(await screen.findByText("7 days")).toBeInTheDocument();
    expect(screen.getByText("5 versions")).toBeInTheDocument();
    expect(toasts).toEqual([{ kind: "success", message: expect.stringContaining("k1") }]);
  });

  it("sends 12 hours as 43200 seconds", async () => {
    request.mockResolvedValue({ key_id: "k1", timestamp: "2026-11-12T00:00:00Z" });
    render(KeyRotationPolicyView);
    await fillKey();
    await fillForm("12", "hours");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    const [, , opts] = request.mock.calls[0]!;
    expect(opts.body.policy.interval_seconds).toBe(43200);
  });

  it("removes the policy after a confirm", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    request.mockResolvedValue({ key_id: "k1", timestamp: "2026-11-12T00:00:00Z" });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("DELETE", PATH, { query: { backend: "software" } });
    expect(await screen.findByText("No rotation policy")).toBeInTheDocument();
  });

  it("sends nothing when the confirm is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove" }));

    expect(window.confirm).toHaveBeenCalledOnce();
    expect(request).not.toHaveBeenCalled();
  });

  it("keeps Load and Save disabled until key ID and backend are set", async () => {
    render(KeyRotationPolicyView);
    expect(screen.getByRole("button", { name: "Load" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k1" } });
    expect(screen.getByRole("button", { name: "Load" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("Backend"), { target: { value: "software" } });
    expect(screen.getByRole("button", { name: "Load" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Save" })).toBeEnabled();
  });

  it.each([
    ["0", "Interval must be a positive whole number."],
    ["-3", "Interval must be a positive whole number."],
    ["1.5", "Interval must be a positive whole number."],
  ])("rejects interval %s inline", async (interval, message) => {
    render(KeyRotationPolicyView);
    await fillKey();
    await fillForm(interval, "days");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("shows a rejected GET in an error alert", async () => {
    request.mockRejectedValue(new Error("key not found"));
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    expect(await screen.findByText("key not found")).toBeInTheDocument();
  });

  it("shows a rejected PUT in an error alert", async () => {
    request.mockRejectedValue(new Error("permission denied"));
    render(KeyRotationPolicyView);
    await fillKey();
    await fillForm("7", "days");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    expect(toasts).toEqual([]);
  });
});

describe("KeyRotationPolicyView server limits and stale replies", () => {
  it("offers no Auto rotate or Retain versions control, which the server refuses", () => {
    render(KeyRotationPolicyView);
    expect(screen.queryByLabelText("Auto rotate")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Retain versions")).not.toBeInTheDocument();
  });

  it("drops a GET reply that lands after the key ID changed", async () => {
    let resolveGet: (v: unknown) => void = () => {};
    request.mockImplementation(() => new Promise((r) => (resolveGet = r)));
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(request).toHaveBeenCalledOnce());

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k2" } });
    resolveGet({
      key_id: "k1",
      timestamp: "2026-11-12T00:00:00Z",
      policy: { enabled: true, interval_seconds: 2592000 },
    });
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));

    expect(screen.queryByText("30 days")).not.toBeInTheDocument();
    expect(screen.queryByText("Current policy")).not.toBeInTheDocument();
  });

  it("clears a loaded policy when the key ID changes", async () => {
    request.mockResolvedValue({
      key_id: "k1",
      timestamp: "2026-11-12T00:00:00Z",
      policy: { enabled: true, interval_seconds: 2592000 },
    });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    expect(await screen.findByText("30 days")).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Key ID"), { target: { value: "k2" } });
    expect(screen.queryByText("30 days")).not.toBeInTheDocument();
  });

  it("freezes the key inputs while a save is pending", async () => {
    let resolvePut: (v: unknown) => void = () => {};
    request.mockImplementation(() => new Promise((r) => (resolvePut = r)));
    render(KeyRotationPolicyView);
    await fillKey();
    await fillForm("7", "days");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(request).toHaveBeenCalledOnce());

    expect(screen.getByLabelText("Key ID")).toBeDisabled();
    expect(screen.getByLabelText("Backend")).toBeDisabled();
    resolvePut({ key_id: "k1", timestamp: "2026-11-12T00:00:00Z" });
    await waitFor(() => expect(screen.getByLabelText("Key ID")).not.toBeDisabled());
  });
});
