// KeyRotationPolicyView: shows, sets and removes a key's automatic rotation
// policy through GET, PUT and DELETE /api/v1/keys/{id}/rotation-policy.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { answerConfirm, confirmDialog, spyWindowConfirm } from "./confirm_modal";
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
      policy: { enabled: true, interval_seconds: 604800, next_rotation: 1800000000 },
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

  it("removes the policy only after the confirm dialog", async () => {
    const confirmSpy = spyWindowConfirm();
    request.mockResolvedValue({ key_id: "k1", timestamp: "2026-11-12T00:00:00Z" });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(await confirmDialog()).toHaveTextContent('Remove the rotation policy of key "k1"?');
    expect(request).not.toHaveBeenCalled();

    await answerConfirm("Remove");

    await waitFor(() => expect(request).toHaveBeenCalledOnce());
    expect(request).toHaveBeenCalledWith("DELETE", PATH, { query: { backend: "software" } });
    expect(await screen.findByText("No rotation policy")).toBeInTheDocument();
    expect(confirmSpy).not.toHaveBeenCalled();
  });

  it("sends nothing when the confirm dialog is cancelled", async () => {
    const confirmSpy = spyWindowConfirm();
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await answerConfirm("Cancel");

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(request).not.toHaveBeenCalled();
    expect(confirmSpy).not.toHaveBeenCalled();
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

  it("disables Auto rotate and Retain versions with the reason the service refuses them", async () => {
    render(KeyRotationPolicyView);
    expect(screen.getByLabelText("Auto rotate")).toBeDisabled();
    expect(screen.getByLabelText("Retain versions")).toBeDisabled();
    expect(screen.getByText(/the service runs no rotation scheduler and retires no versions by itself/)).toBeInTheDocument();
    expect(screen.getByText(/rotate the key by hand from Key Versions/)).toBeInTheDocument();
  });

  it("saves a loaded auto-rotate policy without the fields the service refuses", async () => {
    request.mockResolvedValueOnce({
      key_id: "k1",
      timestamp: "2026-11-12T00:00:00Z",
      policy: { enabled: true, interval_seconds: 86400, retain_versions: 3, auto_rotate: true },
    });
    request.mockResolvedValueOnce({ key_id: "k1", timestamp: "2026-11-12T00:00:00Z" });
    render(KeyRotationPolicyView);
    await fillKey();
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await screen.findByText("1 day");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(request).toHaveBeenCalledTimes(2));
    expect(request.mock.calls[1]![2].body.policy).toEqual({ enabled: true, interval_seconds: 86400 });
  });

  it("shows the service's refusal of an unenforceable rotation policy", async () => {
    request.mockRejectedValue(new Error('keystore: key "k1": auto_rotate cannot be enforced: the service runs no rotation scheduler; rotate with RotateKey'));
    render(KeyRotationPolicyView);
    await fillKey();
    await fillForm("7", "days");
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText(/auto_rotate cannot be enforced/)).toBeInTheDocument();
  });
});
