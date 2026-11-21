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
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { SetSOPINRequest, SetUserPINRequest, VerifyPINRequest, SuccessResponse } from "@go-xkms/sdk";

const setSO = vi.fn<(req: SetSOPINRequest) => Promise<SuccessResponse>>();
const setUser = vi.fn<(req: SetUserPINRequest) => Promise<SuccessResponse>>();
const verifySO = vi.fn<(req: VerifyPINRequest) => Promise<SuccessResponse>>();
const verifyUser = vi.fn<(req: VerifyPINRequest) => Promise<SuccessResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ pin: { setSO, setUser, verifySO, verifyUser } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import PinSetupView from "../src/views/PinSetupView.svelte";

// Distinctive PINs, so a leak into any text or toast is unambiguous.
const DEFAULT_SO = "48151623";
const NEW_SO = "90817263";
const NEW_USER = "55443322";
const TYPED = [DEFAULT_SO, NEW_SO, NEW_USER];

// Shaped as the SDK's XkmsApiError: a status-carrying Error.
class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "XkmsApiError";
    this.status = status;
  }
}

function input(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement;
}

async function type(label: string, value: string): Promise<void> {
  await fireEvent.input(input(label), { target: { value } });
}

function assertNoPinLeak(): void {
  const text = document.body.textContent ?? "";
  for (const pin of TYPED) {
    expect(text).not.toContain(pin);
    for (const t of toasts) expect(t.message).not.toContain(pin);
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("PinSetupView", () => {
  it("sets the SO PIN, toasts without the PINs and clears the inputs", async () => {
    setSO.mockResolvedValue({ success: true });
    render(PinSetupView);

    await type("Current SO PIN", DEFAULT_SO);
    await type("New SO PIN", NEW_SO);
    await type("Confirm new SO PIN", NEW_SO);
    await fireEvent.click(screen.getByRole("button", { name: "Set SO PIN" }));

    await waitFor(() => expect(setSO).toHaveBeenCalledOnce());
    expect(setSO).toHaveBeenCalledWith({ current_so_pin: DEFAULT_SO, new_so_pin: NEW_SO });
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: "SO PIN set." }));
    expect(input("Current SO PIN").value).toBe("");
    expect(input("New SO PIN").value).toBe("");
    expect(input("Confirm new SO PIN").value).toBe("");
    assertNoPinLeak();
  });

  it("refuses an SO PIN confirm mismatch inline and calls nothing", async () => {
    render(PinSetupView);

    await type("Current SO PIN", DEFAULT_SO);
    await type("New SO PIN", NEW_SO);
    await type("Confirm new SO PIN", NEW_USER);
    await fireEvent.click(screen.getByRole("button", { name: "Set SO PIN" }));

    expect(await screen.findByText("The new PIN and its confirmation differ.")).toBeInTheDocument();
    expect(setSO).not.toHaveBeenCalled();
    assertNoPinLeak();
  });

  it("sets the user PIN with the SO PIN and clears the inputs", async () => {
    setUser.mockResolvedValue({ success: true });
    render(PinSetupView);

    await type("SO PIN", NEW_SO);
    await type("New user PIN", NEW_USER);
    await type("Confirm new user PIN", NEW_USER);
    await fireEvent.click(screen.getByRole("button", { name: "Set user PIN" }));

    await waitFor(() => expect(setUser).toHaveBeenCalledOnce());
    expect(setUser).toHaveBeenCalledWith({ so_pin: NEW_SO, new_user_pin: NEW_USER });
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: "User PIN set." }));
    expect(input("SO PIN").value).toBe("");
    expect(input("New user PIN").value).toBe("");
    expect(input("Confirm new user PIN").value).toBe("");
    assertNoPinLeak();
  });

  it("refuses a user PIN confirm mismatch and calls nothing", async () => {
    render(PinSetupView);

    await type("SO PIN", NEW_SO);
    await type("New user PIN", NEW_USER);
    await type("Confirm new user PIN", DEFAULT_SO);
    await fireEvent.click(screen.getByRole("button", { name: "Set user PIN" }));

    expect(await screen.findByText("The new PIN and its confirmation differ.")).toBeInTheDocument();
    expect(setUser).not.toHaveBeenCalled();
  });

  it("verifies the SO PIN and clears the input", async () => {
    verifySO.mockResolvedValue({ success: true });
    render(PinSetupView);

    await fireEvent.click(screen.getByRole("radio", { name: "SO" }));
    await type("PIN to verify", NEW_SO);
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verifySO).toHaveBeenCalledWith({ pin: NEW_SO }));
    expect(verifyUser).not.toHaveBeenCalled();
    expect(await screen.findByText("PIN verified")).toBeInTheDocument();
    expect(input("PIN to verify").value).toBe("");
    assertNoPinLeak();
  });

  it("reports a rejected user PIN with a lockout warning and clears the input", async () => {
    // The PIN handler's 401 body names qrdb's ErrPINInvalid (handlers_pin.go).
    verifyUser.mockRejectedValue(new ApiError(401, "pin: invalid PIN"));
    render(PinSetupView);

    await fireEvent.click(screen.getByRole("radio", { name: "User" }));
    await type("PIN to verify", NEW_USER);
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verifyUser).toHaveBeenCalledWith({ pin: NEW_USER }));
    expect(verifySO).not.toHaveBeenCalled();
    expect(await screen.findByText("PIN not verified")).toBeInTheDocument();
    expect(screen.getByText(/counts toward the PIN lockout/)).toBeInTheDocument();
    expect(input("PIN to verify").value).toBe("");
    assertNoPinLeak();
  });

  // Only the PIN handler's invalid-PIN answer is a verdict on the PIN; a
  // lockout, an unavailable manager, a refusal, a rejected session (a 401
  // from AuthenticationMiddleware, before the PIN handler runs) or a network
  // failure says nothing about it and must show its cause instead (Codex
  // P1s on #2206).
  it.each([
    ["a rejected session", new ApiError(401, "invalid or expired token"), "invalid or expired token"],
    ["a locked PIN", new ApiError(429, "PIN locked"), "PIN locked"],
    ["an unavailable PIN manager", new ApiError(503, "PIN manager not configured"), "PIN manager not configured"],
    ["a permission refusal", new ApiError(403, "forbidden"), "forbidden"],
    ["a network failure", new TypeError("Failed to fetch"), "Failed to fetch"],
  ])("reports %s as a verification error, not a wrong PIN", async (_name, err, text) => {
    verifySO.mockRejectedValue(err);
    render(PinSetupView);

    await fireEvent.click(screen.getByRole("radio", { name: "SO" }));
    await type("PIN to verify", NEW_SO);
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(verifySO).toHaveBeenCalledOnce());
    expect(await screen.findByText("PIN verification could not run")).toBeInTheDocument();
    expect(screen.getByText(text)).toBeInTheDocument();
    expect(screen.queryByText("PIN not verified")).not.toBeInTheDocument();
    expect(screen.queryByText(/counts toward the PIN lockout/)).not.toBeInTheDocument();
    expect(input("PIN to verify").value).toBe("");
    assertNoPinLeak();
  });

  it("shows the server message when setting the SO PIN fails, without any PIN", async () => {
    setSO.mockRejectedValue(new Error("SO PIN already initialized"));
    render(PinSetupView);

    await type("Current SO PIN", DEFAULT_SO);
    await type("New SO PIN", NEW_SO);
    await type("Confirm new SO PIN", NEW_SO);
    await fireEvent.click(screen.getByRole("button", { name: "Set SO PIN" }));

    expect(await screen.findByText("SO PIN already initialized")).toBeInTheDocument();
    expect(input("New SO PIN").value).toBe("");
    assertNoPinLeak();
  });

  it("renders every PIN input as a password field without autocomplete", () => {
    render(PinSetupView);

    const pins = [
      "Current SO PIN",
      "New SO PIN",
      "Confirm new SO PIN",
      "SO PIN",
      "New user PIN",
      "Confirm new user PIN",
      "PIN to verify",
    ];
    for (const label of pins) {
      expect(input(label).type).toBe("password");
      expect(input(label).getAttribute("autocomplete")).toBe("off");
    }
    expect(screen.getByRole("link", { name: /PIN management/ })).toHaveAttribute("href", "#/pin");
  });
});
