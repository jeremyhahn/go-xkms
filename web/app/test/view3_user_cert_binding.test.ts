// UserCertBindingView: lists a user's credentials (users.credentials) and
// binds a client certificate thumbprint to the user (users.bindCert).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { ListUserCredentialsResponse, BindUserCertRequest, UserStatusResponse } from "@go-xkms/sdk";

const credentials = vi.fn<(username: string) => Promise<ListUserCredentialsResponse>>();
const bindCert = vi.fn<(username: string, req: BindUserCertRequest) => Promise<UserStatusResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ users: { credentials, bindCert } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import UserCertBindingView from "../src/views/UserCertBindingView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function loadUser(username: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Username"), { target: { value: username } });
  await fireEvent.click(screen.getByRole("button", { name: "Load" }));
}

async function fillBind(thumbprint: string, notAfter: string): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Thumbprint"), { target: { value: thumbprint } });
  await fireEvent.input(screen.getByLabelText("Not after"), { target: { value: notAfter } });
}

describe("UserCertBindingView", () => {
  it("gates Load and Bind on their inputs and calls nothing on mount", async () => {
    render(UserCertBindingView);

    expect(screen.getByRole("heading", { name: "Certificate Binding" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Load" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Bind" })).toBeDisabled();
    expect(credentials).not.toHaveBeenCalled();
    expect(bindCert).not.toHaveBeenCalled();

    await fireEvent.input(screen.getByLabelText("Username"), { target: { value: "alice" } });
    expect(screen.getByRole("button", { name: "Load" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Bind" })).toBeDisabled();

    await fireEvent.input(screen.getByLabelText("Thumbprint"), { target: { value: "abcd" } });
    expect(screen.getByRole("button", { name: "Bind" })).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Not after"), { target: { value: "2030-01-01" } });
    expect(screen.getByRole("button", { name: "Bind" })).toBeEnabled();
  });

  it("loads and renders the user's credentials", async () => {
    credentials.mockResolvedValue({
      credentials: [
        { id: "cred-1", name: "laptop passkey" },
        { id: "cred-2", name: "yubikey" },
      ],
    });

    render(UserCertBindingView);
    await loadUser("alice");

    expect(await screen.findByText("laptop passkey")).toBeInTheDocument();
    expect(screen.getByText("cred-1")).toBeInTheDocument();
    expect(screen.getByText("yubikey")).toBeInTheDocument();
    expect(screen.getByText("cred-2")).toBeInTheDocument();
    expect(credentials).toHaveBeenCalledOnce();
    expect(credentials).toHaveBeenCalledWith("alice");
  });

  it("shows the empty state when the user has no credentials", async () => {
    credentials.mockResolvedValue({ credentials: [] });

    render(UserCertBindingView);
    await loadUser("bob");

    expect(await screen.findByText("No credentials")).toBeInTheDocument();
  });

  it("binds the normalised thumbprint and not-after, toasts and reloads", async () => {
    credentials.mockResolvedValue({ credentials: [] });
    bindCert.mockResolvedValue({ username: "alice", status: "bound" });

    render(UserCertBindingView);
    await fireEvent.input(screen.getByLabelText("Username"), { target: { value: "alice" } });
    await fillBind("AB:CD:ef 01", "2030-01-01");
    await fireEvent.click(screen.getByRole("button", { name: "Bind" }));

    await waitFor(() => expect(bindCert).toHaveBeenCalledOnce());
    expect(bindCert).toHaveBeenCalledWith("alice", { thumbprint: "ABCDef01", not_after_unix: 1893456000 });
    await waitFor(() => expect(credentials).toHaveBeenCalledWith("alice"));
    expect(toasts).toHaveLength(1);
    expect(toasts[0]!.kind).toBe("success");
    expect(toasts[0]!.message).toContain("bound");
  });

  it("rejects a non-hex thumbprint inline without calling bindCert", async () => {
    render(UserCertBindingView);
    await fireEvent.input(screen.getByLabelText("Username"), { target: { value: "alice" } });
    await fillBind("zz:11", "2030-01-01");
    await fireEvent.click(screen.getByRole("button", { name: "Bind" }));

    expect(await screen.findByText("Thumbprint must be hexadecimal.")).toBeInTheDocument();
    expect(bindCert).not.toHaveBeenCalled();
  });

  it("shows an error alert when loading credentials fails", async () => {
    credentials.mockRejectedValue(new Error("user not found"));

    render(UserCertBindingView);
    await loadUser("ghost");

    expect(await screen.findByText("user not found")).toBeInTheDocument();
  });

  it("shows an error alert when binding fails", async () => {
    bindCert.mockRejectedValue(new Error("thumbprint already bound"));

    render(UserCertBindingView);
    await fireEvent.input(screen.getByLabelText("Username"), { target: { value: "alice" } });
    await fillBind("abcd", "2030-01-01");
    await fireEvent.click(screen.getByRole("button", { name: "Bind" }));

    expect(await screen.findByText("thumbprint already bound")).toBeInTheDocument();
    expect(toasts).toHaveLength(0);
  });
});
