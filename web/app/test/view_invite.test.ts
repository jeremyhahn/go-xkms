import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/svelte";

// Ruling 973 (3): the invite link view runs the passkey enrolment bound to
// the invite. Ruling 972 (1): with webauthn off it names webauthn.enabled
// and never starts the ceremony.

const capabilitiesGet = vi.fn();
const invitesGet = vi.fn();
const invitesBegin = vi.fn();
const invitesFinish = vi.fn();
const loginBegin = vi.fn();
const loginFinish = vi.fn();
const me = vi.fn();
const createCredential = vi.fn();
const getAssertion = vi.fn();
const navigateTo = vi.fn();
const loadSession = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    capabilities: { get: capabilitiesGet },
    invites: {
      get: invitesGet,
      beginRegistration: invitesBegin,
      finishRegistration: invitesFinish,
    },
    auth: {
      webAuthnBeginLogin: loginBegin,
      webAuthnFinishLogin: loginFinish,
      me,
    },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/lib/auth.ts", () => ({
  getAuthContext: () => ({ provider: { createCredential, getAssertion } }),
}));

vi.mock("../src/stores/session.svelte.ts", () => ({
  loadSession: () => loadSession(),
}));

vi.mock("../src/stores/router.svelte.ts", () => ({
  navigateTo: (p: string) => navigateTo(p),
}));

import InviteView from "../src/views/InviteView.svelte";

function httpError(status: number, message: string): Error {
  return Object.assign(new Error(message), { status });
}

beforeEach(() => {
  vi.clearAllMocks();
  capabilitiesGet.mockResolvedValue({ webauthn_enabled: true });
  invitesGet.mockResolvedValue({
    email: "ada@example.com",
    display_name: "Ada",
    expires_at: "2026-12-01T00:00:00Z",
    methods: ["webauthn"],
  });
});

describe("InviteView", () => {
  it("shows the disabled state naming webauthn.enabled and makes no invite request", async () => {
    capabilitiesGet.mockResolvedValue({ webauthn_enabled: false });
    render(InviteView, { props: { tenant: "t1", token: "tok" } });

    expect(await screen.findByText(/webauthn\.enabled/)).toBeInTheDocument();
    expect(invitesGet).not.toHaveBeenCalled();
    expect(invitesBegin).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /register passkey/i })).toBeNull();
  });

  it("shows the unusable-link state on a 404", async () => {
    invitesGet.mockRejectedValue(httpError(404, "link is not valid"));
    render(InviteView, { props: { tenant: "t1", token: "tok" } });

    expect(await screen.findByText(/this invite link is not valid/i)).toBeInTheDocument();
    expect(invitesGet).toHaveBeenCalledWith("t1", "tok");
    expect(screen.queryByRole("button", { name: /register passkey/i })).toBeNull();
  });

  it("shows the tenant and the invited address", async () => {
    render(InviteView, { props: { tenant: "t1", token: "tok" } });

    expect(await screen.findByText("ada@example.com")).toBeInTheDocument();
    expect(screen.getByText("t1")).toBeInTheDocument();
  });

  it("enrols the passkey against the invite and lands signed in", async () => {
    invitesBegin.mockResolvedValue({ sessionId: "s1", options: { publicKey: {} } });
    createCredential.mockResolvedValue({ id: "cred" });
    invitesFinish.mockResolvedValue({ user_id: "42" });
    loginBegin.mockResolvedValue({ sessionId: "s2", options: { publicKey: {} } });
    getAssertion.mockResolvedValue({ id: "cred" });
    loginFinish.mockResolvedValue({ token: "at", refresh_token: "rt" });
    loadSession.mockResolvedValue(undefined);

    render(InviteView, { props: { tenant: "t1", token: "tok" } });
    await fireEvent.click(await screen.findByRole("button", { name: /register passkey/i }));

    await waitFor(() => expect(navigateTo).toHaveBeenCalledWith("/dashboard"));
    expect(invitesBegin).toHaveBeenCalledWith("t1", "tok");
    expect(createCredential).toHaveBeenCalledWith({ publicKey: {} });
    expect(invitesFinish).toHaveBeenCalledWith("t1", "tok", "s1", { id: "cred" });
    expect(loginBegin).toHaveBeenCalledWith({ email: "ada@example.com" });
    expect(loginFinish).toHaveBeenCalledWith("s2", { id: "cred" });
    expect(loadSession).toHaveBeenCalled();
  });

  it("shows the unusable-link state when the invite is spent during enrolment", async () => {
    invitesBegin.mockRejectedValue(httpError(404, "link is not valid"));
    render(InviteView, { props: { tenant: "t1", token: "tok" } });
    await fireEvent.click(await screen.findByRole("button", { name: /register passkey/i }));

    expect(await screen.findByText(/this invite link is not valid/i)).toBeInTheDocument();
    expect(createCredential).not.toHaveBeenCalled();
  });
});
