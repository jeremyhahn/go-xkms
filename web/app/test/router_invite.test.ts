import { describe, expect, it } from "vitest";
import { parseHash } from "../src/stores/router.svelte.ts";

// Ruling 973 (3): servicer_invite.go builds /#/invite/<tenant>/<token>
// links; the web app must route them to the passkey enrolment view.
describe("invite route", () => {
  it("resolves #/invite/<tenant>/<token> to the invite view", () => {
    const r = parseHash("#/invite/t1/tok");
    expect(r.name).toBe("invite");
    expect(r.params).toEqual({ tenant: "t1", token: "tok" });
  });

  it("decodes percent-encoded tenant and token segments", () => {
    const r = parseHash("#/invite/t%201/a%2Fb");
    expect(r.name).toBe("invite");
    expect(r.params).toEqual({ tenant: "t 1", token: "a/b" });
  });

  it("does not route an invite link without a token", () => {
    expect(parseHash("#/invite/t1").name).not.toBe("invite");
    expect(parseHash("#/invite/t1/tok/extra").name).not.toBe("invite");
  });
});
