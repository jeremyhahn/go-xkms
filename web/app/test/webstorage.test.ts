import { describe, it, expect } from "vitest";

// Node 26 enables Web Storage by default and its global localStorage
// shadows jsdom's (#2167). The vitest workers run with
// --no-experimental-webstorage so jsdom's storage is the one tests see.
describe("jsdom localStorage", () => {
  it("is jsdom storage and round-trips a value", () => {
    expect(typeof window.localStorage?.clear).toBe("function");
    window.localStorage.clear();
    window.localStorage.setItem("webstorage-2167", "ok");
    expect(window.localStorage.getItem("webstorage-2167")).toBe("ok");
    window.localStorage.clear();
  });
});
