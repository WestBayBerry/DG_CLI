import { describe, expect, it } from "vitest";
import { packagePageUrl } from "../../src/presentation/package-page.js";

describe("packagePageUrl", () => {
  it("links npm and pypi packages to their indexable pages", () => {
    expect(packagePageUrl("npm", "react")).toBe("https://westbayberry.com/npm/react");
    expect(packagePageUrl("pypi", "flask")).toBe("https://westbayberry.com/pypi/flask");
  });

  it("keeps a scoped npm name as a path so it hits the /<path:name> route", () => {
    expect(packagePageUrl("npm", "@babel/core")).toBe("https://westbayberry.com/npm/@babel/core");
  });

  it("returns null for ecosystems without a public page (no 404 links)", () => {
    expect(packagePageUrl("cargo", "serde")).toBeNull();
    expect(packagePageUrl("unknown", "x")).toBeNull();
  });
});
