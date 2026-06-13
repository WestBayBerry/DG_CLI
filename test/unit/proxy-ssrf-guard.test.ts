import { describe, expect, it } from "vitest";
import { isLinkLocalHost, isPrivateNetworkHost } from "../../src/proxy/server.js";

const u = (s: string): URL => new URL(s);

describe("proxy SSRF host guards", () => {
  it("treats the cloud-metadata IP as link-local in dotted and IPv4-mapped-IPv6 form", () => {
    expect(isLinkLocalHost(u("http://169.254.169.254/latest/meta-data/"))).toBe(true);
    // Node canonicalizes [::ffff:169.254.169.254] to the hex form [::ffff:a9fe:a9fe].
    expect(isLinkLocalHost(u("http://[::ffff:169.254.169.254]/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://[::ffff:169.254.169.254]/"))).toBe(true);
  });

  it("classifies IPv4-mapped IPv6 loopback / RFC1918 as private", () => {
    expect(isPrivateNetworkHost(u("http://[::ffff:127.0.0.1]/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://[::ffff:192.168.1.1]/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://[::ffff:10.0.0.5]/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://[::ffff:172.16.0.1]/"))).toBe(true);
  });

  it("classifies the plain private and loopback ranges", () => {
    expect(isPrivateNetworkHost(u("http://10.0.0.1/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://127.0.0.1/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://192.168.0.1/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://[::1]/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://localhost/"))).toBe(true);
    expect(isPrivateNetworkHost(u("http://100.64.0.1/"))).toBe(true);
  });

  it("does not flag real registry hosts", () => {
    for (const host of ["https://registry.npmjs.org/", "https://files.pythonhosted.org/", "https://pypi.org/", "https://crates.io/"]) {
      expect(isPrivateNetworkHost(u(host))).toBe(false);
      expect(isLinkLocalHost(u(host))).toBe(false);
    }
    // 8.8.8.8 is public; the 0./100. anchors must not over-match a normal octet.
    expect(isPrivateNetworkHost(u("http://8.8.8.8/"))).toBe(false);
    expect(isPrivateNetworkHost(u("http://100.200.0.1/"))).toBe(false);
  });
});
