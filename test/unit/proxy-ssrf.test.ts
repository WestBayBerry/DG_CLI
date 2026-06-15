import { describe, expect, it } from "vitest";
import { isBlockedResolvedIp, isPrivateNetworkHost, isLinkLocalHost } from "../../src/proxy/server.js";

describe("isBlockedResolvedIp (DNS-rebinding / resolved-target guard)", () => {
  it("blocks private, loopback, link-local, CGNAT IPv4", () => {
    for (const ip of ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0"]) {
      expect(isBlockedResolvedIp(ip), ip).toBe(true);
    }
  });

  it("allows ordinary public unicast", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
      expect(isBlockedResolvedIp(ip), ip).toBe(false);
    }
  });

  it("blocks IPv6 loopback / link-local / ULA", () => {
    for (const ip of ["::1", "fe80::1", "fc00::1", "fd00::1"]) {
      expect(isBlockedResolvedIp(ip), ip).toBe(true);
    }
  });

  it("recovers an internal IPv4 embedded in IPv6 (mapped/compat/6to4/NAT64) and blocks it", () => {
    for (const ip of ["::ffff:169.254.169.254", "::a9fe:a9fe", "2002:a9fe:a9fe::", "64:ff9b::a9fe:a9fe"]) {
      expect(isBlockedResolvedIp(ip), ip).toBe(true);
    }
  });

  it("does not over-block a public IPv4 embedded via 6to4", () => {
    expect(isBlockedResolvedIp("2002:0808:0808::")).toBe(false);
  });
});

describe("isPrivateNetworkHost / isLinkLocalHost (literal-target guard)", () => {
  it("blocks a private literal target and the metadata IP in IPv6-mapped form", () => {
    expect(isPrivateNetworkHost(new URL("http://10.0.0.5/x"))).toBe(true);
    expect(isPrivateNetworkHost(new URL("http://[::ffff:169.254.169.254]/x"))).toBe(true);
    expect(isLinkLocalHost(new URL("http://169.254.169.254/x"))).toBe(true);
  });

  it("allows a public registry host", () => {
    expect(isPrivateNetworkHost(new URL("https://registry.npmjs.org/left-pad"))).toBe(false);
  });
});
