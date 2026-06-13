import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import forge from "node-forge";
import {
  CA_LIFETIME_MS,
  CA_ROTATE_AFTER_FRACTION,
  createEphemeralCertificateAuthority
} from "../../src/proxy/ca.js";

const tempRoots: string[] = [];

async function tempCaPath(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-ca-rotation-"));
  tempRoots.push(root);
  return join(root, "ca", "ca.pem");
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("service CA rotation", () => {
  it("uses a 24h lifetime and rotates at 75% of it", () => {
    expect(CA_LIFETIME_MS).toBe(24 * 60 * 60 * 1_000);
    expect(CA_ROTATE_AFTER_FRACTION).toBe(0.75);
  });

  it("keeps the CA and cached leafs below the rotation threshold", async () => {
    const caPath = await tempCaPath();
    let clock = 1_000_000;
    const ca = createEphemeralCertificateAuthority(caPath, { lifetimeMs: 100_000, now: () => clock });
    const initialPem = ca.caCertPem;
    const leaf = ca.leafForHost("registry.npmjs.org");

    clock += 74_999;
    expect(ca.leafForHost("registry.npmjs.org")).toBe(leaf);
    expect(ca.caCertPem).toBe(initialPem);
    const bundle = await readFile(caPath, "utf8");
    expect(bundle.match(/BEGIN CERTIFICATE/g)).toHaveLength(1);
  });

  it("rotates past 75% of lifetime: new CA first in the bundle, previous CA retained, leafs re-minted", async () => {
    const caPath = await tempCaPath();
    let clock = 1_000_000;
    const ca = createEphemeralCertificateAuthority(caPath, { lifetimeMs: 100_000, now: () => clock });
    const initialPem = ca.caCertPem;
    const leafBefore = ca.leafForHost("registry.npmjs.org");

    clock += 75_001;
    const leafAfter = ca.leafForHost("registry.npmjs.org");

    expect(leafAfter).not.toBe(leafBefore);
    expect(ca.caCertPem).not.toBe(initialPem);

    const bundle = await readFile(caPath, "utf8");
    expect(bundle.match(/BEGIN CERTIFICATE/g)).toHaveLength(2);
    expect(bundle.indexOf(ca.caCertPem)).toBe(0);
    expect(bundle).toContain(initialPem);

    const rotatedCa = forge.pki.certificateFromPem(ca.caCertPem);
    const leafCert = forge.pki.certificateFromPem(leafAfter.certPem);
    expect(rotatedCa.verify(leafCert)).toBe(true);

    const previousCa = forge.pki.certificateFromPem(initialPem);
    expect(() => previousCa.verify(leafCert)).toThrow();
  });

  it("constrains the CA and its leafs to serverAuth extended key usage", async () => {
    const caPath = await tempCaPath();
    const ca = createEphemeralCertificateAuthority(caPath);

    const caCert = forge.pki.certificateFromPem(ca.caCertPem);
    const caEku = caCert.getExtension("extKeyUsage") as { serverAuth?: boolean } | undefined;
    expect(caEku?.serverAuth).toBe(true);

    const leafCert = forge.pki.certificateFromPem(ca.leafForHost("registry.npmjs.org").certPem);
    const leafEku = leafCert.getExtension("extKeyUsage") as { serverAuth?: boolean } | undefined;
    expect(leafEku?.serverAuth).toBe(true);
  });

  it("invokes onRotate with the new CA PEM exactly when rotation happens", async () => {
    const caPath = await tempCaPath();
    let clock = 1_000_000;
    const rotations: string[] = [];
    const ca = createEphemeralCertificateAuthority(caPath, {
      lifetimeMs: 100_000,
      now: () => clock,
      onRotate: (caCertPem) => rotations.push(caCertPem)
    });
    const initialPem = ca.caCertPem;

    clock += 74_999;
    ca.leafForHost("registry.npmjs.org");
    expect(rotations).toEqual([]);

    clock += 2;
    ca.leafForHost("registry.npmjs.org");
    expect(rotations).toHaveLength(1);
    expect(rotations[0]).toBe(ca.caCertPem);
    expect(rotations[0]).not.toBe(initialPem);
  });

  it("survives an onRotate callback that throws", async () => {
    const caPath = await tempCaPath();
    let clock = 1_000_000;
    const ca = createEphemeralCertificateAuthority(caPath, {
      lifetimeMs: 100_000,
      now: () => clock,
      onRotate: () => {
        throw new Error("trust store refused");
      }
    });
    const initialPem = ca.caCertPem;

    clock += 75_001;
    expect(() => ca.leafForHost("registry.npmjs.org")).not.toThrow();
    expect(ca.caCertPem).not.toBe(initialPem);
  });
});
