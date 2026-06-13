import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { isIP } from "node:net";
import forge from "node-forge";

export interface CertificateAuthority {
  readonly caCertPem: string;
  readonly caPath: string;
  readonly leafForHost: (host: string) => LeafCertificate;
}

export interface LeafCertificate {
  readonly certPem: string;
  readonly keyPem: string;
}

export interface CertificateAuthorityOptions {
  readonly lifetimeMs?: number;
  readonly now?: () => number;
  readonly onRotate?: (caCertPem: string) => void;
}

export const CA_LIFETIME_MS = 24 * 60 * 60 * 1_000;
export const CA_ROTATE_AFTER_FRACTION = 0.75;
const ROTATION_CHECK_INTERVAL_MS = 60_000;

interface IssuedAuthority {
  readonly cert: any;
  readonly privateKey: any;
  readonly certPem: string;
  readonly notAfterMs: number;
  readonly rotateAtMs: number;
}

export function createEphemeralCertificateAuthority(
  caPath: string,
  options: CertificateAuthorityOptions = {}
): CertificateAuthority {
  const lifetimeMs = options.lifetimeMs ?? CA_LIFETIME_MS;
  const now = options.now ?? Date.now;
  let active = issueAuthority(caPath, lifetimeMs, now(), undefined);
  const leafs = new Map<string, LeafCertificate>();
  const rotateIfDue = (): void => {
    if (now() < active.rotateAtMs) {
      return;
    }
    active = issueAuthority(caPath, lifetimeMs, now(), active.certPem);
    leafs.clear();
    try {
      options.onRotate?.(active.certPem);
    } catch {
      return;
    }
  };
  setInterval(rotateIfDue, ROTATION_CHECK_INTERVAL_MS).unref();

  return {
    get caCertPem(): string {
      return active.certPem;
    },
    caPath,
    leafForHost(host: string): LeafCertificate {
      rotateIfDue();
      const normalized = normalizeHost(host);
      const existing = leafs.get(normalized);
      if (existing) {
        return existing;
      }
      const leaf = createLeafCertificate(normalized, active, lifetimeMs, now());
      leafs.set(normalized, leaf);
      return leaf;
    }
  };
}

interface RsaKeyPair {
  readonly privateKey: any;
  readonly publicKey: any;
}

// node:crypto keygen piped into forge via PEM so keygen never falls back to forge's pure-JS path.
function generateRsaKeyPair(): RsaKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  return {
    privateKey: forge.pki.privateKeyFromPem(privateKey.export({
      type: "pkcs8",
      format: "pem"
    }).toString()),
    publicKey: forge.pki.publicKeyFromPem(publicKey.export({
      type: "spki",
      format: "pem"
    }).toString())
  };
}

function issueAuthority(
  caPath: string,
  lifetimeMs: number,
  nowMs: number,
  previousCertPem: string | undefined
): IssuedAuthority {
  const keys = generateRsaKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = new Date(nowMs - 60_000);
  cert.validity.notAfter = new Date(nowMs + lifetimeMs);
  const attrs = [{
    name: "commonName",
    value: "Dependency Guardian per-session proxy CA"
  }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: true,
      critical: true
    },
    {
      name: "keyUsage",
      keyCertSign: true,
      cRLSign: true,
      critical: true
    },
    {
      name: "extKeyUsage",
      serverAuth: true
    },
    {
      name: "subjectKeyIdentifier"
    }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPem = forge.pki.certificateToPem(cert);
  writeCaBundleAtomic(caPath, previousCertPem ? `${certPem}${previousCertPem}` : certPem);

  return {
    cert,
    privateKey: keys.privateKey,
    certPem,
    notAfterMs: nowMs + lifetimeMs,
    rotateAtMs: nowMs + Math.floor(lifetimeMs * CA_ROTATE_AFTER_FRACTION)
  };
}

function writeCaBundleAtomic(caPath: string, bundle: string): void {
  mkdirSync(dirname(caPath), {
    recursive: true,
    mode: 0o700
  });
  const tempPath = `${caPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync(tempPath, bundle, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });
    renameSync(tempPath, caPath);
  } catch (error) {
    rmSync(tempPath, {
      force: true
    });
    throw error;
  }
}

function createLeafCertificate(host: string, issuer: IssuedAuthority, lifetimeMs: number, nowMs: number): LeafCertificate {
  const keys = generateRsaKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serialNumber();
  cert.validity.notBefore = new Date(nowMs - 60_000);
  cert.validity.notAfter = new Date(Math.min(nowMs + lifetimeMs, issuer.notAfterMs));
  cert.setSubject([{
    name: "commonName",
    value: host
  }]);
  cert.setIssuer(issuer.cert.subject.attributes);
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: false,
      critical: true
    },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true
    },
    {
      name: "extKeyUsage",
      serverAuth: true
    },
    {
      name: "subjectAltName",
      altNames: subjectAlternativeNames(host)
    }
  ]);
  cert.sign(issuer.privateKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey)
  };
}

function subjectAlternativeNames(host: string): readonly Record<string, string | number>[] {
  const ipVersion = isIP(host);
  if (ipVersion !== 0) {
    return [{
      type: 7,
      ip: host
    }];
  }
  return [{
    type: 2,
    value: host
  }];
}

function normalizeHost(host: string): string {
  return host.replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "").toLowerCase();
}

function serialNumber(): string {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] ?? 0) & 0x7f;
  return bytes.toString("hex");
}
