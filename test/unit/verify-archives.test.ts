import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyLocalTarget } from "../../src/verify/local.js";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, {
    force: true,
    recursive: true
  })));
});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "dg-verify-archive-"));
  tempRoots.push(root);
  return root;
}

async function writeArtifact(name: string, bytes: Buffer): Promise<string> {
  const root = await tempRoot();
  const path = join(root, name);
  await writeFile(path, bytes);
  return path;
}

type ZipEntrySpec = {
  name: string;
  body: string;
  dataDescriptor?: boolean;
  encrypted?: boolean;
  centralName?: string;
  localOnly?: boolean;
};

function buildZip(entries: ZipEntrySpec[], options: { omitCentralDirectory?: boolean } = {}): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  let centralCount = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const body = Buffer.from(entry.body);
    const flags = (entry.dataDescriptor ? 0x8 : 0) | (entry.encrypted ? 0x1 : 0);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(flags, 6);
    header.writeUInt32LE(entry.dataDescriptor ? 0 : body.length, 18);
    header.writeUInt32LE(entry.dataDescriptor ? 0 : body.length, 22);
    header.writeUInt16LE(name.length, 26);
    localParts.push(header, name, body);
    const localOffset = offset;
    offset += 30 + name.length + body.length;
    if (entry.dataDescriptor) {
      const descriptor = Buffer.alloc(16);
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(body.length, 8);
      descriptor.writeUInt32LE(body.length, 12);
      localParts.push(descriptor);
      offset += 16;
    }
    if (!entry.localOnly) {
      const centralName = Buffer.from(entry.centralName ?? entry.name);
      const record = Buffer.alloc(46);
      record.writeUInt32LE(0x02014b50, 0);
      record.writeUInt16LE(20, 4);
      record.writeUInt16LE(20, 6);
      record.writeUInt16LE(flags, 8);
      record.writeUInt32LE(body.length, 20);
      record.writeUInt32LE(body.length, 24);
      record.writeUInt16LE(centralName.length, 28);
      record.writeUInt32LE(localOffset, 42);
      centralParts.push(record, centralName);
      centralCount += 1;
    }
  }
  if (options.omitCentralDirectory) {
    return Buffer.concat(localParts);
  }
  const centralSize = centralParts.reduce((total, part) => total + part.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(centralCount, 8);
  eocd.writeUInt16LE(centralCount, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

function tarHeader(name: string, size: number, typeflag: string): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write("0000644\0", 100, 8, "ascii");
  header.write("0000000\0", 108, 8, "ascii");
  header.write("0000000\0", 116, 8, "ascii");
  header.write(`${size.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
  header.write("00000000000\0", 136, 12, "ascii");
  header[156] = typeflag.charCodeAt(0);
  header.write("ustar\0", 257, 6, "ascii");
  header.fill(0x20, 148, 156);
  const checksum = header.reduce((total, byte) => total + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
  return header;
}

function buildTar(members: Array<{ name: string; body: Buffer | string; typeflag?: string }>): Buffer {
  const blocks: Buffer[] = [];
  for (const member of members) {
    const body = Buffer.from(member.body);
    blocks.push(
      tarHeader(member.name, body.length, member.typeflag ?? "0"),
      body,
      Buffer.alloc((512 - (body.length % 512)) % 512)
    );
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function paxBody(records: Record<string, string>): Buffer {
  let out = "";
  for (const [key, value] of Object.entries(records)) {
    const base = ` ${key}=${value}\n`;
    let length = base.length + 1;
    while (`${length}${base}`.length !== length) {
      length += 1;
    }
    out += `${length}${base}`;
  }
  return Buffer.from(out, "utf8");
}

describe("zip central directory parsing", () => {
  it("enumerates entries from the central directory across data-descriptor entries", async () => {
    const path = await writeArtifact("descriptor.zip", buildZip([
      { name: "streamed.txt", body: "streamed", dataDescriptor: true },
      { name: "../escape.txt", body: "owned" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.archive?.entryCount).toBe(2);
    expect(report.status).toBe("block");
    expect(report.findings.map((finding) => finding.id)).toContain("archive-path-traversal");
  });

  it("reads manifest bodies for data-descriptor entries via central directory sizes", async () => {
    const path = await writeArtifact("descriptor.whl", buildZip([
      {
        name: "package/package.json",
        body: JSON.stringify({ name: "streamed-pkg", scripts: { postinstall: "node x.js" } }),
        dataDescriptor: true
      }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("warn");
    expect(report.findings.map((finding) => finding.id)).toContain("npm-lifecycle-script");
  });

  it("fails closed when a local entry is missing from the central directory", async () => {
    const path = await writeArtifact("hidden.zip", buildZip([
      { name: "benign.txt", body: "ok" },
      { name: "hidden.txt", body: "boom", localOnly: true }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("central directory does not list");
    expect(report.archive?.entryCount).toBe(0);
  });

  it("fails closed when central directory and local header names disagree", async () => {
    const path = await writeArtifact("renamed.zip", buildZip([
      { name: "benign.txt", body: "ok", centralName: "../evil.txt" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("name disagrees with the central directory");
  });

  it("fails closed when the central directory is missing", async () => {
    const path = await writeArtifact("headless.zip", buildZip([
      { name: "benign.txt", body: "ok" }
    ], { omitCentralDirectory: true }));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("end of central directory record not found");
  });

  it("blocks encrypted entries listed in the central directory", async () => {
    const path = await writeArtifact("crypted.zip", buildZip([
      { name: "secret.bin", body: "xxxx", encrypted: true }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("block");
    expect(report.findings.map((finding) => finding.id)).toContain("encrypted-archive-entry");
  });
});

describe("tar extended header parsing", () => {
  it("applies PAX path records before the traversal check", async () => {
    const path = await writeArtifact("pax.tar", buildTar([
      { name: "PaxHeader/evil", body: paxBody({ path: "../../etc/cron.d/x" }), typeflag: "x" },
      { name: "evil", body: "boom" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("block");
    expect(report.findings).toEqual([expect.objectContaining({
      id: "archive-path-traversal",
      location: "../../etc/cron.d/x"
    })]);
  });

  it("applies PAX global path records to following entries", async () => {
    const path = await writeArtifact("pax-global.tar", buildTar([
      { name: "PaxHeader/global", body: paxBody({ path: "/abs/path" }), typeflag: "g" },
      { name: "benign", body: "x" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.findings.map((finding) => finding.id)).toContain("archive-path-traversal");
  });

  it("applies GNU long-name headers before the traversal check", async () => {
    const path = await writeArtifact("longname.tar", buildTar([
      { name: "././@LongLink", body: "../../escape\0", typeflag: "L" },
      { name: "truncated-benign", body: "x" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("block");
    expect(report.findings).toEqual([expect.objectContaining({
      id: "archive-path-traversal",
      location: "../../escape"
    })]);
  });

  it("flags overlong PAX paths with the path-length block", async () => {
    const longPath = `dir/${"a".repeat(300)}`;
    const path = await writeArtifact("longpax.tar", buildTar([
      { name: "PaxHeader/long", body: paxBody({ path: longPath }), typeflag: "x" },
      { name: "short-name", body: "x" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.findings.map((finding) => finding.id)).toContain("archive-path-too-long");
  });

  it("fails closed on contradictory PAX and GNU long-name metadata", async () => {
    const path = await writeArtifact("contradiction.tar", buildTar([
      { name: "././@LongLink", body: "one-name\0", typeflag: "L" },
      { name: "PaxHeader/two", body: paxBody({ path: "another-name" }), typeflag: "x" },
      { name: "placeholder", body: "x" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("name metadata is contradictory");
  });

  it("fails closed on contradictory PAX size metadata", async () => {
    const path = await writeArtifact("badsize.tar", buildTar([
      { name: "PaxHeader/size", body: paxBody({ size: "9999" }), typeflag: "x" },
      { name: "small", body: "abc" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("size metadata is contradictory");
  });

  it("fails closed on an unparseable PAX extended header", async () => {
    const path = await writeArtifact("badpax.tar", buildTar([
      { name: "PaxHeader/garbage", body: "not a pax record", typeflag: "x" },
      { name: "after", body: "x" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("unparseable PAX extended header");
  });

  it("fails closed on a trailing unapplied extended header", async () => {
    const path = await writeArtifact("dangling.tar", buildTar([
      { name: "ok-file", body: "x" },
      { name: "PaxHeader/dangling", body: paxBody({ path: "../sneak" }), typeflag: "x" }
    ]));
    const report = verifyLocalTarget(path);

    expect(report.status).toBe("error");
    expect(report.errors.join("\n")).toContain("unapplied extended header");
  });
});
