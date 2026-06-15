import { describe, expect, it } from "vitest";
import { createStreamRedactor, redactSecrets } from "../../src/launcher/output-redaction.js";

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("redactSecrets", () => {
  it("redacts npmrc _authToken assignments", () => {
    expect(redactSecrets("//registry.npmjs.org/:_authToken=abcDEF123456")).toBe(
      "//registry.npmjs.org/:_authToken=<redacted>"
    );
  });

  it("redacts npmrc _auth assignments", () => {
    expect(redactSecrets("_auth=dXNlcjpwYXNz")).toBe("_auth=<redacted>");
  });

  it("redacts npmrc _password assignments", () => {
    expect(redactSecrets("_password=hunter2hunter2")).toBe("_password=<redacted>");
  });

  it("redacts a bearer token of sufficient length", () => {
    expect(redactSecrets("Bearer abcdef123456")).toBe("Bearer <redacted>");
  });

  it("redacts an npm_ token of canonical shape", () => {
    const token = `npm_${"A".repeat(18)}${"9".repeat(18)}`;
    expect(token.length).toBe(40);
    expect(redactSecrets(`set ${token} done`)).toBe("set <redacted> done");
  });

  it("redacts a ghp_ personal access token", () => {
    const token = `ghp_${"a".repeat(40)}`;
    expect(redactSecrets(`x ${token} y`)).toBe("x <redacted> y");
  });

  it("redacts a known-shape token immediately followed by an underscore-word (output-redaction low)", () => {
    const token = `npm_${"A".repeat(18)}${"9".repeat(18)}`;
    expect(redactSecrets(`${token}_ci`)).toBe("<redacted>_ci");
  });

  it("redacts a pypi- token", () => {
    const token = "pypi-AgEIcGkAY2ZmZmZmZmYx";
    expect(token.length).toBeGreaterThanOrEqual(25);
    expect(redactSecrets(`use ${token} here`)).toBe("use <redacted> here");
  });

  it("redacts token assignments and authorization headers together", () => {
    expect(
      redactSecrets("token=abc123 authorization: Basic Zm9vOmJhcg==")
    ).toBe("token=<redacted> authorization: <redacted>");
  });

  it("redacts credential URLs without touching the rest", () => {
    expect(redactSecrets("clone https://user:secret@example.test/repo.git now")).toBe(
      "clone https://<redacted>@example.test/repo.git now"
    );
  });

  it("leaves plain prose untouched", () => {
    const plain = "added 12 packages in 3s, audited 1 package, found 0 vulnerabilities";
    expect(redactSecrets(plain)).toBe(plain);
  });

  it("leaves a short bearer fragment untouched", () => {
    expect(redactSecrets("Bearer ok")).toBe("Bearer ok");
  });

  it("redacts access_token, secret_key and aws_secret_access_key assignments", () => {
    expect(redactSecrets("access_token=abc123def")).toBe("access_token=<redacted>");
    expect(redactSecrets("secret_key=abc123def")).toBe("secret_key=<redacted>");
    expect(redactSecrets("aws_secret_access_key=wJalrXUtnFEMI")).toBe("aws_secret_access_key=<redacted>");
  });

  it("redacts assignment keys whose boundary is an underscore", () => {
    expect(redactSecrets("GITHUB_TOKEN=ghs_value123")).toBe("GITHUB_TOKEN=<redacted>");
    expect(redactSecrets("my_token=abc123")).toBe("my_token=<redacted>");
    expect(redactSecrets("client_secret=abc123")).toBe("client_secret=<redacted>");
    expect(redactSecrets("api_key=abc123")).toBe("api_key=<redacted>");
  });

  it("redacts JSON colon-form secrets while preserving line structure", () => {
    expect(redactSecrets('{"token":"abc123","name":"pkg"}')).toBe('{"token":"<redacted>","name":"pkg"}');
    expect(redactSecrets('"_authToken":"npm_abc123"')).toBe('"_authToken":"<redacted>"');
    expect(redactSecrets('"aws_secret_access_key": "wJalrXUtnFEMI"')).toBe('"aws_secret_access_key": "<redacted>"');
    expect(redactSecrets('"password" : "hunter2"')).toBe('"password" : "<redacted>"');
  });

  it("redacts GitLab and Slack token shapes", () => {
    expect(redactSecrets(`push glpat-${"A".repeat(20)} done`)).toBe("push <redacted> done");
    expect(redactSecrets("xoxb-123456789012-abcdefghij")).toBe("<redacted>");
    expect(redactSecrets("use xoxp-987654321098-zyxwvutsrq here")).toBe("use <redacted> here");
  });

  it("leaves non-secret lookalikes untouched", () => {
    expect(redactSecrets("max_tokens=4096")).toBe("max_tokens=4096");
    expect(redactSecrets('"tokenizer":"bert-base"')).toBe('"tokenizer":"bert-base"');
    expect(redactSecrets("monkey=banana")).toBe("monkey=banana");
    expect(redactSecrets("glpat-short")).toBe("glpat-short");
    expect(redactSecrets("xoxb-short")).toBe("xoxb-short");
  });
});

describe("createStreamRedactor", () => {
  it("redacts a secret split across two write chunks", () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("token=sec");
    redactor.write("ret\n");

    const joined = out.join("");
    expect(joined).toBe("token=<redacted>\n");
    expect(joined).not.toContain("secret");
  });

  it("redacts carriage-return progress segments", () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("token=aaa\rtoken=bbb\r");

    const joined = out.join("");
    expect(joined).toBe("token=<redacted>\rtoken=<redacted>\r");
    expect(joined).not.toContain("aaa");
    expect(joined).not.toContain("bbb");
  });

  it("emits a redacted partial line on flush", () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("trailing _authToken=zzzTOPSECRET");
    expect(out.join("")).toBe("");

    redactor.flush();

    const joined = out.join("");
    expect(joined).toBe("trailing _authToken=<redacted>");
    expect(joined).not.toContain("zzzTOPSECRET");
  });

  it("flushes a newline-less prompt redacted after the quiet timer", async () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("enter token=promptSecret ? ");
    expect(out.join("")).toBe("");

    await delay(120);

    const joined = out.join("");
    expect(joined).toBe("enter token=<redacted> ? ");
    expect(joined).not.toContain("promptSecret");
  });

  it("never leaks a secret tail that dribbles across the quiet timer", async () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("login token=ab");
    await delay(120);
    expect(out.join("")).not.toContain("token=ab");
    redactor.write("c");
    await delay(120);
    expect(out.join("")).not.toContain("abc");
    await delay(120);

    const joined = out.join("");
    expect(joined).not.toContain("abc");
    expect(joined).not.toContain("token=ab");
    expect(joined).toBe("login token=<redacted>");
  });

  it("holds an underscore-keyed secret tail that dribbles across the quiet timer", async () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("export access_token=par");
    await delay(120);
    expect(out.join("")).not.toContain("access_token=par");

    redactor.write("tial\n");

    const joined = out.join("");
    expect(joined).toBe("export access_token=<redacted>\n");
    expect(joined).not.toContain("partial");
  });

  it("releases a held secret tail after a second quiet timer with no new data", async () => {
    const out: string[] = [];
    const redactor = createStreamRedactor((chunk) => out.push(chunk));

    redactor.write("prefix npm_");
    await delay(300);

    const joined = out.join("");
    expect(joined).toBe("prefix npm_");
    expect(joined).not.toContain("npm_abc");
  });

  it("stays linear on a multi-megabyte unbroken blob", () => {
    const blob = "a".repeat(2 * 1024 * 1024);
    const started = performance.now();
    const result = redactSecrets(blob);
    const elapsed = performance.now() - started;
    expect(result).toBe(blob);
    expect(elapsed).toBeLessThan(5000);
  });

  it("still redacts credential urls with a bounded scheme", () => {
    expect(redactSecrets("fetch https://user:hunter2@registry.example/pkg.tgz")).toBe(
      "fetch https://<redacted>@registry.example/pkg.tgz"
    );
    expect(redactSecrets(`${"x".repeat(64)}://user:pw@host/`)).toContain("user");
  });

  it("redacts modern bare token formats", () => {
    const tokens = [
      `github_pat_${"A".repeat(22)}_${"b".repeat(20)}`,
      `hf_${"a".repeat(34)}`,
      "AKIAIOSFODNN7EXAMPLE",
      `AIza${"b".repeat(35)}`,
      `sk_live_${"a".repeat(24)}`,
      `sk-proj-${"A".repeat(24)}`,
      `xoxa-${"1".repeat(12)}`,
    ];
    for (const token of tokens) {
      expect(redactSecrets(`leak: ${token} here`)).toBe("leak: <redacted> here");
    }
  });

  it("redacts colon-form secret assignments (YAML / KEY: value)", () => {
    expect(redactSecrets("api_key: correcthorsebattery")).toBe("api_key: <redacted>");
    expect(redactSecrets("  client_secret: aBcDeFgHiJ")).toBe("  client_secret: <redacted>");
    expect(redactSecrets('MY_TOKEN: "swordfish123"')).toBe('MY_TOKEN: "<redacted>"');
    expect(redactSecrets("PASSWORD=hunter2hunter2")).toBe("PASSWORD=<redacted>");
  });

  it("does not redact a benign colon phrase without a value-like token", () => {
    expect(redactSecrets("Note: review the policy later")).toBe("Note: review the policy later");
  });
});
