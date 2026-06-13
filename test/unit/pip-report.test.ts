import { describe, expect, it } from "vitest";
import { parsePipReportInstallCount, parsePipReportInstallSet } from "../../src/launcher/pip-report.js";

describe("parsePipReportInstallCount", () => {
  it("returns the length of the install array from a pip --report document", () => {
    const report = JSON.stringify({
      version: "1",
      install: [
        { metadata: { name: "scikit-learn" } },
        { metadata: { name: "scipy" } },
        { metadata: { name: "numpy" } }
      ]
    });
    expect(parsePipReportInstallCount(report)).toBe(3);
  });

  it("tolerates leading non-JSON noise before the report object", () => {
    const report = "Using cached index\n" + JSON.stringify({ install: [{}, {}] });
    expect(parsePipReportInstallCount(report)).toBe(2);
  });

  it("counts an empty install set as zero", () => {
    expect(parsePipReportInstallCount(JSON.stringify({ install: [] }))).toBe(0);
  });

  it("returns undefined for empty, non-JSON, or shapeless output", () => {
    expect(parsePipReportInstallCount("")).toBeUndefined();
    expect(parsePipReportInstallCount("not json at all")).toBeUndefined();
    expect(parsePipReportInstallCount(JSON.stringify({ version: "1" }))).toBeUndefined();
  });
});

describe("parsePipReportInstallSet", () => {
  it("returns name+version for each install entry", () => {
    const report = JSON.stringify({
      install: [
        { metadata: { name: "scikit-learn", version: "1.9.0" } },
        { metadata: { name: "scipy", version: "1.17.1" } }
      ]
    });
    expect(parsePipReportInstallSet(report)).toEqual([
      { name: "scikit-learn", version: "1.9.0" },
      { name: "scipy", version: "1.17.1" }
    ]);
  });

  it("skips entries missing a name or version", () => {
    const report = JSON.stringify({
      install: [{ metadata: { name: "a", version: "1" } }, { download_info: {} }, { metadata: { name: "b" } }]
    });
    expect(parsePipReportInstallSet(report)).toEqual([{ name: "a", version: "1" }]);
  });

  it("returns undefined for non-report output", () => {
    expect(parsePipReportInstallSet("not json")).toBeUndefined();
  });
});
