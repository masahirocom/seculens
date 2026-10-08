import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { inflateRawSync } from "node:zlib";
import { cvss3Base, recordSeverity } from "../dist/severity.js";
import { orderedFindings } from "../dist/customer-report.js";
import { scanSbom, writeWordReport } from "../dist/index.js";
const vectors = [
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
  ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10],
  ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1],
  ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
];
test("CVSS reference values, base-only temporal suffix and invalid inputs", () => {
  for (const [vector, score] of vectors) {
    assert.equal(cvss3Base(vector), score);
    assert.equal(cvss3Base(vector + "/E:U/RL:O/RC:R"), score);
  }
  for (const value of [
    undefined,
    "9.8",
    "CVSS:4.0/AV:N",
    "CVSS:3.1/AV:N",
    vectors[0][0] + "/AV:L",
    vectors[0][0].replace("AC:L", "AC:INVALID"),
    vectors[0][0] + "/E:INVALID",
  ])
    assert.equal(cvss3Base(value), undefined);
});
const base = {
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [
        { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
      ],
    },
  ],
};
const records = () => [
  {
    ...structuredClone(base),
    id: "TEST-HIGH",
    database_specific: { severity: "HIGH" },
  },
  {
    ...structuredClone(base),
    id: "TEST-CRITICAL",
    severity: [{ type: "CVSS_V3", score: vectors[0][0] }],
  },
  {
    ...structuredClone(base),
    id: "TEST-UNRATED",
    severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N" }],
  },
];
test("affected severity overrides global vectors, not unrelated packages", () => {
  const r = records()[1];
  r.affected[0].severity = [{ type: "CVSS_V3", score: vectors[3][0] }];
  const other = structuredClone(r.affected[0]);
  other.package.name = "unrelated";
  other.severity[0].score = vectors[0][0];
  r.affected.push(other);
  const result = recordSeverity(r, {
    name: "lodash",
    version: "4.17.20",
    ecosystem: "npm",
  });
  assert.equal(result.level, "medium");
  assert.equal(result.score, 5.3);
  assert.equal(result.sources[0].field, "affected[0].severity[0]");
});
test("alias merge retains highest severity and all evidence", async () => {
  const r = records();
  r[0].aliases = ["TEST-CRITICAL"];
  const report = scanSbom(await readFile("examples/cyclonedx.json", "utf8"), r);
  const findings = report.findings.filter(
    (f) => f.category === "vulnerability",
  );
  assert.equal(findings.length, 2);
  const merged = findings.find((f) => f.severity.level === "critical");
  assert.equal(merged.severity.score, 9.8);
  assert.deepEqual(merged.severity.sources.map((s) => s.recordId).sort(), [
    "TEST-CRITICAL",
    "TEST-HIGH",
  ]);
});
// Read actual OOXML using ZIP central records, including data-descriptor archives.
function zipEntry(buffer, name) {
  let offset = 0;
  while (offset < buffer.length - 46) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) {
      offset++;
      continue;
    }
    const length = buffer.readUInt16LE(offset + 28),
      extra = buffer.readUInt16LE(offset + 30),
      comment = buffer.readUInt16LE(offset + 32);
    const filename = buffer
      .subarray(offset + 46, offset + 46 + length)
      .toString();
    if (filename === name) {
      const local = buffer.readUInt32LE(offset + 42),
        start =
          local +
          30 +
          buffer.readUInt16LE(local + 26) +
          buffer.readUInt16LE(local + 28);
      const bytes = buffer.subarray(
        start,
        start + buffer.readUInt32LE(offset + 20),
      );
      return (
        buffer.readUInt16LE(offset + 10) === 8 ? inflateRawSync(bytes) : bytes
      ).toString();
    }
    offset += 46 + length + extra + comment;
  }
  throw new Error("Missing ZIP entry " + name);
}
test("customer Word has cover, sorted register, color/labels, repeated headers and page footer", async () => {
  const report = scanSbom(
    await readFile("examples/cyclonedx.json", "utf8"),
    records(),
    { policy: { allow: ["MIT", "Apache-2.0"] } },
  );
  const before = JSON.stringify(report);
  assert.deepEqual(
    orderedFindings(report).map((f) => f.severity.level),
    ["critical", "high", "unknown"],
  );
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-customer-"));
  for (const language of ["ja", "en"]) {
    const file = path.join(dir, language + ".docx");
    await writeWordReport(report, file, language, {
      style: "customer",
      issuer: "Example Security Team",
    });
    const buffer = await readFile(file);
    const xml = zipEntry(buffer, "word/document.xml");
    assert.ok(xml.includes("Example Security Team"));
    assert.ok(xml.includes("F-001"));
    assert.ok(xml.includes('w:fill="FEE2E2"'));
    assert.ok(xml.includes('w:color w:val="991B1B"'));
    assert.ok(xml.includes("w:tblHeader"));
    assert.ok(xml.includes("w:cantSplit"));
    assert.ok(xml.includes("w:titlePg"));
    assert.ok(xml.includes(language === "ja" ? "未評価" : "Unrated"));
    assert.ok(
      ["word/footer1.xml", "word/footer2.xml"].some((name) =>
        zipEntry(buffer, name).includes("PAGE"),
      ),
    );
  }
  assert.equal(JSON.stringify(report), before);
  await assert.rejects(
    writeWordReport(report, path.join(dir, "bad.docx"), "en", {
      style: "invalid",
    }),
  );
});
test("empty customer report retains limitations and no safe claim", async () => {
  const r = scanSbom(
    JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [],
    }),
    [],
  );
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-empty-"));
  const file = path.join(dir, "report.docx");
  await writeWordReport(r, file, "en", { style: "customer" });
  const xml = zipEntry(await readFile(file), "word/document.xml");
  assert.ok(xml.includes("No findings were recorded"));
  assert.ok(xml.includes("not absence of vulnerabilities"));
});
test("mixed affected entries each use their effective severity", () => {
  const r = records()[1];
  r.affected[0].severity = [{ type: "CVSS_V3", score: vectors[3][0] }];
  const other = structuredClone(r.affected[0]);
  delete other.severity;
  r.affected.push(other);
  const result = recordSeverity(r, {
    name: "lodash",
    version: "4.17.20",
    ecosystem: "npm",
  });
  assert.equal(result.level, "critical");
  assert.deepEqual(result.sources.map((s) => s.field).sort(), [
    "affected[0].severity[0]",
    "severity[0]",
  ]);
});
