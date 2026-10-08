import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  parseSbom,
  matchRecord,
  evaluateLicense,
  scanSbom,
  analyze,
  validateDatabase,
} from "../dist/index.js";
const c = (version, ecosystem = "npm", name = "demo") => ({
  id: "demo",
  name,
  version,
  ecosystem,
  licenses: ["MIT"],
});
const record = (events, type = "SEMVER", ecosystem = "npm", name = "demo") => ({
  id: "TEST-1",
  affected: [{ package: { name, ecosystem }, ranges: [{ type, events }] }],
});
test("npm fixed boundary, disjoint ranges and inclusive last affected", () => {
  const r = record([
    { introduced: "0" },
    { fixed: "1.0.0" },
    { introduced: "2.0.0" },
    { last_affected: "2.1.0" },
  ]);
  for (const [v, want] of [
    ["0.9.0", "affected"],
    ["1.0.0", "not-affected"],
    ["1.9.0", "not-affected"],
    ["2.0.0", "affected"],
    ["2.1.0", "affected"],
    ["2.1.1", "not-affected"],
  ])
    assert.equal(matchRecord(c(v), r), want, v);
});
test("PyPI normalization and PEP440 pre-release ordering", () => {
  const r = record(
    [{ introduced: "1.0rc1" }, { fixed: "1.0" }],
    "ECOSYSTEM",
    "PyPI",
    "Demo_Package",
  );
  assert.equal(matchRecord(c("1.0rc2", "PyPI", "demo-package"), r), "affected");
  assert.equal(
    matchRecord(c("1.0", "PyPI", "demo.package"), r),
    "not-affected",
  );
});
test("Composer numeric versions and unsupported branches", () => {
  const r = record(
    [{ introduced: "0" }, { fixed: "v2.0.0" }],
    "ECOSYSTEM",
    "Packagist",
    "vendor/demo",
  );
  assert.equal(
    matchRecord(c("1.0.0.0", "Packagist", "vendor/demo"), r),
    "affected",
  );
  assert.equal(
    matchRecord(c("dev-main", "Packagist", "vendor/demo"), r),
    "unknown",
  );
});
test("withdrawn and GIT-only advisories do not become false positives or clean verdicts", () => {
  const r = record([{ introduced: "0" }]);
  assert.equal(
    matchRecord(c("1.0.0"), { ...r, withdrawn: "2020-01-01" }),
    "not-affected",
  );
  assert.equal(
    matchRecord(c("1.0.0"), record([{ introduced: "abcdef" }], "GIT")),
    "unknown",
  );
});
test("SPDX and nested CycloneDX normalize to equivalent package identities", () => {
  const a = parseSbom({
    spdxVersion: "SPDX-2.3",
    packages: [
      {
        SPDXID: "SPDXRef-demo",
        name: "wrong-display",
        versionInfo: "1.0.0",
        licenseDeclared: "MIT",
        externalRefs: [
          {
            referenceType: "purl",
            referenceLocator: "pkg:npm/%40scope/demo@1.0.0",
          },
        ],
      },
    ],
  });
  const b = parseSbom({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      {
        name: "parent",
        components: [
          {
            name: "demo",
            purl: "pkg:npm/%40scope/demo@1.0.0",
            licenses: [{ license: { id: "MIT" } }],
          },
        ],
      },
    ],
  });
  for (const key of ["name", "version", "ecosystem"])
    assert.equal(a.components[0][key], b.components[1][key]);
});
test("unsupported SBOM and duplicate refs reject rather than silently scan", () => {
  assert.throws(() => parseSbom({ spdxVersion: "SPDX-3.0", packages: [] }));
  assert.throws(() =>
    parseSbom({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [
        { name: "a", "bom-ref": "x" },
        { name: "b", "bom-ref": "x" },
      ],
    }),
  );
  assert.throws(() => validateDatabase([{ id: "bad" }]));
});
test("license AND OR WITH are evaluated without substring matching", () => {
  const p = { allow: ["MIT"], deny: ["GPL-3.0-only"] };
  assert.equal(evaluateLicense("MIT OR GPL-3.0-only", p), "allowed");
  assert.equal(evaluateLicense("MIT AND GPL-3.0-only", p), "denied");
  assert.equal(evaluateLicense("MIT WITH LLVM-exception", p), "review");
  assert.equal(evaluateLicense("NOASSERTION", p), "review");
  assert.equal(evaluateLicense("LicenseRef-Customer", p), "review");
});
test("unsupported components remain unassessed and fixed input yields fixed JSON results", () => {
  const input = JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [
      { name: "demo", version: "1.0.0", purl: "pkg:npm/demo@1.0.0" },
      { name: "unknown" },
    ],
  });
  const options = { createdAt: "2026-01-01T00:00:00Z" };
  const a = scanSbom(input, [record([{ introduced: "0" }])], options);
  assert.deepEqual(
    a,
    scanSbom(input, [record([{ introduced: "0" }])], options),
  );
  assert.equal(a.checks[0].status, "matched");
  assert.equal(a.checks[1].status, "unassessed");
});
test("AST finds candidates, ignores comments and reports syntax errors", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-"));
  await writeFile(
    path.join(dir, "sample.ts"),
    '// eval(user)\nconst s="eval(user)";\neval(user);\nnode.innerHTML=user;\nnew Function(user);',
  );
  await writeFile(path.join(dir, "broken.ts"), "const x = ;");
  const results = await analyze(dir);
  assert.equal(results.filter((f) => f.category === "security").length, 3);
  assert.equal(results.filter((f) => f.category === "coverage").length, 1);
});
test("GIT ranges do not obscure a complete ecosystem version assessment", () => {
  const r = record([{ introduced: "0" }, { fixed: "1.0.0" }]);
  r.affected[0].ranges.push({
    type: "GIT",
    events: [{ introduced: "abcdef" }],
  });
  assert.equal(matchRecord(c("2.0.0"), r), "not-affected");
});
test("transitive advisory aliases merge per component", () => {
  const input = JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [{ name: "demo", purl: "pkg:npm/demo@1.0.0" }],
  });
  const a = { ...record([{ introduced: "0" }]), id: "A", aliases: ["CVE-X"] };
  const b = { ...a, id: "B", aliases: ["CVE-X", "GHSA-X"] };
  const r = scanSbom(input, [a, b], { policy: { allow: ["MIT"] } });
  const findings = r.findings.filter((f) => f.category === "vulnerability");
  assert.equal(findings.length, 1);
  assert.deepEqual(
    [findings[0].ruleId, ...findings[0].aliases],
    ["A", "B", "CVE-X", "GHSA-X"],
  );
});
