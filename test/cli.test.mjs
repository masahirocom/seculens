import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
const exec = promisify(execFile);
test("CLI generates real Word ZIP and reports vulnerability exit policy", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-cli-"));
  await exec(process.execPath, [
    "dist/cli.js",
    "scan",
    "examples/spdx.json",
    "--db",
    "examples/database.json",
    "--policy",
    "examples/policy.json",
    "--output",
    dir,
  ]);
  const bytes = await readFile(path.join(dir, "report.docx"));
  assert.equal(bytes.subarray(0, 2).toString(), "PK");
  const report = JSON.parse(
    await readFile(path.join(dir, "report.json"), "utf8"),
  );
  assert.equal(report.sbom.components.length, 3);
  assert.equal(
    report.findings.filter((f) => f.category === "vulnerability").length,
    1,
  );
  await assert.rejects(
    exec(process.execPath, [
      "dist/cli.js",
      "scan",
      "examples/spdx.json",
      "--db",
      "examples/database.json",
      "--output",
      dir,
      "--fail-on-findings",
    ]),
    (e) => e.code === 1,
  );
});
test("CLI rejects ambiguous DB options before producing a report", async () => {
  await assert.rejects(
    exec(process.execPath, [
      "dist/cli.js",
      "scan",
      "examples/spdx.json",
      "--db",
      "examples/database.json",
      "--fetch-osv",
    ]),
    (e) => e.code === 2 && e.stderr.includes("exactly one"),
  );
});
test("CLI returns incomplete coverage for unsupported package identity", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "seculens-coverage-"));
  const sbom = path.join(dir, "input.json");
  await writeFile(
    sbom,
    JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      components: [{ name: "unknown" }],
    }),
  );
  await assert.rejects(
    exec(process.execPath, [
      "dist/cli.js",
      "scan",
      sbom,
      "--db",
      "examples/database.json",
      "--output",
      path.join(dir, "reports"),
    ]),
    (e) => e.code === 2,
  );
  const report = JSON.parse(
    await readFile(path.join(dir, "reports/report.json"), "utf8"),
  );
  assert.equal(report.checks[0].status, "unassessed");
});
