import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "dist/cli.js");
const run = (values, args = [], cwd = root) =>
  spawnSync(process.execPath, [cli, ...args], {
    cwd,
    input: values.join("\n") + "\n",
    encoding: "utf8",
    timeout: 30000,
  });
const scanAnswers = (output) => [
  "",
  path.join(root, "examples/cyclonedx.json"),
  "",
  path.join(root, "examples/database.json"),
  "",
  "",
  "Example Customer",
  "Example System",
  "Example Team",
  "",
  output,
  "",
  "",
];
for (const lang of ["en", "ja"])
  test(`bare wizard ${lang} produces customer report`, () => {
    const dir = mkdtempSync(path.join(tmpdir(), "seculens-wizard-"));
    try {
      const result = run([lang === "en" ? "" : "ja", ...scanAnswers(dir)]);
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.ok(existsSync(path.join(dir, "report.docx")), result.stdout);
      const report = JSON.parse(
        readFileSync(path.join(dir, "report.json"), "utf8"),
      );
      assert.equal(report.customer, "Example Customer");
      assert.equal(report.target, "Example System");
      assert.ok(
        result.stdout.includes(
          lang === "ja" ? "設定内容の確認" : "Review your settings (en)",
        ),
      );
      assert.ok(
        result.stdout.includes(lang === "ja" ? "レポート:" : "Reports:"),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
test("invalid language, choice and path retry; cancellation creates no reports", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "seculens-cancel-"));
  try {
    const values = [
      "fr",
      "",
      "9",
      "",
      "missing.json",
      path.join(root, "examples/cyclonedx.json"),
      ...scanAnswers(path.join(dir, "absent")).slice(2),
    ];
    values[values.length - 1] = "n";
    const result = run(values);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(result.stdout.includes("Enter one of the listed choices"));
    assert.ok(result.stdout.includes("Enter an existing file path"));
    assert.ok(result.stdout.includes("Cancelled"));
    assert.ok(!existsSync(path.join(dir, "absent")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("EOF cancels instead of executing incomplete options", () => {
  const result = run([], ["wizard", "--lang", "ja"]);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.includes("中止しました"));
  assert.ok(!result.stdout.includes("Language / 言語"));
});
test("fetch and optional inputs are reviewed before cancellation", () => {
  const result = run(
    [
      "",
      path.join(root, "examples/cyclonedx.json"),
      "2",
      path.join(root, "examples/policy.json"),
      path.join(root, "examples"),
      "Client",
      "System",
      "Team",
      "2",
      "out",
      "y",
      "n",
    ],
    ["wizard", "--lang", "en"],
  );
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.includes("OSV receives package names"));
  assert.ok(result.stdout.includes("Review your settings"));
  assert.ok(result.stdout.includes("Cancelled"));
});
test("generation wizard executes npm directly with selected format", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "seculens-sbom-"));
  try {
    const output = path.join(dir, "bom.json");
    const result = run(
      ["2", root, "2", output, "y"],
      ["wizard", "--lang", "en"],
    );
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(
      JSON.parse(readFileSync(output, "utf8")).spdxVersion,
      "SPDX-2.3",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Ctrl+C cancels the wizard with exit code 130", async () => {
  const child = spawn(process.execPath, [cli], {
    cwd: root,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let output = "";
  const closed = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal }));
  });
  let interrupted = false;
  child.stdout.on("data", (chunk) => {
    output += chunk;
    if (!interrupted && output.includes("Language / 言語")) {
      interrupted = true;
      child.kill("SIGINT");
    }
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 10000);
  try {
    const result = await closed;
    assert.equal(result.code, 130, output);
    assert.ok(output.includes("Cancelled"));
  } finally {
    clearTimeout(timer);
    child.stdin.destroy();
  }
});
