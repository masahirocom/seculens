#!/usr/bin/env node
import { Command } from "commander";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import {
  scanSbom,
  parseSbom,
  fetchDatabase,
  validateDatabase,
  sha256,
  writeWordReport,
  analyze,
} from "./index.js";
import type { Policy } from "./types.js";
const cli = new Command()
  .name("seculens")
  .description("SBOM assessment and evidence-based customer reports")
  .version("0.2.0");
cli
  .command("sbom")
  .description(
    "Generate SPDX or CycloneDX JSON for an installed npm project using npm sbom",
  )
  .argument("<project>")
  .option("--format <format>", "cyclonedx or spdx", "cyclonedx")
  .requiredOption("-o, --output <file>")
  .action(async (project, opts) => {
    if (!["cyclonedx", "spdx"].includes(opts.format))
      throw new Error("Format must be cyclonedx or spdx");
    const { stdout } = await promisify(execFile)(
      process.platform === "win32" ? "npm.cmd" : "npm",
      ["sbom", `--sbom-format=${opts.format}`],
      { cwd: path.resolve(project), maxBuffer: 64 * 1024 * 1024 },
    );
    parseSbom(JSON.parse(stdout));
    await writeFile(opts.output, stdout);
    console.log(`SBOM written to ${opts.output}`);
  });
cli
  .command("scan")
  .description(
    "Scan SPDX/CycloneDX JSON with a local OSV snapshot, or fetch candidates explicitly",
  )
  .argument("<sbom>")
  .option("--db <file>", "Local OSV JSON snapshot")
  .option(
    "--fetch-osv",
    "Send package names/ecosystems to OSV and save a database snapshot",
  )
  .option("--policy <file>", "License policy JSON")
  .option("--source <directory>", "Run JS/TS AST review rules")
  .option("--customer <name>", "Customer name", "Customer")
  .option("--target <name>", "Human-readable system or project name")
  .option(
    "--report-style <style>",
    "Word layout: standard or customer",
    "standard",
  )
  .option("--issuer <name>", "Report preparer name for the customer cover", "")
  .option("--lang <language>", "Word report language: en or ja", "en")
  .option("-o, --output <directory>", "Output directory", "reports")
  .option(
    "--fail-on-findings",
    "Exit 1 for affected vulnerabilities, denied licenses or security candidates",
  )
  .action(async (file, opts) => {
    if (Boolean(opts.db) === Boolean(opts.fetchOsv))
      throw new Error("Specify exactly one of --db or --fetch-osv");
    if (!["standard", "customer"].includes(opts.reportStyle))
      throw new Error("Report style must be standard or customer");
    if (!["en", "ja"].includes(opts.lang))
      throw new Error("Language must be en or ja");
    const input = await readFile(file, "utf8");
    const sbom = parseSbom(JSON.parse(input));
    let databaseText: string, records;
    if (opts.db) {
      databaseText = await readFile(opts.db, "utf8");
      records = validateDatabase(JSON.parse(databaseText));
    } else {
      console.error(
        "Fetching OSV candidates: package names and ecosystems are sent to api.osv.dev.",
      );
      records = await fetchDatabase(sbom.components);
      databaseText = JSON.stringify({ records }, null, 2) + "\n";
    }
    let policy: Policy = {};
    if (opts.policy) {
      policy = JSON.parse(await readFile(opts.policy, "utf8"));
      if (
        !policy ||
        typeof policy !== "object" ||
        ["allow", "deny"].some(
          (k) =>
            (policy as any)[k] !== undefined &&
            (!Array.isArray((policy as any)[k]) ||
              (policy as any)[k].some((x: unknown) => typeof x !== "string")),
        )
      )
        throw new Error("Policy allow/deny must be string arrays");
    }
    const report = scanSbom(input, records, {
      customer: opts.customer,
      target: opts.target || path.basename(file),
      policy,
      databaseSource: opts.db
        ? path.basename(opts.db)
        : "OSV API candidate snapshot",
      databaseHash: sha256(databaseText),
    });
    if (opts.source) {
      report.findings.push(...(await analyze(opts.source)));
      report.sourceAnalysis = {
        language: "JavaScript/TypeScript",
        target: path.basename(path.resolve(opts.source)),
      };
    }
    await mkdir(opts.output, { recursive: true });
    await writeFile(path.join(opts.output, "sbom.json"), input);
    await writeFile(path.join(opts.output, "database.json"), databaseText);
    await writeFile(
      path.join(opts.output, "report.json"),
      JSON.stringify(report, null, 2) + "\n",
    );
    await writeWordReport(
      report,
      path.join(opts.output, "report.docx"),
      opts.lang,
      { style: opts.reportStyle, issuer: opts.issuer },
    );
    console.log(
      `${report.sbom.components.length} components; ${report.findings.length} findings; ${report.checks.filter((c) => c.status === "unassessed").length} incomplete component assessments. Reports: ${opts.output}`,
    );
    if (
      opts.failOnFindings &&
      report.findings.some(
        (f) =>
          f.status === "affected" ||
          f.status === "denied" ||
          f.category === "security",
      )
    )
      process.exitCode = 1;
    else if (report.findings.some((f) => f.status === "unassessed"))
      process.exitCode = 2;
  });
cli.parseAsync().catch((error: Error) => {
  console.error(`SecuLens: ${error.message}`);
  process.exitCode = 2;
});
