import { recordSeverity, mergeSeverity } from "./severity.js";
import { createHash } from "node:crypto";
import { parseSbom } from "./sbom.js";
import { matchRecord, samePackage, supportedVersion } from "./matcher.js";
import { licenseFindings } from "./licenses.js";
import type { Report, OsvRecord, Policy } from "./types.js";
export * from "./types.js";
export { parseSbom } from "./sbom.js";
export { matchRecord } from "./matcher.js";
export { evaluateLicense } from "./licenses.js";
export { fetchDatabase, validateDatabase } from "./database.js";
export { analyze } from "./analysis.js";
export { writeWordReport } from "./word.js";
export const sha256 = (text: string) =>
  createHash("sha256").update(text).digest("hex");
export function scanSbom(
  input: string,
  records: OsvRecord[],
  options: {
    customer?: string;
    target?: string;
    policy?: Policy;
    databaseSource?: string;
    databaseHash?: string;
    createdAt?: string;
  } = {},
): Report {
  const sbom = parseSbom(JSON.parse(input));
  const report: Report = {
    schemaVersion: "1.1",
    tool: { name: "SecuLens", version: "0.2.0" },
    createdAt: options.createdAt || new Date().toISOString(),
    customer: options.customer || "Customer",
    target: options.target || "SBOM",
    sbomSha256: sha256(input),
    database: {
      source: options.databaseSource || "OSV snapshot",
      sha256: options.databaseHash || sha256(JSON.stringify(records)),
    },
    sbom,
    checks: [],
    findings: [],
    limitations: [
      "No match means no matching record in the supplied database snapshot, not absence of vulnerabilities.",
      "License policy checks are not a legal compliance determination.",
      "AST rules identify review candidates and complexity, not proven exploitability.",
      "SBOM content and package identifiers are supplied by the generating tool.",
      "Packagist matching supports stable numeric versions and SemVer prereleases only; Composer branches and other version forms may be unassessed.",
    ],
  };
  for (const c of sbom.components) {
    report.findings.push(...licenseFindings(c, options.policy || {}));
    if (!supportedVersion(c)) {
      const reason = !c.ecosystem
        ? "Supported package URL required (npm, pypi or composer)"
        : !c.version
          ? "Package version is missing"
          : "Unsupported package version syntax";
      report.checks.push({
        componentId: c.id,
        status: "unassessed",
        recordsChecked: 0,
        reason,
      });
      report.findings.push({
        category: "coverage",
        ruleId: "PACKAGE-IDENTITY",
        subject: c.id,
        status: "unassessed",
        summary: "Component could not be assessed",
        evidence: reason,
        recommendation:
          "Regenerate the SBOM with complete package URLs and versions.",
      });
      continue;
    }
    const candidates = records.filter((r) =>
      r.affected.some((a) => samePackage(c, a.package)),
    );
    let matched = false,
      uncertain = false;
    for (const r of candidates) {
      const result = matchRecord(c, r);
      if (result === "not-affected") continue;
      if (result === "unknown") {
        uncertain = true;
        report.findings.push({
          category: "coverage",
          ruleId: r.id,
          subject: c.id,
          status: "unassessed",
          summary: "Advisory could not be fully evaluated",
          evidence: `${c.name}@${c.version}; unsupported or incomplete version range`,
          recommendation: "Review the advisory and package version manually.",
        });
        continue;
      }
      matched = true;
      report.findings.push({
        category: "vulnerability",
        ruleId: r.id,
        subject: c.id,
        status: "affected",
        summary: r.summary || r.id,
        evidence: `${c.ecosystem}:${c.name}@${c.version}; matched against affected versions/ranges in ${r.id}`,
        recommendation:
          "Review the advisory references for a fixed version and validate the upgrade.",
        severity: recordSeverity(r, c),
        aliases: r.aliases || [],
        references: (r.references || []).map((x) => x.url),
      });
    }
    report.checks.push({
      componentId: c.id,
      status: uncertain ? "unassessed" : matched ? "matched" : "no-match",
      recordsChecked: candidates.length,
      reason: uncertain
        ? "One or more candidate records require manual review"
        : undefined,
    });
  }
  // Merge advisory aliases per component; keep all source identifiers and evidence.
  const groups: typeof report.findings = [];
  for (const finding of report.findings) {
    if (finding.category !== "vulnerability") {
      groups.push(finding);
      continue;
    }
    let merged = {
      ...finding,
      aliases: [...(finding.aliases || [])],
      references: [...(finding.references || [])],
    };
    let changed = true;
    while (changed) {
      changed = false;
      for (let i = groups.length - 1; i >= 0; i--) {
        const other = groups[i];
        if (
          other.category !== "vulnerability" ||
          other.subject !== merged.subject
        )
          continue;
        const ids = new Set([merged.ruleId, ...(merged.aliases || [])]);
        if (![other.ruleId, ...(other.aliases || [])].some((id) => ids.has(id)))
          continue;
        const all = [
          ...new Set([
            merged.ruleId,
            ...merged.aliases!,
            other.ruleId,
            ...(other.aliases || []),
          ]),
        ].sort();
        merged = {
          ...merged,
          severity: mergeSeverity(merged.severity!, other.severity!),
          ruleId: all[0],
          aliases: all.slice(1),
          references: [
            ...new Set([...merged.references!, ...(other.references || [])]),
          ].sort(),
          evidence: [merged.evidence, other.evidence].sort().join(" | "),
        };
        groups.splice(i, 1);
        changed = true;
      }
    }
    groups.push(merged);
  }
  report.findings = groups.sort((a, b) =>
    [a.category, a.subject, a.ruleId]
      .join(":")
      .localeCompare([b.category, b.subject, b.ruleId].join(":")),
  );
  return report;
}
