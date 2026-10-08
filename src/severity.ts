/** Traceable OSV severity. CVSS 3.0/3.1 base scores use FIRST's Roundup. */
import { matchRecord, samePackage } from "./matcher.js";
import type {
  Component,
  OsvRecord,
  Severity,
  SeverityLevel,
  SeveritySource,
} from "./types.js";
export const LEVELS: SeverityLevel[] = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "unknown",
];
export function cvss3Base(vector: unknown): number | undefined {
  if (typeof vector !== "string" || !/^CVSS:3\.[01]\//.test(vector))
    return undefined;
  const allowed: Record<string, string> = {
    AV: "NALP",
    AC: "LH",
    PR: "NLH",
    UI: "NR",
    S: "UC",
    C: "NLH",
    I: "NLH",
    A: "NLH",
    E: "XUPFH",
    RL: "XOTWU",
    RC: "XURC",
    CR: "XLMH",
    IR: "XLMH",
    AR: "XLMH",
    MAV: "XNALP",
    MAC: "XLH",
    MPR: "XNLH",
    MUI: "XNR",
    MS: "XUC",
    MC: "XNLH",
    MI: "XNLH",
    MA: "XNLH",
  };
  const metrics: Record<string, string> = {};
  for (const token of vector.split("/").slice(1)) {
    const pair = token.split(":");
    const [key, value] = pair;
    if (
      pair.length !== 2 ||
      Object.hasOwn(metrics, key) ||
      !Object.hasOwn(allowed, key) ||
      value.length !== 1 ||
      !allowed[key].includes(value)
    )
      return undefined;
    metrics[key] = value;
  }
  if (
    !["AV", "AC", "PR", "UI", "S", "C", "I", "A"].every((k) =>
      Object.hasOwn(metrics, k),
    )
  )
    return undefined;
  const weight: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };
  const iss =
    1 -
    ["C", "I", "A"].reduce((value, k) => value * (1 - weight[metrics[k]]), 1);
  const changed = metrics.S === "C";
  const impact = changed
    ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const av = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as Record<string, number>)[
    metrics.AV
  ];
  const ac = metrics.AC === "L" ? 0.77 : 0.44;
  const pr = (
    { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 } as Record<
      string,
      number
    >
  )[metrics.PR];
  const ui = metrics.UI === "N" ? 0.85 : 0.62;
  const value = Math.min(
    (impact + 8.22 * av * ac * pr * ui) * (changed ? 1.08 : 1),
    10,
  );
  const integer = Math.floor(value * 100000 + 0.5);
  return integer % 10000 === 0
    ? integer / 100000
    : (Math.floor(integer / 10000) + 1) / 10;
}
function scoreLevel(score: number): SeverityLevel {
  return score >= 9
    ? "critical"
    : score >= 7
      ? "high"
      : score >= 4
        ? "medium"
        : score > 0
          ? "low"
          : "none";
}
export function mergeSeverity(...values: Severity[]): Severity {
  const sources = [
    ...new Map(
      values.flatMap((v) => v.sources).map((s) => [JSON.stringify(s), s]),
    ).values(),
  ].sort((a, b) =>
    a.recordId < b.recordId
      ? -1
      : a.recordId > b.recordId
        ? 1
        : a.field < b.field
          ? -1
          : a.field > b.field
            ? 1
            : a.value < b.value
              ? -1
              : a.value > b.value
                ? 1
                : 0,
  );
  const level =
    sources
      .map((s) => s.level)
      .sort((a, b) => LEVELS.indexOf(a) - LEVELS.indexOf(b))[0] || "unknown";
  const scores = sources
    .filter((s) => s.level === level && s.score !== undefined)
    .map((s) => s.score!);
  return {
    level,
    sources,
    ...(scores.length ? { score: Math.max(...scores) } : {}),
  };
}
export function recordSeverity(
  record: OsvRecord,
  component: Component,
): Severity {
  const sources: SeveritySource[] = [];
  const applicable = record.affected
    .map((a, i) => ({ a, i }))
    .filter(
      ({ a }) =>
        samePackage(component, a.package) &&
        matchRecord(component, { ...record, affected: [a] }) === "affected",
    );
  const entries = applicable.length
    ? applicable.map(({ a, i }) =>
        Array.isArray(a.severity) && a.severity.length
          ? { field: `affected[${i}].severity`, items: a.severity }
          : { field: "severity", items: record.severity || [] },
      )
    : [{ field: "severity", items: record.severity || [] }];
  for (const { field, items } of entries) {
    if (!Array.isArray(items)) continue;
    for (const [index, entry] of items.entries()) {
      if (!entry || typeof entry.score !== "string") continue;
      const score =
        entry.type === "CVSS_V3" ? cvss3Base(entry.score) : undefined;
      sources.push({
        recordId: record.id,
        field: `${field}[${index}]`,
        type: entry.type || "unknown",
        value: entry.score,
        level: score !== undefined ? scoreLevel(score) : "unknown",
        ...(score !== undefined ? { score } : {}),
      });
    }
  }
  const labels = [
    { field: "database_specific.severity", data: record.database_specific },
    ...applicable.map(({ a, i }) => ({
      field: `affected[${i}].database_specific.severity`,
      data: a.database_specific,
    })),
  ];
  const mapping: Record<string, SeverityLevel> = {
    CRITICAL: "critical",
    HIGH: "high",
    MODERATE: "medium",
    MEDIUM: "medium",
    LOW: "low",
    NONE: "none",
  };
  for (const { field, data } of labels) {
    const value = data?.severity;
    if (typeof value === "string")
      sources.push({
        recordId: record.id,
        field,
        type: "database_label",
        value,
        level: mapping[value.toUpperCase()] || "unknown",
      });
  }
  return mergeSeverity({ level: "unknown", sources });
}
