export interface Component {
  id: string;
  name: string;
  version?: string;
  purl?: string;
  ecosystem?: "npm" | "PyPI" | "Packagist";
  licenses: string[];
}
export interface Sbom {
  format: "SPDX" | "CycloneDX";
  version: string;
  components: Component[];
  dependencies: { from: string; to: string }[];
  warnings: string[];
}
export interface OsvRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  withdrawn?: string;
  modified?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  references?: { type: string; url: string }[];
  affected: {
    severity?: { type: string; score: string }[];
    database_specific?: { severity?: string };
    package: { name: string; ecosystem: string; purl?: string };
    versions?: string[];
    ranges?: {
      type: string;
      events: {
        introduced?: string;
        fixed?: string;
        last_affected?: string;
        limit?: string;
      }[];
    }[];
  }[];
}
export type SeverityLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "none"
  | "unknown";
export interface SeveritySource {
  recordId: string;
  field: string;
  type: string;
  value: string;
  level: SeverityLevel;
  score?: number;
}
export interface Severity {
  level: SeverityLevel;
  score?: number;
  sources: SeveritySource[];
}
export interface Finding {
  severity?: Severity;
  category: "vulnerability" | "license" | "security" | "quality" | "coverage";
  ruleId: string;
  subject: string;
  status: "affected" | "review" | "denied" | "unassessed";
  summary: string;
  evidence: string;
  recommendation: string;
  aliases?: string[];
  references?: string[];
  file?: string;
  line?: number;
}
export interface Policy {
  allow?: string[];
  deny?: string[];
}
export interface Check {
  componentId: string;
  status: "matched" | "no-match" | "unassessed";
  recordsChecked: number;
  reason?: string;
}
export interface Report {
  schemaVersion: "1.1";
  tool: { name: "SecuLens"; version: string };
  createdAt: string;
  customer: string;
  target: string;
  sbomSha256: string;
  database: { source: string; sha256: string };
  sbom: Sbom;
  checks: Check[];
  findings: Finding[];
  sourceAnalysis?: {
    language: "Python" | "JavaScript/TypeScript" | "PHP";
    target: string;
  };
  limitations: string[];
}
