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
  references?: { type: string; url: string }[];
  affected: {
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
export interface Finding {
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
  schemaVersion: "1.0";
  tool: { name: "SecuLens"; version: "0.1.0" };
  createdAt: string;
  customer: string;
  target: string;
  sbomSha256: string;
  database: { source: string; sha256: string };
  sbom: Sbom;
  checks: Check[];
  findings: Finding[];
  limitations: string[];
}
