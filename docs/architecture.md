# SecuLens architecture

The Node.js/TypeScript implementation is the reference implementation for release 0.1.0. The [Python](https://github.com/masahiroid/seculens-python) and [PHP](https://github.com/masahiroid/seculens-php) implementations run independently and share the report contract and assessment fixtures. They do not depend on a Python runtime or remote assessment service.

## Processing

1. Read an existing SPDX or CycloneDX JSON SBOM, or generate one through npm.
2. Normalize package URLs, identities, licenses and dependency edges.
3. Load an OSV snapshot or explicitly download candidates without a version filter.
4. Match versions locally, preserving unknown coverage.
5. Evaluate license expressions against an explicit customer policy.
6. Optionally apply JS/TS AST review rules.
7. Save a versioned JSON result, evidence snapshots and a Word document.

Input and DB hashes bind the report to exact evidence. Matching uses version semantics per ecosystem; it never substitutes string comparison. Advisory alias sets merge duplicates per component. Unsupported inputs remain unassessed. The tool does not execute analyzed source code.

## Cross-language contract

All implementations should preserve schemaVersion 1.0 report concepts: components, dependency edges, checks, findings, database identity, coverage limitations. Use the same advisory fixtures and boundary cases to establish parity. CLI timestamps may differ, but findings should agree for identical inputs, policy and DB snapshots.

## Next releases

- Formal JSON Schema and full SPDX/CycloneDX conformance validation.
- Broader Composer version semantics and test corpus.
- CVSS and customer-context prioritization with explicit provenance.
- Report templates, reviewer notes, waivers, remediation and baseline diffs.
- Extend native AST analyzers with dataflow and framework-aware review rules.
- Dataflow-based security rules with documented framework coverage.
- Broader OS package/vendor advisories and configurable DB providers.
- Schema-aware SPDX 3 and XML adapters.

No published release should claim Trivy feature parity. The first release focuses on auditable SBOM assessment and reporting.

See the README customer report mode section for severity evidence and layout options.
