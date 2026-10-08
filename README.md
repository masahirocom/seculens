# SecuLens

SecuLens is a TypeScript security assessment CLI and library. It reads SPDX and CycloneDX SBOMs, independently matches component versions against OSV advisory records, evaluates license policies, reviews JavaScript/TypeScript syntax trees, and writes customer-facing Word reports.

**Version 0.1.0 is an early release.** Findings are evidence for review, not a guarantee of security or legal compliance. Python and PHP implementations are planned; this release is the independent Node.js implementation.

## Install

Requires Node.js 22 or later and npm.

```sh
npm install -g https://github.com/masahirocom/seculens/releases/download/v0.1.0/seculens-0.1.0.tgz
seculens --help
```

The GitHub release archive is available independently of npm registry publication. Once published to npm, the package name will be `seculens`.

## Assess an existing SBOM

Offline assessment with a local OSV JSON snapshot:

```sh
seculens scan sbom.json --db database.json --policy policy.json \
  --customer 'Example Customer' --lang ja --output reports
```

Download candidate advisories and match locally:

```sh
seculens scan sbom.json --fetch-osv --policy policy.json --output reports
```

`--fetch-osv` sends package names and ecosystems to `api.osv.dev`. Package versions are matched by SecuLens, not delegated to the OSV query service. Source code and the entire SBOM are not uploaded. This option requires network access; there is no network access in `--db` mode. Network failures stop the assessment instead of producing a clean result.

Every assessment saves `report.json`, `report.docx`, the original `sbom.json`, and `database.json`. Reports include database and SBOM SHA-256 digests so the evidence can be retained and reused. Replaying a snapshot stabilizes findings; report timestamps and generated DOCX metadata can differ.

## Generate an SBOM

For an npm project with its dependencies already installed:

```sh
seculens sbom ./my-project --format cyclonedx --output sbom.json
seculens sbom ./my-project --format spdx --output sbom.spdx.json
```

This invokes the existing `npm sbom` command without running installation scripts. For Python, PHP, containers or other targets, generate an SBOM with your existing tool and import it into SecuLens. npm must support `npm sbom`.

## Optional JS and TS review

```sh
seculens scan sbom.json --db database.json --source ./src --output reports
```

Rules flag direct `eval`, `new Function`, assignments to `innerHTML`/`outerHTML`, and functions exceeding cyclomatic complexity 10 or nesting depth 4. Logical `&&`, `||`, and `??` contribute to complexity. Nested functions are measured separately. Syntax errors appear as coverage findings. Generated directories and symlinks are skipped.

These are syntax-based review candidates. There is no interprocedural dataflow, type-based call resolution, exploitability determination, or Python/PHP AST analysis in this release. Shadowed names can produce candidates requiring manual review; other unsafe constructs can be missed.

## License policy

```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny": ["AGPL-3.0-only", "AGPL-3.0-or-later"]
}
```

SPDX expressions are parsed structurally. `AND` requires all branches to be allowed; `OR` accepts an allowed choice. A `WITH` exception must be explicitly allowed as the complete expression. Unknown, custom or missing licenses require review. Declared licenses are not verified against source files, distribution obligations or the customer's actual use. No policy means all licenses require review.

## Supported input and matching

- SPDX 2.2 and 2.3 JSON package records.
- CycloneDX 1.4 through 1.7 JSON component and dependency records.
- npm versions: SemVer.
- PyPI versions: PEP 440; package names are normalized.
- Packagist versions: stable numeric SemVer-compatible versions, leading `v`, four-part versions ending in `.0`, and SemVer prereleases. Composer branch aliases, nonzero fourth parts and other Composer-specific version syntax are unassessed.
- OSV `SEMVER` and `ECOSYSTEM` ranges, explicit affected versions, fixed/last-affected/limit boundaries and withdrawn records. GIT-only ranges are unassessed. Equivalent advisory aliases are merged per component.

A supported package URL (`pkg:npm`, `pkg:pypi`, `pkg:composer`) and version are required. Other ecosystems are recorded as unassessed. Input adapters validate fields used by SecuLens; they are not complete standards conformance validators. SPDX 3, XML, cryptographic attestation verification, CVSS prioritization, source license discovery, and infrastructure configuration audits are not supported yet.

“No match” means no matching advisory in the supplied snapshot, not that a component is safe. An offline snapshot must contain the relevant records; SecuLens cannot prove its completeness. A supported version range provides package-level evidence, not proof that vulnerable code is reachable.

## Exit codes

- `0`: assessment completed without incomplete coverage. Review findings may still exist.
- `1`: `--fail-on-findings` was set and affected vulnerabilities, denied licenses or security candidates exist.
- `2`: invalid input, operational failure, or incomplete coverage. With `--fail-on-findings`, detected findings take precedence over incomplete coverage.

Use the JSON report for detailed checks. Word output is English by default; `--lang ja` localizes its main headings and overview. Advisory content and technical notes retain their original language.

## Library API

```ts
import { scanSbom, validateDatabase, writeWordReport } from "seculens";

const records = validateDatabase(databaseJson);
const report = scanSbom(sbomText, records, {
  customer: "Example Customer",
  policy: { allow: ["MIT", "Apache-2.0"] },
});
await writeWordReport(report, "report.docx", "ja");
```

## Development

```sh
npm ci
npm test
npm pack
```

See [architecture and roadmap](docs/architecture.md) for the independent Python and PHP implementation plan. See [security policy](SECURITY.md) for responsible reporting.

## License

Apache-2.0. SecuLens is independent of Trivy and of the optical lens company using the SECULENS name. Advisory records retain their respective source licensing; do not assume the software license applies to downloaded database snapshots.

Japanese Word reports embed the bundled Noto Sans JP font (SIL OFL 1.1) to preserve Japanese text across viewing environments. This increases the report size by approximately 4 MB.
