# SecuLens

[English](README.md) | [日本語](README.jp.md)

SecuLens is a TypeScript security assessment CLI and library. It reads SPDX and CycloneDX SBOMs, independently matches component versions against OSV advisory records, evaluates license policies, reviews JavaScript/TypeScript syntax trees, and writes customer-facing Word reports.

**Version 0.3.1 is an early release.** Findings are evidence for review, not a guarantee of security or legal compliance. The independent Python implementation is available at https://github.com/masahiroid/seculens-python; PHP is planned.

## Interactive wizard

Run `seculens` with no arguments to start interactive setup. English is the default: press Enter at the language prompt, or type `ja` for Japanese. Use `seculens wizard --lang ja` to open Japanese setup directly.

```sh
seculens
# or
seculens wizard --lang ja
```

Choose an existing SBOM assessment or SBOM generation, then supply the requested paths and options. Assessment asks for a local OSV snapshot or explicit OSV fetching, an optional license policy and source directory, customer / target / preparer, report style, output directory and findings exit policy. Customer report layout is the wizard default. Review the settings and confirm to start. EOF or choosing `n` at the final prompt cancels; Ctrl+C interrupts. OSV fetching sends package names and ecosystems; the wizard displays this before execution.


## Install

Requires Node.js 22 or later and npm.

```sh
npm install -g seculens
seculens --help
```

Release archives are also available from [GitHub releases](https://github.com/masahiroid/seculens/releases).

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

A supported package URL (`pkg:npm`, `pkg:pypi`, `pkg:composer`) and version are required. Other ecosystems are recorded as unassessed. Input adapters validate fields used by SecuLens; they are not complete standards conformance validators. SPDX 3, XML, cryptographic attestation verification, customer-specific risk prioritization, source license discovery, and infrastructure configuration audits are not supported yet.

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

## Customer report mode

Add `--report-style customer` to generate a formal Word report with a dedicated cover, executive summary, severity colors, a prioritized findings register, numbered details, component coverage tables, evidence hashes and page numbers. Existing standard layout remains available with `--report-style standard` (the default).

```sh
seculens scan bom.json --db database.json --policy policy.json \
  --customer "Customer Company" --target "Customer Web Service" \
  --issuer "Security Assessment Team" --lang ja \
  --report-style customer --output reports/customer
```

`--target` supplies a human-readable system name; it defaults to the SBOM filename. `--issuer` supplies the cover's preparer and document author. Both are optional. The report ID incorporates the SBOM hash, DB hash and assessment timestamp. Finding numbers link the register to details; code/license review statuses are separate from vulnerability severity.

Severity colors: Critical / High red, Medium amber, Low blue, None green, Unrated gray. Labels accompany colors for accessibility. Vulnerability counts consolidate aliases per component; category counts include review candidates. CVSS zero / None is a severity band, not proof of absence of vulnerabilities.

Severity comes from validated CVSS 3.0/3.1 base vectors or recognized `database_specific.severity` labels. Package-specific OSV `affected.severity` overrides global vectors for that affected entry. Alias consolidation preserves all provenance and displays the highest supported severity; when sources disagree, the underlying labels/vectors and scores remain available in JSON. CVSS 2/4 vectors and malformed vectors are not calculated. Without other usable metadata these stay Unrated. No severity is inferred from advisory wording, AST review candidates or licenses.

Report JSON schema 1.1 adds optional vulnerability `severity` (level, optional base score, and source record IDs / field paths / raw values) and optional CLI `sourceAnalysis` execution metadata. Presentation sorting does not alter the assessment JSON. Word contains concise severity attribution; full original metadata and references stay in JSON. This mode changes presentation and adds severity evidence, not the vulnerability matching criteria.

Scoring reference: https://www.first.org/cvss/v3.1/specification-document
OSV field reference: https://ossf.github.io/osv-schema/

```js
await writeWordReport(report, "customer.docx", "ja", {
  style: "customer",
  issuer: "Assessment Team",
});
```
