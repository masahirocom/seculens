import {
  Document,
  Packer,
  Paragraph,
  HeadingLevel,
  TextRun,
  ExternalHyperlink,
  Table,
  TableRow,
  TableCell,
  WidthType,
} from "docx";
import { writeFile, readFile } from "node:fs/promises";
import type { Report } from "./types.js";
export async function writeWordReport(
  report: Report,
  file: string,
  language: "en" | "ja" = "en",
): Promise<void> {
  const ja = language === "ja";
  const translations: Record<string, string> = {
    "Review the advisory references for a fixed version and validate the upgrade.":
      "参照先で修正済みバージョンを確認し、更新後の動作を検証してください。",
    "Review the call and trace untrusted input before deciding whether it is exploitable.":
      "処理を確認し、外部入力の経路を追跡して、実際に悪用可能か判断してください。",
    "Consider simplifying the function and adding focused tests.":
      "関数の分割や簡素化を検討し、分岐に対応したテストを追加してください。",
    "Confirm the license, usage and distribution conditions against the customer policy.":
      "ライセンスと利用・配布条件を確認し、顧客のポリシーに照らして判断してください。",
    "No match means no matching record in the supplied database snapshot, not absence of vulnerabilities.":
      "照合なしは使用したDB内に該当情報がないことを示し、脆弱性が存在しないことを保証しません。",
    "License policy checks are not a legal compliance determination.":
      "ライセンスポリシー評価は法的な適合性の確定を行うものではありません。",
    "AST rules identify review candidates and complexity, not proven exploitability.":
      "AST検査は要確認のコードや複雑性を抽出します。悪用可能性を立証するものではありません。",
    "SBOM content and package identifiers are supplied by the generating tool.":
      "構成部品の一覧と識別情報は、SBOM生成ツールから取得した情報に依存します。",
    "Packagist matching supports stable numeric versions and SemVer prereleases only; Composer branches and other version forms may be unassessed.":
      "Composerのブランチ指定など、未対応のバージョン表記は未判定になります。",
  };
  const localize = (text: string) => (ja ? translations[text] || text : text);
  const status = (text: string) =>
    ja
      ? (
          {
            affected: "脆弱性該当",
            matched: "脆弱性該当",
            "no-match": "照合なし",
            unassessed: "未判定",
            review: "要確認",
            denied: "ポリシー違反",
          } as Record<string, string>
        )[text] || text
      : text;
  const p = (text: string) =>
    new Paragraph({
      children: [new TextRun({ text })],
      spacing: { after: 120 },
    });
  const heading = (text: string) =>
    new Paragraph({ text, heading: HeadingLevel.HEADING_1 });
  const findings = report.findings;
  const vulnerable = new Set(
    findings
      .filter((f) => f.category === "vulnerability")
      .map((f) => f.subject),
  ).size;
  const unresolved = report.checks.filter(
    (c) => c.status === "unassessed",
  ).length;
  const children: (Paragraph | Table)[] = [
    new Paragraph({
      text: ja
        ? "ソフトウェアセキュリティ検査報告書"
        : "Software Security Assessment Report",
      heading: HeadingLevel.TITLE,
    }),
    p(`${report.customer} | SecuLens ${report.tool.version}`),
    p(
      ja
        ? `対象 ${report.target}　検査日時 ${report.createdAt}`
        : `Target ${report.target} | Assessed ${report.createdAt}`,
    ),
    p(
      ja
        ? `SBOM内の${report.sbom.components.length}件の構成部品を評価しました。既知の脆弱性に該当する部品は${vulnerable}件、脆弱性照合が未判定の部品は${unresolved}件です。以下の指摘と確認事項に沿って対応してください。`
        : `Assessed ${report.sbom.components.length} SBOM components. ${vulnerable} components matched known vulnerability records; ${unresolved} components have incomplete vulnerability assessments. Review the findings and follow-up actions below.`,
    ),
    heading(ja ? "検査範囲と根拠" : "Scope and Evidence"),
    p(`${report.sbom.format} ${report.sbom.version}`),
    p(`SBOM SHA256 ${report.sbomSha256}`),
    p(`DB ${report.database.source}`),
    p(`DB SHA256 ${report.database.sha256}`),
  ];
  const labels: Record<string, string> = {
    vulnerability: "既知の脆弱性",
    license: "ライセンス評価",
    security: "コードのセキュリティ確認",
    quality: "コード品質",
    coverage: "未判定と検査範囲",
  };
  const rows = [
    [ja ? "分類" : "Category", ja ? "指摘件数" : "Findings"],
    ...["vulnerability", "license", "security", "quality", "coverage"].map(
      (c) => [
        ja ? labels[c] : c,
        String(findings.filter((f) => f.category === c).length),
      ],
    ),
  ];
  children.push(
    new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: rows.map(
        (row) =>
          new TableRow({
            children: row.map((text) => new TableCell({ children: [p(text)] })),
          }),
      ),
    }),
  );
  for (const category of [
    "vulnerability",
    "license",
    "security",
    "quality",
    "coverage",
  ]) {
    const group = findings.filter((f) => f.category === category);
    if (!group.length) continue;
    children.push(heading(ja ? labels[category] : category));
    for (const f of group) {
      const component = report.sbom.components.find((c) => c.id === f.subject);
      children.push(
        new Paragraph({
          text: `${f.ruleId} ${f.summary}`,
          heading: HeadingLevel.HEADING_2,
        }),
        p(
          `${component ? `${component.name}@${component.version || "unknown"}` : f.subject} | ${status(f.status)}${f.line ? ` | line ${f.line}` : ""}`,
        ),
        p(`${ja ? "根拠" : "Evidence"} ${f.evidence}`),
        p(`${ja ? "推奨対応" : "Action"} ${localize(f.recommendation)}`),
      );
      if (f.aliases?.length)
        children.push(
          p(`${ja ? "関連ID" : "Aliases"} ${f.aliases.join(", ")}`),
        );
      const references = [...(f.references || [])].sort((a, b) => {
        const priority = (u: string) =>
          u.includes("/advisories/") || u.includes("/security/advisories/")
            ? 0
            : u.includes("nvd.nist.gov")
              ? 1
              : 2;
        return priority(a) - priority(b) || a.localeCompare(b);
      });
      for (const [i, ref] of references.slice(0, 3).entries()) {
        let url: URL;
        try {
          url = new URL(ref);
        } catch {
          continue;
        }
        if (!["https:", "http:"].includes(url.protocol)) continue;
        children.push(
          new Paragraph({
            spacing: { after: 60 },
            children: [
              new ExternalHyperlink({
                link: ref,
                children: [
                  new TextRun({
                    text: `${ja ? "参照" : "Reference"} ${i + 1} ${url.hostname}`,
                    style: "Hyperlink",
                  }),
                ],
              }),
            ],
          }),
        );
      }
      if (references.length > 3)
        children.push(
          p(
            ja
              ? "参照先の全一覧は同梱のJSON報告書に記録しています。"
              : "The complete reference list is preserved in the accompanying JSON report.",
          ),
        );
    }
  }
  children.push(
    heading(ja ? "構成部品の評価状況" : "Component Assessment Coverage"),
  );
  for (const c of report.sbom.components) {
    const check = report.checks.find((x) => x.componentId === c.id);
    children.push(
      p(
        `${c.name}@${c.version || "unknown"} | ${status(check?.status || "unassessed")} | ${c.licenses.join("; ") || "License unknown"}`,
      ),
    );
  }
  children.push(
    heading(ja ? "制約と確認事項" : "Limitations and Review Notes"),
  );
  for (const text of [...report.limitations, ...report.sbom.warnings])
    children.push(p(localize(text)));
  const doc = new Document({
    fonts: ja
      ? [
          {
            name: "Noto Sans JP",
            data: await readFile(
              new URL("../assets/NotoSansJP-Regular.otf", import.meta.url),
            ),
          },
        ]
      : [],
    creator: "SecuLens",
    title: "Software Security Assessment Report",
    styles: {
      default: {
        document: {
          run: { font: ja ? "Noto Sans JP" : "Arial", size: 21 },
          paragraph: { spacing: { after: 120 } },
        },
      },
      paragraphStyles: [
        {
          id: "Heading1",
          name: "Heading 1",
          basedOn: "Normal",
          next: "Normal",
          run: {
            font: ja ? "Noto Sans JP" : "Arial",
            size: 28,
            bold: true,
            color: "000000",
          },
          paragraph: { keepNext: true, spacing: { before: 240, after: 120 } },
        },
        {
          id: "Heading2",
          name: "Heading 2",
          basedOn: "Normal",
          next: "Normal",
          run: {
            font: ja ? "Noto Sans JP" : "Arial",
            size: 23,
            bold: true,
            color: "000000",
          },
          paragraph: { keepNext: true, spacing: { before: 180, after: 80 } },
        },
        {
          id: "Title",
          name: "Title",
          basedOn: "Normal",
          next: "Normal",
          run: {
            font: ja ? "Noto Sans JP" : "Arial",
            size: 36,
            bold: true,
            color: "000000",
          },
          paragraph: { spacing: { after: 240 } },
        },
      ],
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: 11906, height: 16838 },
            margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 },
          },
        },
        children,
      },
    ],
  });
  await writeFile(file, await Packer.toBuffer(doc));
}
