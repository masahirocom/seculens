import { createHash } from "node:crypto";
import {
  Paragraph,
  TextRun,
  HeadingLevel,
  Table,
  TableRow,
  TableCell,
  WidthType,
  BorderStyle,
  AlignmentType,
  VerticalAlign,
  TableLayoutType,
} from "docx";
import { LEVELS } from "./severity.js";
import type { Finding, Report, SeverityLevel } from "./types.js";
export const PALETTE: Record<SeverityLevel, [string, string, string, string]> =
  {
    critical: ["重大", "Critical", "991B1B", "FEE2E2"],
    high: ["高", "High", "B91C1C", "FFF1F2"],
    medium: ["中", "Medium", "92400E", "FEF3C7"],
    low: ["低", "Low", "075985", "E0F2FE"],
    none: ["なし", "None", "166534", "F0FDF4"],
    unknown: ["未評価", "Unrated", "475569", "F1F5F9"],
  };
const CATEGORIES: Record<string, [string, string]> = {
  vulnerability: ["脆弱性", "Vulnerability"],
  license: ["ライセンス", "License"],
  security: ["コード確認", "Code review"],
  quality: ["品質", "Quality"],
  coverage: ["検査範囲", "Coverage"],
};
export function reportId(report: Report): string {
  return (
    "SL-" +
    createHash("sha256")
      .update(
        [report.sbomSha256, report.database.sha256, report.createdAt].join("|"),
      )
      .digest("hex")
      .slice(0, 12)
      .toUpperCase()
  );
}
export const severityLevel = (f: Finding): SeverityLevel =>
  LEVELS.includes(f.severity?.level as SeverityLevel)
    ? f.severity!.level
    : "unknown";
export function orderedFindings(report: Report): Finding[] {
  const categories = Object.keys(CATEGORIES);
  return [...report.findings].sort(
    (a, b) =>
      categories.indexOf(a.category) - categories.indexOf(b.category) ||
      (a.category === "vulnerability"
        ? LEVELS.indexOf(severityLevel(a)) - LEVELS.indexOf(severityLevel(b))
        : 0) ||
      (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0) ||
      (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0) ||
      (a.line || 0) - (b.line || 0),
  );
}
export function severityLabel(f: Finding, ja: boolean): string {
  if (f.category === "vulnerability")
    return PALETTE[severityLevel(f)][ja ? 0 : 1];
  return f.status === "unassessed"
    ? ja
      ? "未判定"
      : "Incomplete"
    : f.status === "denied"
      ? ja
        ? "ポリシー違反"
        : "Denied"
      : ja
        ? "要確認"
        : "Review";
}
const p = (text: string) =>
  new Paragraph({ children: [new TextRun(text)], spacing: { after: 120 } });
const heading = (text: string) =>
  new Paragraph({ text, heading: HeadingLevel.HEADING_1 });
export const pageBreak = () =>
  new Paragraph({ pageBreakBefore: true, spacing: { after: 0 } });
export function customerTable(
  rows: string[][],
  widths: number[],
  marks: Record<number, { column: number; level: SeverityLevel }> = {},
  compact = false,
): Table {
  const border = { style: BorderStyle.SINGLE, color: "D9D9D9", size: 4 };
  const twips = widths.map((mm) => Math.round((mm * 1440) / 25.4));
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    columnWidths: twips,
    layout: TableLayoutType.FIXED,
    borders: {
      top: border,
      bottom: border,
      left: border,
      right: border,
      insideHorizontal: border,
      insideVertical: border,
    },
    margins: { top: 80, bottom: 80, left: 80, right: 80 },
    rows: rows.map(
      (row, index) =>
        new TableRow({
          tableHeader: index === 0,
          cantSplit: true,
          children: row.map((text, column) => {
            const mark =
              marks[index]?.column === column
                ? PALETTE[marks[index].level]
                : undefined;
            return new TableCell({
              width: { size: twips[column], type: WidthType.DXA },
              verticalAlign: VerticalAlign.CENTER,
              shading: {
                fill:
                  index === 0
                    ? "E7EDF3"
                    : mark
                      ? mark[3]
                      : index % 2
                        ? "FFFFFF"
                        : "F8FAFC",
              },
              children: [
                new Paragraph({
                  alignment:
                    widths[column] <= 30
                      ? AlignmentType.CENTER
                      : AlignmentType.LEFT,
                  spacing: { before: 40, after: 40 },
                  children: text.split("\n").flatMap((line, i) => [
                    new TextRun({
                      text: line,
                      break: i ? 1 : undefined,
                      bold: index === 0 || !!mark,
                      color: index === 0 ? "000000" : mark ? mark[2] : "000000",
                      size: compact ? 18 : 20,
                    }),
                  ]),
                }),
              ],
            });
          }),
        }),
    ),
  });
}
export function customerFront(
  report: Report,
  findings: Finding[],
  ja: boolean,
  issuer: string,
): (Paragraph | Table)[] {
  const children: (Paragraph | Table)[] = [
    new Paragraph({
      spacing: { before: 1500, after: 240 },
      children: [
        new TextRun({
          text: "SecuLens",
          size: 56,
          bold: true,
          color: "000000",
        }),
      ],
    }),
    new Paragraph({
      text: ja
        ? "ソフトウェアセキュリティ評価報告書"
        : "Software Security Assessment Report",
      heading: HeadingLevel.TITLE,
    }),
    p(
      ja
        ? "脆弱性とライセンスの評価およびコード確認"
        : "Vulnerability and license assessment with code review",
    ),
    new Paragraph({
      spacing: { before: 720, after: 180 },
      children: [
        new TextRun({
          text: `${report.customer}${ja ? " 御中" : ""}`,
          bold: true,
        }),
      ],
    }),
    p(`${ja ? "検査対象" : "Target"}  ${report.target}`),
    p(`${ja ? "検査日時" : "Assessment time"}  ${report.createdAt}`),
    p(`${ja ? "報告書ID" : "Report ID"}  ${reportId(report)}`),
    ...(issuer ? [p(`${ja ? "作成者" : "Prepared by"}  ${issuer}`)] : []),
    p(`SecuLens ${report.tool.version}`),
    new Paragraph({
      spacing: { before: 600, after: 120 },
      children: [
        new TextRun(
          ja
            ? "本報告書は、対象の構成部品と脆弱性DBの照合、ライセンスポリシーの評価、および実施したコード検査の結果をまとめたものです。指摘一覧と詳細の根拠を参照し、対応方針を決定してください。"
            : "This report summarizes the supplied component inventory, advisory matching, license policy evaluation and any code checks performed. Use the findings and supporting evidence to decide follow-up actions.",
        ),
      ],
    }),
    pageBreak(),
    heading(ja ? "1 検査結果の要約" : "1 Assessment Summary"),
  ];
  const vulnerabilities = findings.filter(
    (f) => f.category === "vulnerability",
  );
  const vulnerable = new Set(vulnerabilities.map((f) => f.subject)).size;
  const incomplete = report.checks.filter(
    (c) => c.status === "unassessed",
  ).length;
  const urgent = vulnerabilities.filter((f) =>
    ["critical", "high"].includes(severityLevel(f)),
  ).length;
  children.push(
    p(
      ja
        ? `構成部品${report.sbom.components.length}件を照合し、${vulnerabilities.length}件の脆弱性指摘を検出しました。該当する構成部品は${vulnerable}件、脆弱性照合が未判定の構成部品は${incomplete}件です。件数は同一部品内の別名IDを統合した後の値です。`
        : `Assessed ${report.sbom.components.length} components and identified ${vulnerabilities.length} vulnerability findings affecting ${vulnerable} components. ${incomplete} components have incomplete vulnerability assessments. Counts consolidate advisory aliases per component.`,
    ),
    p(
      ja
        ? `重大または高の指摘は${urgent}件です。優先して参照先の修正情報と利用状況を確認してください。未評価の指摘も、重要度を確定するための確認が必要です。`
        : `${urgent} findings are Critical or High. Prioritize review of available fixes and deployment context. Unrated findings also require severity review.`,
    ),
  );
  const actions = ja
    ? [
        "優先して修正情報と影響を確認",
        "優先して修正情報と影響を確認",
        "更新計画と影響を確認",
        "通常の更新計画で確認",
        "評価根拠と利用条件を確認",
        "重要度の根拠を追加確認",
      ]
    : [
        "Prioritize fixes and impact review",
        "Prioritize fixes and impact review",
        "Review upgrade plan and impact",
        "Review in routine upgrade planning",
        "Review evidence and usage context",
        "Obtain severity evidence",
      ];
  children.push(
    customerTable(
      [
        [
          ja ? "重要度" : "Severity",
          ja ? "件数" : "Count",
          ja ? "確認方針" : "Review guidance",
        ],
        ...LEVELS.map((level, i) => [
          PALETTE[level][ja ? 0 : 1],
          String(
            vulnerabilities.filter((f) => severityLevel(f) === level).length,
          ),
          actions[i],
        ]),
      ],
      [30, 20, 120],
      Object.fromEntries(
        LEVELS.map((level, i) => [i + 1, { column: 0, level }]),
      ),
    ),
    p(
      ja
        ? "重要度はCVSS 3.0／3.1の基本値、またはDB提供のラベルに基づきます。複数の根拠がある場合は最も高い重要度を採用し、詳細に根拠を残します。CVSS 2／4のベクトルは値を計算せず保存し、他に判定可能な根拠がなければ未評価とします。重要度は顧客環境での悪用可能性や事業影響を確定するものではありません。"
        : "Severity uses CVSS 3.0/3.1 base scores or database labels. The highest available severity is displayed when sources differ; all evidence is retained. CVSS 2/4 vectors are preserved but not calculated; absent other usable evidence they remain Unrated. Severity does not establish exploitability or business impact in the customer environment.",
    ),
    customerTable(
      [
        [ja ? "分類" : "Category", ja ? "件数" : "Count"],
        ...Object.entries(CATEGORIES).map(([category, names]) => [
          names[ja ? 0 : 1],
          String(findings.filter((f) => f.category === category).length),
        ]),
      ],
      [140, 30],
      {},
      true,
    ),
    pageBreak(),
    heading(ja ? "2 指摘事項の一覧" : "2 Findings Register"),
    p(
      ja
        ? "番号は後続の詳細と対応します。コード検査とライセンスの要確認事項は脆弱性の重要度と区別して記載しています。"
        : "Finding numbers correspond to the details that follow. Code and license review candidates are distinguished from vulnerability severity.",
    ),
  );
  if (findings.length) {
    const rows = [
      [
        ja ? "番号" : "No.",
        ja ? "重要度／状態" : "Severity / status",
        ja ? "分類" : "Category",
        ja ? "対象と指摘" : "Subject and finding",
      ],
      ...findings.map((f, i) => {
        const component = report.sbom.components.find(
          (c) => c.id === f.subject,
        );
        const subject = component
          ? `${component.name}@${component.version || "unknown"}`
          : `${f.subject}${f.line ? `:${f.line}` : ""}`;
        return [
          `F-${String(i + 1).padStart(3, "0")}`,
          severityLabel(f, ja),
          CATEGORIES[f.category][ja ? 0 : 1],
          `${subject}\n${f.ruleId}`,
        ];
      }),
    ];
    const marks: Record<number, { column: number; level: SeverityLevel }> = {};
    findings.forEach((f, i) => {
      if (f.category === "vulnerability")
        marks[i + 1] = { column: 1, level: severityLevel(f) };
    });
    children.push(customerTable(rows, [18, 28, 28, 96], marks, true));
  } else
    children.push(
      p(
        ja
          ? "指摘事項はありません。検査範囲と制約もご確認ください。"
          : "No findings were recorded. Review assessment coverage and limitations as well.",
      ),
    );
  children.push(
    pageBreak(),
    heading(ja ? "3 指摘事項の詳細" : "3 Finding Details"),
  );
  return children;
}
export function severityParagraphs(
  f: Finding,
  ja: boolean,
  keepNext = false,
): Paragraph[] {
  if (f.category !== "vulnerability") return [];
  const score = f.severity?.score;
  const result = [
    new Paragraph({
      keepNext,
      spacing: { after: 120 },
      children: [
        new TextRun({
          text: `${ja ? "重要度" : "Severity"}  ${severityLabel(f, ja)}${score !== undefined ? ` | ${ja ? "CVSS 3 基本値" : "CVSS 3 base"} ${score.toFixed(1)}` : ""}`,
          bold: true,
          color: PALETTE[severityLevel(f)][2],
        }),
      ],
    }),
  ];
  if (!f.severity?.sources.length)
    result.push(
      new Paragraph({
        keepNext,
        text: ja
          ? "重要度を判定できるDB情報がありません。参照先で確認してください。"
          : "No usable severity metadata was available. Review the advisory references.",
      }),
    );
  const grouped = new Map<string, Set<string>>();
  for (const source of f.severity?.sources || []) {
    const value =
      source.score !== undefined
        ? `${ja ? "CVSS 3 基本値" : "CVSS 3 base"} ${source.score.toFixed(1)}`
        : source.type === "database_label"
          ? `${ja ? "DB評価" : "Database label"} ${source.value}`
          : `${source.type} (${ja ? "未計算" : "not calculated"})`;
    if (!grouped.has(source.recordId)) grouped.set(source.recordId, new Set());
    grouped.get(source.recordId)!.add(value);
  }
  for (const [recordId, values] of grouped)
    result.push(
      new Paragraph({
        keepNext,
        spacing: { after: 120 },
        children: [
          new TextRun({
            text: `${recordId} | ${[...values].join(" / ")}`,
            size: 18,
          }),
        ],
      }),
    );
  return result;
}
