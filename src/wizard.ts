import { createInterface } from "node:readline";
import { stat } from "node:fs/promises";
import path from "node:path";
const messages = {
  en: {
    welcome: "SecuLens setup wizard",
    hint: "Press Enter to accept defaults. Ctrl+C cancels.",
    task: "Task: 1 = scan an existing SBOM, 2 = generate an SBOM",
    sbom: "SBOM JSON file",
    dbmode: "Vulnerability database: 1 = local snapshot, 2 = fetch from OSV",
    db: "Local OSV database JSON file",
    network:
      "OSV receives package names and ecosystems. Source code is not sent.",
    policy: "License policy JSON file (optional)",
    source: "Source directory for AST review (optional)",
    customer: "Customer name",
    target: "System / project name",
    issuer: "Report preparer (optional)",
    style: "Report style: 1 = customer, 2 = standard",
    output: "Report output directory",
    fail: "Return exit code 1 for actionable findings? (y/n)",
    project: "Project directory",
    format: "SBOM format: 1 = CycloneDX, 2 = SPDX",
    sbomoutput: "SBOM output file",
    syft: "Syft executable (must be installed)",
    summary: "Review your settings",
    start: "Start?",
    cancel: "Cancelled. No assessment or generation was started.",
    invalid: "Enter one of the listed choices.",
    required: "A value is required.",
    file: "Enter an existing file path.",
    directory: "Enter an existing directory path.",
    yes: "yes",
    no: "no",
    running: "Starting...",
  },
  ja: {
    welcome: "SecuLens 設定ウィザード",
    hint: "Enterで既定値を選択できます。Ctrl+Cで中止します。",
    task: "操作: 1 = 既存SBOMを検査、2 = SBOMを生成",
    sbom: "SBOMのJSONファイル",
    dbmode: "脆弱性DB: 1 = 保存済みDB、2 = OSVから取得",
    db: "保存済みOSV DBのJSONファイル",
    network:
      "OSVへパッケージ名とエコシステムを送信します。ソースコードは送信しません。",
    policy: "ライセンスポリシーJSONファイル（任意）",
    source: "AST解析するソースフォルダー（任意）",
    customer: "顧客名",
    target: "対象システム・プロジェクト名",
    issuer: "報告書の作成者（任意）",
    style: "レポート形式: 1 = 顧客提出用、2 = 標準",
    output: "レポートの出力フォルダー",
    fail: "対応対象の指摘があれば終了コード1にしますか？ (y/n)",
    project: "プロジェクトフォルダー",
    format: "SBOM形式: 1 = CycloneDX、2 = SPDX",
    sbomoutput: "SBOMの出力ファイル",
    syft: "Syftの実行ファイル（事前インストールが必要）",
    summary: "設定内容の確認",
    start: "開始しますか？",
    cancel: "中止しました。検査・生成は開始していません。",
    invalid: "表示された選択肢を入力してください。",
    required: "入力が必要です。",
    file: "存在するファイルのパスを入力してください。",
    directory: "存在するフォルダーのパスを入力してください。",
    yes: "はい",
    no: "いいえ",
    running: "開始しています…",
  },
} as const;

/** Gather options only. The normal CLI performs the actual operation. */
export async function wizard(
  language?: "en" | "ja",
): Promise<{ args: string[] | null; language: "en" | "ja" }> {
  const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const lines = reader[Symbol.asyncIterator]();
  const interrupt = () => {
    process.exitCode = 130;
    reader.close();
  };
  process.once("SIGINT", interrupt);
  let lang: "en" | "ja" = language ?? "en";
  const ask = async (
    label: string,
    fallback = "",
    required = false,
  ): Promise<string> => {
    while (true) {
      process.stdout.write(`${label}${fallback ? ` [${fallback}]` : ""}: `);
      const next = await lines.next();
      if (next.done) throw new Error("WIZARD_EOF");
      const value = next.value.trim() || fallback;
      if (value || !required) return value;
      console.log(messages[lang].required);
    }
  };
  const choice = async (
    label: string,
    choices: string[],
    fallback: string,
  ): Promise<string> => {
    while (true) {
      const answer = (await ask(label, fallback)).toLowerCase();
      if (choices.includes(answer)) return answer;
      console.log(messages[lang].invalid);
    }
  };
  try {
    if (!language)
      lang = (await choice("Language / 言語 (en / ja)", ["en", "ja"], "en")) as
        | "en"
        | "ja";
    const m = messages[lang];
    console.log(`\n${m.welcome}\n${m.hint}`);
    const settings: [string, string][] = [];
    const field = async (
      key: keyof typeof m,
      fallback = "",
      required = false,
      kind?: "file" | "directory",
    ): Promise<string> => {
      while (true) {
        let value = await ask(m[key], fallback, required);
        if (
          kind &&
          value.length > 1 &&
          ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'")))
        )
          value = value.slice(1, -1);
        if (required && !value) {
          console.log(m.required);
          continue;
        }
        if (kind && value) {
          const info = await stat(value).catch(() => null);
          if (
            !info ||
            (kind === "file" ? !info.isFile() : !info.isDirectory())
          ) {
            console.log(m[kind]);
            continue;
          }
        }
        if (value) settings.push([m[key], value]);
        return value;
      }
    };
    const select = async (
      key: keyof typeof m,
      values: string[],
      fallback: string,
      display: Record<string, string> = {},
    ): Promise<string> => {
      const value = await choice(m[key], values, fallback);
      settings.push([m[key], display[value] ?? value]);
      return value;
    };
    const task = await select("task", ["1", "2"], "1");
    let args: string[];
    if (task === "2") {
      const project = await field("project", "", true, "directory");
      const format = await select("format", ["1", "2"], "1", {
        "1": "CycloneDX",
        "2": "SPDX",
      });
      const output = await field("sbomoutput", "sbom.json", true);
      args = [
        "sbom",
        project,
        "--format",
        format === "1" ? "cyclonedx" : "spdx",
        "--output",
        output,
      ];
    } else {
      const sbom = await field("sbom", "", true, "file");
      args = ["scan", sbom];
      const mode = await select("dbmode", ["1", "2"], "1");
      if (mode === "1") args.push("--db", await field("db", "", true, "file"));
      else {
        console.log(m.network);
        args.push("--fetch-osv");
      }
      for (const key of ["policy", "source"] as const) {
        const value = await field(
          key,
          "",
          false,
          key === "source" ? "directory" : "file",
        );
        if (value) args.push(`--${key}`, value);
      }
      args.push(
        "--customer",
        await field("customer", lang === "ja" ? "顧客" : "Customer", true),
      );
      args.push("--target", await field("target", path.basename(sbom), true));
      const issuer = await field("issuer");
      if (issuer) args.push("--issuer", issuer);
      const style = await select("style", ["1", "2"], "1");
      args.push(
        "--report-style",
        style === "1" ? "customer" : "standard",
        "--lang",
        lang,
      );
      args.push("--output", await field("output", "reports", true));
      const fail = await select("fail", ["y", "n"], "n", { y: m.yes, n: m.no });
      if (fail === "y") args.push("--fail-on-findings");
    }
    console.log(`\n${m.summary} (${lang})`);
    for (const [label, value] of settings) console.log(`  ${label}: ${value}`);
    if ((await choice(`${m.start} (y/n)`, ["y", "n"], "y")) === "n") {
      console.log(m.cancel);
      return { args: null, language: lang };
    }
    console.log(m.running);
    return { args, language: lang };
  } catch (error) {
    if (error instanceof Error && error.message === "WIZARD_EOF") {
      console.log(`\n${messages[lang].cancel}`);
      return { args: null, language: lang };
    }
    throw error;
  } finally {
    process.removeListener("SIGINT", interrupt);
    reader.close();
  }
}
