import ts from "typescript";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "./types.js";
export async function analyze(directory: string): Promise<Finding[]> {
  const root = path.resolve(directory);
  const findings: Finding[] = [];
  async function visit(dir: string) {
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      if (
        ["node_modules", "vendor", ".git", "dist", "build"].includes(entry.name)
      )
        continue;
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) await visit(file);
      else if (entry.isFile() && /\.(?:[cm]?[jt]s|[jt]sx)$/.test(entry.name))
        await inspect(file);
    }
  }
  async function inspect(file: string) {
    const source = ts.createSourceFile(
      file,
      await readFile(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
    );
    const relative = path.relative(root, file).split(path.sep).join("/");
    const add = (
      n: ts.Node,
      category: "security" | "quality",
      ruleId: string,
      summary: string,
      evidence: string,
    ) =>
      findings.push({
        category,
        ruleId,
        subject: relative,
        status: "review",
        summary,
        evidence,
        recommendation:
          category === "security"
            ? "Review the call and trace untrusted input before deciding whether it is exploitable."
            : "Consider simplifying the function and adding focused tests.",
        file: relative,
        line: source.getLineAndCharacterOfPosition(n.getStart(source)).line + 1,
      });
    function walk(n: ts.Node) {
      if (
        ts.isCallExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "eval"
      )
        add(
          n,
          "security",
          "JS-EVAL",
          "Direct eval call requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        ts.isNewExpression(n) &&
        ts.isIdentifier(n.expression) &&
        n.expression.text === "Function"
      )
        add(
          n,
          "security",
          "JS-FUNCTION-CONSTRUCTOR",
          "Dynamic Function constructor requires review",
          n.getText(source).slice(0, 300),
        );
      if (
        ts.isBinaryExpression(n) &&
        n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(n.left) &&
        ["innerHTML", "outerHTML"].includes(n.left.name.text)
      )
        add(
          n,
          "security",
          "JS-HTML-ASSIGNMENT",
          "HTML assignment requires review",
          n.getText(source).slice(0, 300),
        );
      if (ts.isFunctionLike(n) && "body" in n && n.body) {
        let complexity = 1,
          maxDepth = 0;
        function count(x: ts.Node, depth: number) {
          if (x !== n && ts.isFunctionLike(x)) return;
          const branch =
            ts.isIfStatement(x) ||
            ts.isForStatement(x) ||
            ts.isForInStatement(x) ||
            ts.isForOfStatement(x) ||
            ts.isWhileStatement(x) ||
            ts.isDoStatement(x) ||
            ts.isConditionalExpression(x) ||
            ts.isCatchClause(x) ||
            ts.isCaseClause(x);
          if (branch) complexity++;
          if (
            ts.isBinaryExpression(x) &&
            [
              ts.SyntaxKind.AmpersandAmpersandToken,
              ts.SyntaxKind.BarBarToken,
              ts.SyntaxKind.QuestionQuestionToken,
            ].includes(x.operatorToken.kind)
          )
            complexity++;
          const next = depth + (branch ? 1 : 0);
          maxDepth = Math.max(maxDepth, next);
          ts.forEachChild(x, (c) => count(c, next));
        }
        count(n.body, 0);
        if (complexity > 10 || maxDepth > 4)
          add(
            n,
            "quality",
            "JS-COMPLEXITY",
            "Function complexity exceeds the baseline",
            `cyclomatic=${complexity}; nesting=${maxDepth}; thresholds=10,4`,
          );
      }
      ts.forEachChild(n, walk);
    }
    walk(source);
    const diagnostics = (source as any).parseDiagnostics as ts.Diagnostic[];
    for (const d of diagnostics || [])
      findings.push({
        category: "coverage",
        ruleId: "JS-PARSE-ERROR",
        subject: relative,
        status: "unassessed",
        summary: "Source could not be completely parsed",
        evidence: ts.flattenDiagnosticMessageText(d.messageText, " "),
        recommendation: "Resolve the syntax error and repeat the analysis.",
        file: relative,
      });
  }
  await visit(root);
  return findings;
}
