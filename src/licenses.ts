import parse from "spdx-expression-parse";
import type { Component, Finding, Policy } from "./types.js";
type Decision = "allowed" | "denied" | "review";
export function evaluateLicense(expression: string, policy: Policy): Decision {
  if (["NOASSERTION", "NONE", ""].includes(expression)) return "review";
  try {
    const walk = (n: any): Decision => {
      if (n.conjunction) {
        const a = walk(n.left),
          b = walk(n.right);
        return n.conjunction === "or"
          ? a === "allowed" || b === "allowed"
            ? "allowed"
            : a === "denied" && b === "denied"
              ? "denied"
              : "review"
          : a === "denied" || b === "denied"
            ? "denied"
            : a === "allowed" && b === "allowed"
              ? "allowed"
              : "review";
      }
      const id = `${n.license}${n.plus ? "+" : ""}${n.exception ? ` WITH ${n.exception}` : ""}`;
      if (policy.deny?.includes(id)) return "denied";
      if (policy.allow?.includes(id)) return "allowed";
      return "review";
    };
    return walk(parse(expression));
  } catch {
    return "review";
  }
}
export function licenseFindings(c: Component, p: Policy): Finding[] {
  const result: Finding[] = [];
  const entries = c.licenses.length ? c.licenses : ["NOASSERTION"];
  for (const expression of entries) {
    const d = evaluateLicense(expression, p);
    if (d === "allowed") continue;
    result.push({
      category: "license",
      ruleId: d === "denied" ? "LICENSE-DENIED" : "LICENSE-REVIEW",
      subject: c.id,
      status: d === "denied" ? "denied" : "review",
      summary:
        d === "denied" ? "License denied by policy" : "License requires review",
      evidence: expression,
      recommendation:
        "Confirm the license, usage and distribution conditions against the customer policy.",
    });
  }
  return result;
}
