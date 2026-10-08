import type { Component, OsvRecord } from "./types.js";
export function validateDatabase(input: unknown): OsvRecord[] {
  const records = Array.isArray(input) ? input : (input as any)?.records;
  if (!Array.isArray(records))
    throw new Error(
      "Database must be an OSV record array or { records: [...] }",
    );
  for (const r of records) {
    if (typeof r?.id !== "string" || !Array.isArray(r.affected))
      throw new Error("Invalid OSV record");
    for (const a of r.affected) {
      if (
        typeof a.package?.name !== "string" ||
        typeof a.package?.ecosystem !== "string"
      )
        throw new Error(`Invalid affected package in ${r.id}`);
      for (const range of a.ranges || [])
        if (!Array.isArray(range.events))
          throw new Error(`Invalid events in ${r.id}`);
    }
  }
  return records;
}
// Query without a version: the server supplies candidate records; SecuLens performs matching.
export async function fetchDatabase(
  components: Component[],
): Promise<OsvRecord[]> {
  const records = new Map<string, OsvRecord>();
  const seen = new Set<string>();
  for (const c of components) {
    if (!c.ecosystem) continue;
    const key = `${c.ecosystem}:${c.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    let pageToken: string | undefined;
    const tokens = new Set<string>();
    do {
      const response = await fetch("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          package: { name: c.name, ecosystem: c.ecosystem },
          ...(pageToken ? { page_token: pageToken } : {}),
        }),
        signal: AbortSignal.timeout(30000),
      });
      if (!response.ok)
        throw new Error(`OSV request failed (${response.status}) for ${key}`);
      const data = (await response.json()) as any;
      for (const record of validateDatabase(data.vulns || []))
        records.set(record.id, record);
      pageToken = data.next_page_token;
      if (pageToken) {
        if (tokens.has(pageToken))
          throw new Error("Repeated OSV pagination token");
        tokens.add(pageToken);
      }
    } while (pageToken);
  }
  return [...records.values()].sort((a, b) => a.id.localeCompare(b.id));
}
