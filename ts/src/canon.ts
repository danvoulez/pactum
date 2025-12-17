export function canonicalString(v: any): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    // Pactum V0 should not use JSON numbers; keep strict.
    throw new Error("JSON numbers are not allowed in Pactum canonical form (use decimal strings).");
  }
  if (typeof v === "string") return JSON.stringify(v);

  if (Array.isArray(v)) {
    return "[" + v.map(canonicalString).join(",") + "]";
  }

  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ":" + canonicalString(v[k]));
    }
    return "{" + parts.join(",") + "}";
  }

  throw new Error(`Unsupported JSON type: ${typeof v}`);
}

