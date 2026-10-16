// RFC 4180 CSV: quoted fields may hold commas, quotes ("") and line breaks.

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0; // BOM
  for (; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') (field += '"'), i++;
        else quoted = false;
      } else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === ",") row.push(field), (field = "");
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field), (field = "");
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.length > 1 || row[0] !== "") rows.push(row);
  return rows;
}

/** Rows as objects keyed by the header row (keys lowercased and trimmed). */
export function csvRecords(text: string): Record<string, string>[] {
  const [head, ...rows] = parseCsv(text);
  if (!head) return [];
  const keys = head.map((k) => k.trim().toLowerCase());
  return rows.map((r) => Object.fromEntries(keys.map((k, i) => [k, r[i] ?? ""])));
}

const cell = (v: string | number | null | undefined) => {
  const s = v == null ? "" : String(v);
  return /[",\r\n]/.test(s) || /^\s|\s$/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function toCsv(head: string[], rows: (string | number | null | undefined)[][]): string {
  return [head, ...rows].map((r) => r.map(cell).join(",")).join("\n") + "\n";
}
