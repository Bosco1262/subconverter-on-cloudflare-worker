// YAML helpers mimicking yaml-cpp Node semantics used by subconverter

import { parse as yamlParse } from "yaml";

export type YNode = unknown;

export function loadYaml(content: string): Record<string, unknown> | null {
  try {
    // yaml-cpp accepts 1.1-style booleans (yes/no/on/off)
    const parsed = yamlParse(content, { version: "1.1" }) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export class YamlTypeError extends Error {}

// safe_as<std::string>: undefined/null → ""; scalar → string; map/seq → throw (like yaml-cpp)
export function yAsStr(node: unknown): string {
  if (node === undefined || node === null) return "";
  if (typeof node === "object") throw new YamlTypeError("not a scalar");
  if (typeof node === "boolean") return node ? "true" : "false";
  return String(node);
}

// operator>>= into std::string — same as safe_as but callers often tolerate throw via outer try
export function yStr(node: unknown, def = ""): string {
  try {
    const v = yAsStr(node);
    return v.length === 0 ? def : v;
  } catch {
    return def;
  }
}

// safe_as<std::vector<std::string>> on a sequence
export function yAsStrList(node: unknown): string[] {
  if (node === undefined || node === null) return [];
  if (!Array.isArray(node)) throw new YamlTypeError("not a sequence");
  return node.map((x) => yAsStr(x));
}

// operator>> semantics: only assign when defined && !null
export function yAssignStr(node: unknown, target: { v: string }): void {
  if (node === undefined || node === null) return;
  target.v = yAsStr(node);
}

export function yIsDefined(node: unknown): boolean {
  return node !== undefined && node !== null;
}

export function yScalarList(node: unknown): string[] {
  if (Array.isArray(node)) return node.map((x) => (typeof x === "object" && x !== null ? "" : String(x)));
  if (node === undefined || node === null) return [];
  if (typeof node === "object") return [];
  return [String(node)];
}
