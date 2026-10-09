// YAML helpers mimicking yaml-cpp Node semantics used by subconverter

import { parse as yamlParse, parseDocument, isMap, isSeq, isScalar } from "yaml";

export type YNode = unknown;

export interface LoadYamlOptions {
  /**
   * Emulate yaml-cpp's `node.as<std::string>()`, which returns the scalar's SOURCE TEXT rather than
   * a JS-resolved value. Only the subscription parser needs this: resolving `1.50` to the number 1.5
   * (or `1e5` to 100000, or `0123` to the octal 83) silently rewrites string fields such as
   * password / uuid / sni. Base-config loading must keep real numbers, so this is opt-in.
   * Booleans stay canonical ("true"/"false") because the port reads every YAML bool through
   * tribool.setString, which only understands true/1/false/0.
   */
  rawScalarText?: boolean;
}

export function loadYaml(content: string, opts: LoadYamlOptions = {}): Record<string, unknown> | null {
  try {
    if (opts.rawScalarText) {
      const doc = parseDocument(content, { version: "1.1", keepSourceTokens: true });
      if (doc.errors.length > 0) return null;
      const converted = toRawScalarValue(doc.contents);
      if (!converted || typeof converted !== "object" || Array.isArray(converted)) return null;
      return converted as Record<string, unknown>;
    }
    // yaml-cpp accepts 1.1-style booleans (yes/no/on/off)
    const parsed = yamlParse(content, { version: "1.1" }) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

type SrcTokenHolder = { srcToken?: { source?: string } };

// Walk a parsed Document, returning plain JS values except that numeric scalars keep their source
// spelling (see LoadYamlOptions.rawScalarText).
function toRawScalarValue(node: unknown): unknown {
  if (isMap(node)) {
    const out: Record<string, unknown> = {};
    for (const item of node.items) {
      const keyNode = item.key;
      const key = isScalar(keyNode) ? String(keyNode.value) : String((keyNode as { toJS?: () => unknown })?.toJS?.() ?? "");
      out[key] = toRawScalarValue(item.value);
    }
    return out;
  }
  if (isSeq(node)) return node.items.map((item) => toRawScalarValue(item));
  if (isScalar(node)) {
    const value = node.value as unknown;
    if (typeof value === "number") {
      const raw = (node as SrcTokenHolder).srcToken?.source;
      if (typeof raw === "string" && raw.length > 0) return raw;
    }
    return value;
  }
  const holder = node as { toJS?: () => unknown } | null;
  if (holder && typeof holder.toJS === "function") return holder.toJS();
  return node ?? null;
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

// safe_as<bool> (yamlcpp_extra.h:14-19): an undefined/null node yields T() == false, and a present
// scalar goes through yaml-cpp's bool conversion. Distinct from tribool.setString, which only
// understands true/1/false/0 — YAML bools must not be routed through it when a `bool` field (as
// opposed to a tribool field) is being read.
export function yAsBool(node: unknown): boolean {
  if (node === undefined || node === null) return false;
  if (typeof node === "boolean") return node;
  const s = String(node).trim().toLowerCase();
  if (s.length === 0) return false;
  if (s === "true" || s === "yes" || s === "on" || s === "y") return true;
  if (s === "false" || s === "no" || s === "off" || s === "n") return false;
  const n = parseInt(s, 10);
  return isFinite(n) && n !== 0;
}

// safe_as<T> for an unsigned 16-bit field (subparser.cpp:1681 `uint16_t request_timeout`): an absent
// node yields 0, and a present value is truncated to 16 bits the way static_cast<uint16_t> does.
export function yAsUint16(node: unknown): number {
  if (node === undefined || node === null) return 0;
  const n = parseFloat(String(node).trim());
  if (!isFinite(n)) return 0;
  return Math.trunc(n) & 0xffff;
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
