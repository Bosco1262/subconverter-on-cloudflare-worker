// Port of src/generator/template/templates.cpp render_template (lines 80-259)

import { renderTemplate as miniRender, type TemplateCallbacks, type TObject } from "../lib/template-mini";
import { urlEncode, urlDecode } from "../lib/urlencode";
import { trim, trimOf } from "../lib/string";
import { regFind, regReplace } from "../lib/regex";
import { global } from "./settings";

export interface template_args {
  global_vars: Record<string, string>;
  request_params: Record<string, string>;
  local_vars: Record<string, string>;
}

// injectable file accessor (vfs module sets this)
let fileGetFn: (path: string, scopeLimit?: boolean) => string = () => "";
export function setTemplateFileGet(fn: (path: string, scopeLimit?: boolean) => string): void {
  fileGetFn = fn;
}

// injectable webGet for template fetch() callback
let templateWebGetFn: (url: string) => string = () => "";
export function setTemplateWebGet(fn: (url: string) => string): void {
  templateWebGetFn = fn;
}

// Property names that must never be traversed or written: `obj["__proto__"]` IS Object.prototype, so
// writing through it pollutes every object in the isolate (i.e. every later request). Upstream writes
// into inja's own nlohmann::json value (templates.cpp:150-155) and C++ has no prototype chain.
const FORBIDDEN_PATH_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);

function isSafePath(path: string): boolean {
  return !path.split(".").some((p) => FORBIDDEN_PATH_SEGMENTS.has(p));
}

// parse_json_pointer semantics: "clash.http_port" → nested object; also supports "/a/b" json-pointer form
function parseJsonPointer(data: TObject, key: string, value: string): void {
  const path = key.replace(/\//g, ".").replace(/^\./, "");
  if (!isSafePath(path)) return;
  const parts = path.split(".");
  let cur: TObject = data;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== "object" || cur[parts[i]] === null) cur[parts[i]] = {};
    cur = cur[parts[i]] as TObject;
  }
  cur[parts[parts.length - 1]] = value;
}

// Read the value at a dot path the way upstream's `data[pointer].get<std::string>()` does: anything
// missing or non-string yields "" (nlohmann throws on a non-string and the caller swallows it).
function readJsonPointer(data: TObject, key: string): string {
  const path = key.replace(/\//g, ".").replace(/^\./, "");
  if (!isSafePath(path)) return "";
  const parts = path.split(".");
  let cur: unknown = data;
  for (const p of parts) {
    if (cur === null || typeof cur !== "object" || !Object.prototype.hasOwnProperty.call(cur, p)) return "";
    cur = (cur as TObject)[p];
  }
  return typeof cur === "string" ? cur : "";
}

export function render_template(
  content: string, vars: template_args, includeScope: string,
): { ret: number; output: string } {
  const data: TObject = {};
  for (const [k, v] of Object.entries(vars.global_vars)) parseJsonPointer(data, "global." + k, v);
  let allArgs = "";
  for (const [k, v] of Object.entries(vars.request_params)) {
    allArgs += k;
    if (v.length > 0) {
      parseJsonPointer(data, "request." + k, v);
      allArgs += "=" + v;
    }
    allArgs += "&";
  }
  if (allArgs.length > 0) allArgs = allArgs.substring(0, allArgs.length - 1);
  parseJsonPointer(data, "request._args", allArgs);
  for (const [k, v] of Object.entries(vars.local_vars)) parseJsonPointer(data, "local." + k, v);

  const callbacks: TemplateCallbacks = {
    UrlEncode: { arity: 1, fn: (args) => urlEncode(String(args[0] ?? "")) },
    UrlDecode: { arity: 1, fn: (args) => urlDecode(String(args[0] ?? "")) },
    trim_of: { arity: 2, fn: (args) => {
      const s = String(args[0] ?? ""), target = String(args[1] ?? "");
      if (target.length === 0) return s;
      return trimOf(s, target[0]);
    } },
    trim: { arity: 1, fn: (args) => trim(String(args[0] ?? "")) },
    find: { arity: 2, fn: (args) => regFind(String(args[0] ?? ""), String(args[1] ?? "")) },
    replace: { arity: 3, fn: (args) => {
      const src = String(args[0] ?? ""), target = String(args[1] ?? ""), rep = String(args[2] ?? "");
      if (target.length === 0 || src.length === 0) return src;
      return regReplace(src, target, rep);
    } },
    set: { arity: 2, fn: (args) => {
      parseJsonPointer(data, String(args[0] ?? ""), String(args[1] ?? ""));
      return "";
    } },
    split: { arity: 3, fn: (args) => {
      const content = String(args[0] ?? ""), delim = String(args[1] ?? ""), dest = String(args[2] ?? "");
      const vArray = content.split(delim);
      for (let i = 0; i < vArray.length; i++) parseJsonPointer(data, dest + "." + i, vArray[i]);
      return "";
    } },
    append: { arity: 2, fn: (args) => {
      const path = String(args[0] ?? ""), value = String(args[1] ?? "");
      // upstream (templates.cpp:164-179) reads the existing value — "" when the path does not exist,
      // because the lookup throws and is swallowed — appends, then assigns UNCONDITIONALLY. The port
      // used to bail out on a missing path, so `append("local.k","a")` wrote nothing at all.
      parseJsonPointer(data, path, readJsonPointer(data, path) + value);
      return "";
    } },
    getLink: { arity: 1, fn: (args) => global.managedConfigPrefix + String(args[0] ?? "") },
    startsWith: { arity: 2, fn: (args) => String(args[0] ?? "").startsWith(String(args[1] ?? "")) },
    endsWith: { arity: 2, fn: (args) => String(args[0] ?? "").endsWith(String(args[1] ?? "")) },
    or: { arity: -1, fn: (args) => args.some((a) => Number(a ?? 0) !== 0) },
    and: { arity: -1, fn: (args) => args.every((a) => Number(a ?? 0) !== 0) },
    bool: { arity: 1, fn: (args) => {
      const value = String(args[0] ?? "").toLowerCase();
      return value === "true" || value === "1" ? 1 : 0;
    } },
    string: { arity: 1, fn: (args) => String(Number(args[0] ?? 0)) },
    fetch: { arity: 1, fn: (args) => templateWebGetFn(String(args[0] ?? "")) },
  };

  try {
    const output = miniRender(content, data, {
      callbacks,
      include: (name) => {
        // scope jail: template_name must be inside include_scope
        if (includeScope.length > 0 && !(name.startsWith(includeScope) || name.startsWith("./" + includeScope) || !name.startsWith("/"))) {
          // the C++ canonicalization check reduces to: relative paths under template scope are allowed
          if (name.includes("..")) throw new Error("access denied when trying to include '" + name + "': out of scope");
        }
        if (name.includes("..")) throw new Error("access denied when trying to include '" + name + "': out of scope");
        return fileGetFn(name, true);
      },
    });
    return { ret: 0, output };
  } catch (e) {
    const output = "Template render failed! Reason: " + String(e instanceof Error ? e.message : e);
    console.error(output);
    return { ret: -1, output };
  }
}
