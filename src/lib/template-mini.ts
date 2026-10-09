// Minimal inja-compatible template engine — supports the subset used by subconverter templates:
// {{ expr }}, {% if expr %} / {% else %} / {% elif expr %} / {% endif %}, {% for x in expr %} / {% endfor %},
// {% include "name" %}, {% set k = expr %}, functions, comparisons, and/or/not, dotted paths.
// Implements inja's set_trim_blocks(true) + set_lstrip_blocks(true) semantics.

export type TValue = string | number | boolean | null | undefined | TObject | TValue[];
export interface TObject {
  [key: string]: TValue;
}

export interface TemplateCallbacks {
  [name: string]: { arity: number; // -1 = variable
    fn: (args: TValue[]) => TValue };
}

export interface TemplateEngineOptions {
  callbacks: TemplateCallbacks;
  include?: (name: string) => string;
}

// --- tokenizer -----------------------------------------------------------------

type TokType = "text" | "var" | "block";
interface Tok {
  type: TokType;
  content: string;
}

function tokenize(template: string): Tok[] {
  const toks: Tok[] = [];
  let pos = 0;
  while (pos < template.length) {
    const varStart = template.indexOf("{{", pos);
    const blockStart = template.indexOf("{%", pos);
    const earliest = [varStart, blockStart].filter((x) => x !== -1).sort((a, b) => a - b)[0] ?? -1;
    if (earliest === -1) {
      toks.push({ type: "text", content: template.substring(pos) });
      break;
    }
    if (earliest > pos) toks.push({ type: "text", content: template.substring(pos, earliest) });
    if (earliest === varStart && (blockStart === -1 || varStart <= blockStart)) {
      const end = template.indexOf("}}", varStart + 2);
      if (end === -1) {
        toks.push({ type: "text", content: template.substring(pos) });
        break;
      }
      toks.push({ type: "var", content: template.substring(varStart + 2, end) });
      pos = end + 2;
    } else {
      const end = template.indexOf("%}", blockStart + 2);
      if (end === -1) {
        toks.push({ type: "text", content: template.substring(pos) });
        break;
      }
      toks.push({ type: "block", content: template.substring(blockStart + 2, end).trim() });
      pos = end + 2;
      // trim_blocks: remove newline immediately after block tag
      if (pos < template.length && template[pos] === "\n") pos++;
      else if (pos + 1 < template.length && template[pos] === "\r" && template[pos + 1] === "\n") pos += 2;
    }
  }
  return toks;
}

// --- parser (recursive descent for expressions) ---------------------------------

class ExprParser {
  private pos = 0;
  constructor(private src: string, private callbacks: TemplateCallbacks, private resolve: (path: string) => TValue) {}

  parse(): TValue {
    const v = this.parseOr();
    return v;
  }

  private skipWs(): void {
    while (this.pos < this.src.length && /\s/.test(this.src[this.pos])) this.pos++;
  }

  private peek(): string {
    this.skipWs();
    return this.src[this.pos] ?? "";
  }

  private eat(str: string): boolean {
    this.skipWs();
    if (this.src.startsWith(str, this.pos)) {
      this.pos += str.length;
      return true;
    }
    return false;
  }

  private parseOr(): TValue {
    let left = this.parseAnd();
    for (;;) {
      const save = this.pos;
      if (this.eatWord("or")) {
        const right = this.parseAnd();
        left = truthy(left) || truthy(right);
      } else {
        this.pos = save;
        return left;
      }
    }
  }

  private parseAnd(): TValue {
    let left = this.parseNot();
    for (;;) {
      const save = this.pos;
      if (this.eatWord("and")) {
        const right = this.parseNot();
        left = truthy(left) && truthy(right);
      } else {
        this.pos = save;
        return left;
      }
    }
  }

  private eatWord(w: string): boolean {
    this.skipWs();
    if (this.src.startsWith(w, this.pos)) {
      const after = this.src[this.pos + w.length] ?? "";
      if (!/[a-zA-Z0-9_]/.test(after)) {
        this.pos += w.length;
        return true;
      }
    }
    return false;
  }

  private parseNot(): TValue {
    if (this.eatWord("not")) {
      return !truthy(this.parseNot());
    }
    return this.parseComparison();
  }

  private parseComparison(): TValue {
    const left = this.parseAdditive();
    this.skipWs();
    for (const op of ["==", "!=", ">=", "<=", ">", "<"]) {
      if (this.src.startsWith(op, this.pos)) {
        this.pos += op.length;
        const right = this.parseAdditive();
        switch (op) {
          case "==": return looseEq(left, right);
          case "!=": return !looseEq(left, right);
          case ">": return num(left) > num(right);
          case "<": return num(left) < num(right);
          case ">=": return num(left) >= num(right);
          case "<=": return num(left) <= num(right);
        }
      }
    }
    return left;
  }

  private parseAdditive(): TValue {
    let left = this.parsePrimary();
    for (;;) {
      this.skipWs();
      if (this.src[this.pos] === "+") {
        this.pos++;
        const right = this.parsePrimary();
        left = typeof left === "number" || typeof right === "number" ? num(left) + num(right) : str(left) + str(right);
      } else break;
    }
    return left;
  }

  private parsePrimary(): TValue {
    this.skipWs();
    const c = this.src[this.pos] ?? "";
    if (c === "(") {
      this.pos++;
      const v = this.parseOr();
      this.skipWs();
      if (this.src[this.pos] === ")") this.pos++;
      return v;
    }
    if (c === '"' || c === "'") {
      // string literal
      const quote = c;
      let out = "";
      this.pos++;
      while (this.pos < this.src.length && this.src[this.pos] !== quote) {
        if (this.src[this.pos] === "\\" && this.pos + 1 < this.src.length) {
          const n = this.src[this.pos + 1];
          out += n === "n" ? "\n" : n === "t" ? "\t" : n === "r" ? "\r" : n;
          this.pos += 2;
        } else {
          out += this.src[this.pos];
          this.pos++;
        }
      }
      this.pos++; // closing quote
      return out;
    }
    if (/[0-9-]/.test(c)) {
      const m = /^-?[0-9]+(\.[0-9]+)?/.exec(this.src.substring(this.pos));
      if (m) {
        this.pos += m[0].length;
        return Number(m[0]);
      }
    }
    if (c === "t" && this.src.startsWith("true", this.pos)) {
      this.pos += 4;
      return true;
    }
    if (c === "f" && this.src.startsWith("false", this.pos)) {
      this.pos += 5;
      return false;
    }
    // identifier: dotted path or function call
    const m = /^[a-zA-Z_][a-zA-Z0-9_]*/.exec(this.src.substring(this.pos));
    if (!m) return "";
    let name = m[0];
    this.pos += name.length;
    // consume dotted continuation (but not if followed by '(' — handled below)
    for (;;) {
      if (this.src[this.pos] === "." && /[a-zA-Z0-9_]/.test(this.src[this.pos + 1] ?? "")) {
        this.pos++;
        const seg = /^[a-zA-Z0-9_]+/.exec(this.src.substring(this.pos));
        if (seg) {
          name += "." + seg[0];
          this.pos += seg[0].length;
          continue;
        }
      }
      break;
    }
    this.skipWs();
    if (this.src[this.pos] === "(") {
      // function call
      this.pos++;
      const args: TValue[] = [];
      this.skipWs();
      if (this.src[this.pos] !== ")") {
        for (;;) {
          args.push(this.parseOr());
          this.skipWs();
          if (this.src[this.pos] === ",") {
            this.pos++;
            continue;
          }
          break;
        }
      }
      this.skipWs();
      if (this.src[this.pos] === ")") this.pos++;
      const cb = this.callbacks[name];
      if (cb) {
        if (cb.arity >= 0 && args.length !== cb.arity) {
          // tolerate arity mismatch like inja throws — return empty
        }
        return cb.fn(args);
      }
      // inja builtins
      switch (name) {
        case "default": {
          const v = args[0];
          return v === undefined || v === null || v === "" && args[1] !== undefined && (args[1] as unknown) !== "" ? (args[1] ?? "") : v;
        }
        case "exists":
          return args[0] !== undefined && args[0] !== null;
        case "bool": {
          const v = str(args[0]).toLowerCase();
          return v === "true" || v === "1" ? 1 : 0;
        }
        case "existsIn":
          return args[1] !== undefined && args[1] !== null;
        case "isString":
          return typeof args[0] === "string";
        case "isNumber":
          return typeof args[0] === "number";
        case "round":
          return Math.round(num(args[0]));
        case "abs":
          return Math.abs(num(args[0]));
        case "upper":
          return str(args[0]).toUpperCase();
        case "lower":
          return str(args[0]).toLowerCase();
        case "length":
          return Array.isArray(args[0]) ? args[0].length : str(args[0]).length;
        case "first":
          return Array.isArray(args[0]) ? args[0][0] : str(args[0])[0] ?? "";
        case "last":
          return Array.isArray(args[0]) ? args[0][args[0].length - 1] : str(args[0]).slice(-1);
        default:
          return "";
      }
    }
    // dotted path — resolve immediately (so default()/exists() see undefined)
    return this.resolve(name);
  }
}

function truthy(v: TValue): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") return v.length > 0 && v !== "0";
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

function num(v: TValue): number {
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  const n = Number(v);
  return isNaN(n) ? 0 : n;
}

function str(v: TValue): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  return "";
}

function looseEq(a: TValue, b: TValue): boolean {
  if (typeof a === "string" && typeof b === "string") return a === b;
  if (typeof a === "number" || typeof b === "number") return num(a) === num(b);
  if (typeof a === "boolean" || typeof b === "boolean") return truthy(a) === truthy(b);
  return str(a) === str(b);
}

// --- template AST ----------------------------------------------------------------

type TNode =
  | { t: "text"; v: string }
  | { t: "var"; expr: string }
  | { t: "if"; branches: { cond: string | null; body: TNode[] }[] }
  | { t: "for"; varName: string; arrExpr: string; body: TNode[] }
  | { t: "include"; name: string }
  | { t: "set"; key: string; expr: string };

function lstripCheck(template: string, pos: number): number {
  // lstrip_blocks: if the tag is preceded only by whitespace back to line start, the whitespace is removed
  let p = pos;
  while (p > 0 && (template[p - 1] === " " || template[p - 1] === "\t")) p--;
  if (p === 0 || template[p - 1] === "\n" || (template[p - 2] === "\n" && template[p - 1] === "\r")) {
    return p;
  }
  return pos;
}

function parseNodes(toks: Tok[], iRef: { i: number }, stopAt?: Set<string>): TNode[] {
  const nodes: TNode[] = [];
  while (iRef.i < toks.length) {
    const tok = toks[iRef.i];
    if (tok.type === "text") {
      nodes.push({ t: "text", v: tok.content });
      iRef.i++;
      continue;
    }
    if (tok.type === "var") {
      nodes.push({ t: "var", expr: tok.content.trim() });
      iRef.i++;
      continue;
    }
    // block
    const content = tok.content.trim();
    const keyword = content.split(/\s+/)[0];
    if (stopAt && stopAt.has(keyword)) {
      return nodes; // caller consumes
    }
    iRef.i++;
    if (keyword === "if") {
      const branches: { cond: string | null; body: TNode[] }[] = [];
      const stop = new Set(["elif", "else", "endif"]);
      branches.push({ cond: content.substring(2).trim(), body: parseNodes(toks, iRef, stop) });
      while (iRef.i < toks.length) {
        const t = toks[iRef.i];
        if (t.type === "block") {
          const c = t.content.trim();
          const kw = c.split(/\s+/)[0];
          iRef.i++;
          if (kw === "elif") {
            branches.push({ cond: c.substring(4).trim(), body: parseNodes(toks, iRef, stop) });
            continue;
          }
          if (kw === "else") {
            branches.push({ cond: null, body: parseNodes(toks, iRef, new Set(["endif"])) });
            continue;
          }
          if (kw === "endif") break;
          continue;
        }
        break;
      }
      nodes.push({ t: "if", branches });
      continue;
    }
    if (keyword === "for") {
      // for x in expr
      const m = /^for\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+in\s+(.*)$/.exec(content);
      if (!m) continue;
      const stop = new Set(["endfor"]);
      const body = parseNodes(toks, iRef, stop);
      if (iRef.i < toks.length) iRef.i++; // consume endfor
      nodes.push({ t: "for", varName: m[1], arrExpr: m[2], body });
      continue;
    }
    if (keyword === "include") {
      const m = /^include\s+"([^"]*)"/.exec(content) ?? /^include\s+'([^']*)'/.exec(content);
      if (m) nodes.push({ t: "include", name: m[1] });
      continue;
    }
    if (keyword === "set") {
      const m = /^set\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*=\s*(.*)$/.exec(content);
      if (m) nodes.push({ t: "set", key: m[1], expr: m[2] });
      continue;
    }
    // unknown block — skip
  }
  return nodes;
}

function renderNodes(nodes: TNode[], ctx: RenderCtx): string {
  let out = "";
  for (const node of nodes) {
    switch (node.t) {
      case "text":
        out += node.v;
        break;
      case "var": {
        const v = evalExpr(node.expr, ctx);
        out += str(v);
        break;
      }
      case "if": {
        for (const branch of node.branches) {
          if (branch.cond === null || truthy(evalExpr(branch.cond, ctx))) {
            out += renderNodes(branch.body, ctx);
            break;
          }
        }
        break;
      }
      case "for": {
        const arr = evalExpr(node.arrExpr, ctx);
        const items = Array.isArray(arr) ? arr : typeof arr === "object" && arr !== null ? Object.entries(arr as TObject) : [];
        // `{% for __proto__ in x %}` would otherwise set the prototype of the loop-variable holder
        if (!isSafePathSegment(node.varName)) break;
        for (const item of items) {
          if (Array.isArray(item) && item.length === 2 && typeof item[0] === "string") {
            ctx.loopVars[node.varName] = item[0];
            ctx.loopVars[node.varName + "s"] = item[1];
          } else {
            ctx.loopVars[node.varName] = item as TValue;
          }
          out += renderNodes(node.body, ctx);
        }
        delete ctx.loopVars[node.varName];
        delete ctx.loopVars[node.varName + "s"];
        break;
      }
      case "include": {
        const content = ctx.include(node.name);
        const includeToks = tokenize(content);
        const includeNodes = parseNodes(includeToks, { i: 0 });
        out += renderNodes(includeNodes, ctx);
        break;
      }
      case "set": {
        const v = evalExpr(node.expr, ctx);
        setByPath(ctx.data, node.key, str(v));
        break;
      }
    }
  }
  return out;
}

// Property names that must never be traversed or written: `obj["__proto__"]` is Object.prototype
// itself, so descending into it and assigning pollutes EVERY object in the isolate (and therefore
// every later request). inja rejects a dotted `{% set %}` key outright — it requires a single Id
// token — and its data store is a C++ json object with no prototype chain, so this guard restores
// the upstream behaviour instead of allowing prototype pollution.
const FORBIDDEN_PATH_SEGMENTS = new Set(["__proto__", "prototype", "constructor"]);

function isSafePathSegment(segment: string): boolean {
  return !FORBIDDEN_PATH_SEGMENTS.has(segment);
}

function setByPath(obj: TObject, path: string, value: string): void {
  const parts = path.split(".");
  if (parts.some((p) => !isSafePathSegment(p))) return;
  let cur: TObject = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== "object" || cur[parts[i]] === null) cur[parts[i]] = {};
    cur = cur[parts[i]] as TObject;
  }
  cur[parts[parts.length - 1]] = value;
}

function evalExpr(expr: string, ctx: RenderCtx): TValue {
  const parser = new ExprParser(expr, ctx.callbacks, (p) => resolvePath(ctx.data, p, ctx));
  return parser.parse();
}

function resolvePath(data: TObject, path: string, ctx: RenderCtx): TValue {
  if (ctx.loopVars && path in ctx.loopVars) return ctx.loopVars[path];
  const parts = path.split(".");
  if (parts.some((p) => !isSafePathSegment(p))) return undefined;
  let cur: TValue = data;
  for (const p of parts) {
    if (cur === undefined || cur === null) return undefined;
    if (typeof cur !== "object") return undefined;
    cur = (cur as TObject)[p];
  }
  return cur;
}

interface RenderCtx {
  data: TObject;
  callbacks: TemplateCallbacks;
  include: (name: string) => string;
  loopVars: Record<string, TValue>;
}

export function renderTemplate(template: string, data: TObject, options: TemplateEngineOptions): string {
  const toks = tokenize(template);
  const nodes = parseNodes(toks, { i: 0 });
  const ctx: RenderCtx = {
    data,
    callbacks: options.callbacks,
    include: options.include ?? (() => ""),
    loopVars: {},
  };
  return renderNodes(nodes, ctx);
}
