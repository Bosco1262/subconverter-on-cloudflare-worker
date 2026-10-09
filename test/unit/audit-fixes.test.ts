import { describe, expect, it, beforeAll } from "vitest";
import { regFind, regMatch, regReplace, regGetAllMatch, regGetMatch, regValid } from "../../src/lib/regex";
import { INIReader, INIREADER_EXCEPTION } from "../../src/lib/ini";
import { explodeSurge } from "../../src/core/parser/surge";
import { explodeClash } from "../../src/core/parser/clash";
import { explode } from "../../src/core/parser";
import { explodeConfContent } from "../../src/core/parser/conf";
import { loadYaml } from "../../src/lib/yaml";
import { proxyToClash } from "../../src/core/export/clash";
import { proxyToSurge } from "../../src/core/export/surge";
import { renderClashScript } from "../../src/core/ruleconvert";
import { render_template } from "../../src/core/template";
import { base64Decode } from "../../src/lib/base64";
import { newProxy, ProxyType, type Proxy } from "../../src/core/proxy";
import { newExtraSettings, ProxyGroupType, type RulesetContent } from "../../src/core/extra";
import { tribool } from "../../src/lib/tribool";
import { subconverter, type SubRequest } from "../../src/core/orchestrator";
import { readConf, global } from "../../src/core/settings";
import { fileGet, fileCopy } from "../../src/lib/vfs";
import { base64Encode } from "../../src/lib/base64";

// Regression tests for the audit findings that were PORT bugs (upstream behaves correctly).
// Each block names the finding id from 任务要求与进度.md section 七.

beforeAll(async () => {
  if (fileGet("pref.toml").length === 0) {
    for (const [src, dest] of [
      ["pref.example.toml", "pref.toml"],
      ["pref.example.yml", "pref.yml"],
      ["pref.example.ini", "pref.ini"],
    ] as const) {
      if (fileGet(src).length > 0) {
        fileCopy(src, dest);
        break;
      }
    }
  }
  await readConf();
  global.enableCache = false;
});

function ssNode(password: string, remark = "n"): Proxy {
  const n = newProxy();
  n.Type = ProxyType.Shadowsocks;
  n.Remark = remark;
  n.Hostname = "1.2.3.4";
  n.Port = 443;
  n.EncryptMethod = "aes-256-gcm";
  n.Password = password;
  return n;
}

describe("C2 — regGetAllMatch keeps a slot for a group that did not participate", () => {
  it("substitutes an empty string like jpcre2 does", () => {
    expect(regGetAllMatch("b", "(a)|(b)")).toEqual(["b", "", "b"]);
    expect(regGetMatch("b", "(a)|(b)")).toEqual(["b", "", "b"]);
  });

  it("keeps both groups aligned on alternating matches", () => {
    expect(regGetAllMatch("ab", "(a)|(b)")).toEqual(["a", "a", "", "b", "", "b"]);
  });

  it("std vmess/vless links parse instead of throwing", () => {
    const uuid = "8f1e1e4c-1234-1234-1234-123456789abc";
    // No trailing "?query": before the fix the missing group shifted `addition` to undefined and
    // getUrlArg threw, turning the whole /sub request into a 500.
    const vmess = newProxy();
    explode(`vmess://tcp:${uuid}-0@example.com:443`, vmess);
    expect(vmess.Hostname).toBe("example.com");
    expect(vmess.Port).toBe(443);

    const vless = newProxy();
    explode(`vless://${uuid}@example.com:443`, vless);
    expect(vless.Hostname).toBe("example.com");
    expect(vless.Port).toBe(443);
  });
});

describe("H4 — \\A \\z \\Z stay absolute while the m flag stays on", () => {
  it("does not anchor at line starts", () => {
    expect(regReplace("x\ny", "\\A.", "-")).toBe("-\ny");
    expect(regFind("xhello", "\\Ahello")).toBe(false);
    expect(regFind("hello", "\\Ahello")).toBe(true);
  });

  it("\\z/\\Z only match the end", () => {
    expect(regReplace("x\ny", "y\\z", "-")).toBe("x\n-");
    expect(regFind("hellox", "hello\\z")).toBe(false);
  });

  it("^ is still multiline (upstream sets PCRE2_MULTILINE)", () => {
    expect(regReplace("a\nb", "^", "> ")).toBe("> a\n> b");
  });
});

describe("M5 — \\U…\\E case forcing applies to capture-group text", () => {
  it("uppercases an inserted group", () => {
    expect(
      regReplace(
        "domain-suffix,example.com,PROXY",
        "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$",
        "\\U$1\\E$2${3:-}",
        true,
      ),
    ).toBe("DOMAIN-SUFFIX,example.com");
  });

  it("\\L lowercases an inserted group", () => {
    expect(regReplace("ABC", "(B)", "\\L$1\\E")).toBe("AbC");
  });
});

describe("L7 — (?x), POSIX classes inside a class, and code-point semantics", () => {
  it("supports (?x) instead of compiling an invalid flag", () => {
    expect(regFind("abc", "(?x) a b c")).toBe(true);
    expect(regFind("abc", "(?x) a b c # comment")).toBe(true);
  });

  it("expands POSIX classes positionally", () => {
    expect(regMatch("a5", "[[:alpha:]0-9]+")).toBe(true);
    expect(regMatch("a!5", "[[:alpha:]0-9]+")).toBe(false);
    expect(regMatch("abc123", "[[:alpha:]]+[[:digit:]]+")).toBe(true);
    expect(regMatch("!!!", "[[:^alpha:]]+")).toBe(true);
  });

  it("matches astral characters as one code point", () => {
    expect(regReplace("😀", ".", "x")).toBe("x");
  });

  it("treats a codepoint escape as a literal", () => {
    expect(regFind("a.b", "a\\x{2E}b")).toBe(true);
    expect(regFind("axb", "a\\x{2E}b")).toBe(false);
  });
});

describe("M11 — backtracking guard replaces PCRE2's match limit", () => {
  it("rejects nested unbounded quantifiers quickly", () => {
    expect(regFind("aaaaaaaaaaaaaaaaaaaaaaaa!", "(a+)+$")).toBe(false);
    expect(regValid("(ab+)+")).toBe(false);
  });

  it("rejects absurd pattern lengths", () => {
    expect(regValid("a".repeat(9000))).toBe(false);
  });

  // self-review regression: making escapeLiteralChar stop escaping "-" (needed so "\-" stays valid
  // under the u flag, which allows it only inside a class) broke "\Q…\E" INSIDE a character class,
  // where the literal "-" was turned into a range.
  it("\\Q…\\E is class-aware", () => {
    expect(regFind("a-z", "\\Qa-z\\E")).toBe(true);
    expect(regFind("b", "\\Qa-z\\E")).toBe(false);
    expect(regFind("-", "[\\Qa-z\\E]")).toBe(true);
    expect(regFind("a", "[\\Qa-z\\E]")).toBe(true);
    expect(regFind("b", "[\\Qa-z\\E]")).toBe(false);
    expect(regFind("]", "[\\Q]\\E]")).toBe(true);
  });

  it("leaves normal patterns alone", () => {
    expect(regFind("abc", "a.c")).toBe(true);
    expect(regValid("a+")).toBe(true);
  });
});

describe("H2 — headerless Surge proxy list is parsed via the isolated section", () => {
  it("stores bare lines in the isolated section", () => {
    const ini = new INIReader();
    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.setIsolatedItemsSection("Proxy");
    ini.addDirectSaveSection("Proxy");
    expect(ini.parse("P1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pw\n")).toBe(0);
    expect(ini.sectionExist("Proxy")).toBe(true);
    expect(ini.getAll("Proxy", "{NONAME}")).toEqual([
      "P1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pw",
    ]);
  });

  it("explodeSurge produces a node from such a document", () => {
    const nodes: Proxy[] = [];
    expect(explodeSurge("P1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pw\n", nodes)).toBe(1);
    expect([nodes[0].Hostname, nodes[0].Port, nodes[0].Password]).toEqual(["1.2.3.4", 8388, "pw"]);
  });
});

describe("M6 — duplicate section detection and state reset", () => {
  it("returns DUPLICATE instead of silently dropping items", () => {
    const ini = new INIReader();
    expect(ini.parse("[a]\nk=1\n[a]\nm=2\n")).toBe(INIREADER_EXCEPTION.DUPLICATE);
  });

  it("merges when duplicate titles are allowed", () => {
    const ini = new INIReader();
    ini.allow_dup_section_titles = true;
    expect(ini.parse("[a]\nk=1\n[a]\nm=2\n")).toBe(0);
    expect(ini.getItems("a")).toEqual([["k", "1"], ["m", "2"]]);
  });

  it("clears previous content when a later parse fails", () => {
    const ini = new INIReader();
    ini.parse("[a]\nk=1\n");
    expect(ini.parse("orphan=1\n")).toBe(INIREADER_EXCEPTION.OUTOFBOUND);
    expect(ini.getItems("a")).toEqual([]);
  });
});

describe("M7 — set() no longer re-sorts on every insert", () => {
  it("stays key-sorted on read with stable equal keys", () => {
    const ini = new INIReader();
    ini.set("S", "seed", "v");
    for (let i = 0; i < 500; i++) ini.set("S", "{NONAME}", "rule" + i);
    const items = ini.getItems("S");
    expect(items.length).toBe(501);
    expect(items[0][0]).toBe("seed");
    expect(items[items.length - 1][0]).toBe("{NONAME}");
    expect(items[1][1]).toBe("rule0");
    expect(items[2][1]).toBe("rule1");
  });
});

describe("H3 — numeric-looking YAML strings keep their source text", () => {
  const text = [
    "proxies:",
    "  - name: n1",
    "    type: ss",
    "    server: 1.2.3.4",
    "    port: 443",
    "    cipher: aes-256-gcm",
    "    password: 1.50",
    "  - name: n2",
    "    type: ss",
    "    server: 1.2.3.4",
    "    port: 443",
    "    cipher: aes-256-gcm",
    "    password: 0123",
    "",
  ].join("\n");

  it("preserves the spelling in the subscription parser", () => {
    const nodes: Proxy[] = [];
    explodeClash(loadYaml(text, { rawScalarText: true }) as never, nodes);
    expect(nodes.map((n) => n.Password)).toEqual(["1.50", "0123"]);
    expect(nodes.map((n) => n.Port)).toEqual([443, 443]);
  });

  it("leaves the base-config loader untouched (numbers stay numbers)", () => {
    const base = loadYaml("port: 7890\n");
    expect(typeof base?.["port"]).toBe("number");
  });
});

describe("H5 — vmess conf entry missing address/port/id is skipped", () => {
  it("does not emit an empty node", () => {
    const nodes: Proxy[] = [];
    explodeConfContent('{"vnext":true,"vmess":[{"configType":1,"remarks":"a"}]}', nodes);
    expect(nodes.length).toBe(0);
  });

  it("still parses a complete entry", () => {
    const nodes: Proxy[] = [];
    explodeConfContent(
      '{"vnext":true,"vmess":[{"configType":1,"remarks":"ok","address":"1.2.3.4","port":443,"id":"8f1e1e4c-1234-1234-1234-123456789abc","aid":0,"net":"tcp"}]}',
      nodes,
    );
    expect([nodes.length, nodes[0].Hostname, nodes[0].Port]).toEqual([1, "1.2.3.4", 443]);
  });
});

describe("M1 — explodeSSD keeps the previous server", () => {
  it("reuses the last server when an entry omits it", () => {
    const doc = {
      airport: "g",
      port: 8388,
      encryption: "aes-256-gcm",
      password: "pw",
      servers: [{ server: "1.1.1.1", remarks: "a" }, { remarks: "b" }],
    };
    const nodes: Proxy[] = [];
    explodeConfContent("ssd://" + Buffer.from(JSON.stringify(doc)).toString("base64"), nodes);
    expect(nodes.map((n) => n.Hostname)).toEqual(["1.1.1.1", "1.1.1.1"]);
  });
});

describe("M2/M3 — clash tuic and vless defaults match safe_as<T>()", () => {
  it("absent request-timeout is 0 and bools are defined-false", () => {
    const nodes: Proxy[] = [];
    explodeClash(loadYaml("proxies:\n  - name: t\n    type: tuic\n    server: 1.2.3.4\n    port: 443\n    uuid: u\n    password: p\n", { rawScalarText: true }) as never, nodes);
    expect(nodes[0].RequestTimeout).toBe(0);
    expect(nodes[0].DisableSni.isUndef()).toBe(false);
    expect(nodes[0].DisableSni.get()).toBe(false);
    expect(nodes[0].ReduceRtt.isUndef()).toBe(false);
  });

  it("request-timeout wraps like uint16", () => {
    const nodes: Proxy[] = [];
    explodeClash(loadYaml("proxies:\n  - name: t\n    type: tuic\n    server: 1.2.3.4\n    port: 443\n    uuid: u\n    password: p\n    request-timeout: 70000\n", { rawScalarText: true }) as never, nodes);
    expect(nodes[0].RequestTimeout).toBe(70000 & 0xffff);
  });

  it("absent client-fingerprint is empty, not chrome", () => {
    const nodes: Proxy[] = [];
    explodeClash(loadYaml("proxies:\n  - name: v\n    type: vless\n    server: 1.2.3.4\n    port: 443\n    uuid: 8f1e1e4c-1234-1234-1234-123456789abc\n", { rawScalarText: true }) as never, nodes);
    expect(nodes[0].Fingerprint).toBe("");
  });
});

describe("M9 — a value without ':' keeps its whole text as the hostname", () => {
  it("wireguard endpoint", () => {
    const ini =
      "[Proxy]\nWG1 = wireguard, section-name = WGS, mtu = 1420\n[WireGuard WGS]\nprivate-key = PRIV\nself-ip = 10.0.0.2\npeer = (public-key = PUB, allowed-ips = 0.0.0.0/0, endpoint = engage.cloudflareclient.com)\n";
    const nodes: Proxy[] = [];
    explodeSurge(ini, nodes);
    expect([nodes[0].Hostname, nodes[0].Port]).toEqual(["engage.cloudflareclient.com", 0]);
  });
});

describe("C3 — digit-only password is a quoted YAML string", () => {
  it("does not emit a map", () => {
    const ext = newExtraSettings();
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = false;
    const out = proxyToClash([ssNode("123456")], "port: 7890\n", [], [], false, ext);
    expect(out).toMatch(/password:\s*"123456"/);
    expect(out).not.toContain("{ value:");
    expect(out).not.toContain("!<str>");
  });

  it("also applies in the nodelist output", () => {
    const ext = newExtraSettings();
    ext.clash_new_field_name = true;
    ext.nodelist = true;
    const out = proxyToClash([ssNode("987654")], "port: 7890\n", [], [], false, ext);
    expect(out).toMatch(/password:\s*"987654"/);
  });
});

describe("H1 — script mode generates rule blocks", () => {
  it("includes rule_providers lookups", () => {
    const rc: RulesetContent = {
      rule_group: "PROXY",
      rule_path: "x.list",
      rule_path_typed: "x.list",
      rule_format: "clash-domain",
      rule_type: 2,
      rule_content: "payload:\n  - 'ads.example.com'\n",
      update_interval: 0,
    };
    const base: Record<string, unknown> = {};
    renderClashScript(base, [rc], "http://127.0.0.1:25500", true, true, false);
    const code = String(((base["script"] as Record<string, unknown>) ?? {})["code"] ?? "");
    expect(code).toContain("rule_providers[");
    expect(code.length).toBeGreaterThan(100);
  });
});

describe("I — clash_proxies_style / clash_proxy_groups_style take effect", () => {
  // Upstream parses both pref strings (subexport.cpp:260-282) and applies Flow|Block per item
  // (:751-754 proxies, :825-828 groups) plus a whole-sequence Flow for "compact" (:760-761/:841-842).
  // The port read the settings but never passed them to the dumper, so every style produced flow.
  const group = {
    Name: "AUTO", Type: ProxyGroupType.URLTest, Proxies: [".*"], UsingProvider: [], Url: "http://x/204",
    Interval: 300, Timeout: 5, Tolerance: 0, Strategy: 0, Lazy: new tribool(), DisableUdp: new tribool(),
    Persistent: new tribool(), EvaluateBeforeUse: new tribool(), Extras: {},
  };
  function gen(proxiesStyle: string, groupsStyle: string): string {
    const ext = newExtraSettings();
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = false;
    ext.clash_proxies_style = proxiesStyle;
    ext.clash_proxy_groups_style = groupsStyle;
    return proxyToClash([ssNode("pw")], "port: 7890\n", [], [group as never], false, ext);
  }

  it("flow proxies are inline maps", () => {
    expect(gen("flow", "flow")).toMatch(/^proxies:\n {2}- \{/m);
  });

  it("block proxies use block maps and leave groups alone", () => {
    const out = gen("block", "flow");
    expect(out).toMatch(/^proxies:\n {2}- name:/m);
    expect(out).toMatch(/^proxy-groups:\n {2}- \{/m);
  });

  it("block groups (the pref default) use block maps", () => {
    const out = gen("flow", "block");
    expect(out).toMatch(/^proxies:\n {2}- \{/m);
    expect(out).toMatch(/^proxy-groups:\n {2}- name:/m);
  });

  it("compact collapses the whole sequence", () => {
    expect(gen("compact", "flow")).toMatch(/^proxies: \[/m);
    expect(gen("flow", "compact")).toMatch(/^proxy-groups: \[/m);
    expect(gen("compact", "compact")).toMatch(/^proxies: \[/m);
  });

  it("unknown style falls back to flow", () => {
    expect(gen("nonsense", "nonsense")).toMatch(/^proxies:\n {2}- \{/m);
  });
});

describe("M4 — Surge smart group keeps type smart", () => {
  it("emits smart, not url-test", () => {
    const group = {
      Name: "AUTO", Type: ProxyGroupType.Smart, Proxies: [".*"], UsingProvider: [], Url: "http://x/204",
      Interval: 300, Timeout: 5, Tolerance: 0, Strategy: 0, Lazy: new tribool(), DisableUdp: new tribool(),
      Persistent: new tribool(), EvaluateBeforeUse: new tribool(), Extras: {},
    };
    const ext = newExtraSettings();
    ext.enable_rule_generator = false;
    const out = proxyToSurge([ssNode("pw")], "[General]\n", [], [group as never], 4, ext);
    expect(out).toMatch(/^AUTO = smart,/m);
  });
});

describe("C4 — template paths cannot pollute Object.prototype", () => {
  it("ignores {% set __proto__… %}", () => {
    const r = render_template('{% set __proto__.polluted = "1" %}ok', { global_vars: {}, request_params: {}, local_vars: {} }, "");
    expect(r.output).toBe("ok");
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  it("ignores the set() callback on __proto__", () => {
    const r = render_template('{{ set("__proto__.p2", "1") }}ok', { global_vars: {}, request_params: {}, local_vars: {} }, "");
    expect(r.output).toBe("ok");
    expect(({} as Record<string, unknown>)["p2"]).toBeUndefined();
  });

  it("keeps normal paths working", () => {
    const r = render_template('{% set local.a = "1" %}{{ local.a }}', { global_vars: {}, request_params: {}, local_vars: {} }, "");
    expect(r.output).toBe("1");
  });
});

describe("M8 — append() creates a missing path", () => {
  it("writes the value", () => {
    const r = render_template('{{ append("local.k", "a") }}|{{ local.k }}', { global_vars: {}, request_params: {}, local_vars: {} }, "");
    expect(r.output).toBe("|a");
  });

  it("appends to an existing value", () => {
    const r = render_template('{{ set("local.k", "x") }}{{ append("local.k", "a") }}|{{ local.k }}', { global_vars: {}, request_params: {}, local_vars: {} }, "");
    expect(r.output).toBe("|xa");
  });
});

describe("M10 — lenient base64 preserves non-ASCII bytes", () => {
  it("returns non-ASCII input unchanged", () => {
    expect(base64Decode("你好")).toBe("你好");
    expect(base64Decode(base64Encode("节点 one"))).toBe("节点 one");
  });

  it("still mangles a plain ss:// link (upstream parity, documented)", () => {
    const plain = "ss://YWVzLTI1Ni1nY206cHcx@1.2.3.4:8388";
    expect(base64Decode(plain)).not.toBe(plain);
  });
});

describe("M12 — MAX_NODES fuse is enforced per subscription", () => {
  it("truncates a single oversized subscription", async () => {
    const saved = global.maxAllowedNodes;
    global.maxAllowedNodes = 2;
    const links = [1, 2, 3, 4, 5].map((i) => `ss://YWVzLTI1Ni1nY206cHcx@10.0.0.${i}:8388#n${i}`).join("\n");
    const uri = "data:application/octet-stream;base64," + base64Encode(base64Encode(links));
    const req: SubRequest = { method: "GET", argument: [["target", "mixed"], ["url", uri]], headers: new Map(), userAgent: "" };
    const r = await subconverter(req);
    global.maxAllowedNodes = saved;
    expect(r.status).toBe(200);
    expect(base64Decode(r.body).trim().split("\n").length).toBe(2);
  });
});
