import { describe, expect, it, beforeAll } from "vitest";
import { getRulesetHandler } from "../../src/routes/handlers";
import type { SubRequest } from "../../src/core/orchestrator";
import { readConf, global, fromIniRulesetConfs } from "../../src/core/settings";
import { fileGet, fileCopy } from "../../src/lib/vfs";
import { urlSafeBase64Encode } from "../../src/lib/base64";

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

const RULESET = "rules/ACL4SSR/Clash/BanAD.list";

function req(type: string, extra: [string, string][] = []): SubRequest {
  return {
    method: "GET",
    argument: [["url", urlSafeBase64Encode(RULESET)], ["type", type], ...extra],
    headers: new Map(),
    userAgent: "",
  };
}

describe("/getruleset", () => {
  it("rejects missing/invalid args", async () => {
    const r = await getRulesetHandler({ method: "GET", argument: [], headers: new Map(), userAgent: "" });
    expect(r.status).toBe(400);
    expect(r.body).toBe("Invalid request!");
  });

  it("type=1 surge ruleset keeps original lines", async () => {
    const r = await getRulesetHandler(req("1"));
    expect(r.status).toBe(200);
    expect(r.body.split("\n").length).toBeGreaterThan(1);
    expect(r.body).not.toContain("payload:");
  });

  it("type=3 emits clash domain payload with suffix markers", async () => {
    const r = await getRulesetHandler(req("3"));
    expect(r.status).toBe(200);
    expect(r.body.startsWith("payload:\n")).toBe(true);
    const lines = r.body.trim().split("\n").slice(1);
    expect(lines.length).toBeGreaterThan(0);
    for (const l of lines) expect(l).toMatch(/^ {2}- '(\+\.)?[^']+'$/);
  });

  it("type=4 emits clash ipcidr payload", async () => {
    const r = await getRulesetHandler(req("4"));
    expect(r.status).toBe(200);
    expect(r.body.startsWith("payload:\n")).toBe(true);
  });

  it("type=5 emits surge DOMAIN-SET entries without quotes or payload header", async () => {
    const r = await getRulesetHandler(req("5"));
    expect(r.status).toBe(200);
    expect(r.body).not.toContain("payload:");
    expect(r.body).not.toMatch(/^ {2}- '/m);
    expect(r.body.split("\n").filter((l) => l.length > 0).length).toBeGreaterThan(0);
  });

  it("type=6 emits clash classical payload with bullets", async () => {
    const r = await getRulesetHandler(req("6"));
    expect(r.status).toBe(200);
    expect(r.body.startsWith("payload:\n")).toBe(true);
    const examples = r.body.split("\n").filter((l) => l.startsWith("  - "));
    expect(examples.length).toBeGreaterThan(0);
    expect(examples[0]).toContain(",");
  });

  it("type=2 requires group and appends it", async () => {
    const noGroup = await getRulesetHandler(req("2"));
    expect(noGroup.status).toBe(400);

    const withGroup = await getRulesetHandler(req("2", [["group", urlSafeBase64Encode("PROXY")]]));
    expect(withGroup.status).toBe(200);
    expect(withGroup.body).toContain(",PROXY");
  });

  it("accepts inline [] rulesets without fetching (type filter still applies)", async () => {
    // convertRuleset(RULESET_SURGE) returns the content verbatim, then getRuleset applies its
    // per-type rule-type filter. "[]GEOIP,CN" is already a finished rule line without a leading
    // rule type, so every type filter drops it — upstream getRuleset behaves the same way, and the
    // placeholder branch keeps the payload valid. What is asserted here is that no fetch/400 occurs.
    const surge = await getRulesetHandler({
      method: "GET",
      argument: [["url", urlSafeBase64Encode("[]GEOIP,CN")], ["type", "1"]],
      headers: new Map(),
      userAgent: "",
    });
    expect(surge.status).toBe(200);
    expect(surge.body).toBe("");

    const clash = await getRulesetHandler({
      method: "GET",
      argument: [["url", urlSafeBase64Encode("[]GEOIP,CN")], ["type", "6"]],
      headers: new Map(),
      userAgent: "",
    });
    expect(clash.status).toBe(200);
    expect(clash.body).toBe("payload:\n  - 'DOMAIN,--placeholder--'");
  });
});

describe("fromIniRulesetConfs binding semantics (binding.h:306)", () => {
  it("parses group,url[,interval]", () => {
    expect(fromIniRulesetConfs(["ruleset,rules/ACL4SSR/Clash/BanAD.list"])).toEqual([
      ["ruleset", "rules/ACL4SSR/Clash/BanAD.list", 0],
    ]);
    expect(fromIniRulesetConfs(["Proxy,https://x/y.list,3600"])).toEqual([["Proxy", "https://x/y.list", 3600]]);
  });

  it("treats [] payloads as literal inline rules", () => {
    expect(fromIniRulesetConfs(["ruleset,[]GEOIP,CN"])).toEqual([["ruleset", "[]GEOIP,CN", 0]]);
    expect(fromIniRulesetConfs(["x,rules/a.list[]FINAL"])).toEqual([["x", "rules/a.list[]FINAL", 0]]);
  });

  it("skips lines without a comma", () => {
    expect(fromIniRulesetConfs([""])).toEqual([]);
    expect(fromIniRulesetConfs(["nocomma"])).toEqual([]);
  });
});
