import { describe, expect, it, beforeAll } from "vitest";
import { surgeConfToClashHandler } from "../../src/routes/handlers";
import { readConf } from "../../src/core/settings";
import { fileGet, fileCopy } from "../../src/lib/vfs";
import { base64Encode } from "../../src/lib/base64";
import { parse as yamlParse } from "yaml";

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
});

const SURGE = `[General]
loglevel = notify

[Proxy]
DIRECT = direct
REJECT = reject
SS1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pw1, udp-relay=true
SS2 = ss, 5.6.7.8, 8388, encrypt-method=aes-256-gcm, password=pw2

[Proxy Group]
PROXY = select, SS1, SS2, DIRECT
Auto = url-test, SS1, SS2, url = http://www.gstatic.com/generate_204, interval = 300

[Rule]
DOMAIN-SUFFIX,google.com,PROXY
DOMAIN-KEYWORD,github,Auto
GEOIP,CN,DIRECT
FINAL,PROXY
`;

function dataLink(text: string): string {
  return "data:application/octet-stream;base64," + base64Encode(text);
}

describe("/surge2clash", () => {
  it("converts a minimal surge config to clash yaml", async () => {
    // The handler rebuilds the query string with joinArguments() (urlEncode per value) and then
    // urlDecode()s the "link=" value again, mirroring upstream where httplib hands over decoded
    // request.params. Feeding raw values is therefore equivalent to what index.ts passes through.
    // The link must return the Surge config itself (not a base64 subscription wrapper).
    const r = await surgeConfToClashHandler({
      method: "GET",
      argument: [["link", dataLink(SURGE)]],
      headers: new Map(),
      userAgent: "",
    });
    console.log("STATUS=" + r.status + " LEN=" + r.body.length + " BODY_HEAD=" + JSON.stringify(r.body.substring(0, 300)));
    expect(r.status).toBe(200);
    expect(r.body).toContain("proxies:");
    expect(r.body).toContain("proxy-groups:");
    expect(r.body).toContain("rules:");
  });

  it("rejects requests without a link argument", async () => {
    const r = await surgeConfToClashHandler({ method: "GET", argument: [], headers: new Map(), userAgent: "" });
    expect(r.status).toBe(400);
  });

  it("keeps [Rule] lines and emits DIRECT/REJECT policy shims", async () => {
    const r = await surgeConfToClashHandler({
      method: "GET",
      argument: [["link", dataLink(SURGE)]],
      headers: new Map(),
      userAgent: "",
    });
    expect(r.status).toBe(200);
    const conf = yamlParse(r.body) as Record<string, unknown>;

    const proxies = conf["proxies"] as Record<string, unknown>[];
    expect(proxies.map((p) => p["name"])).toEqual(["SS1", "SS2"]);

    // Upstream parity: proxyToClash() rebuilds proxy-groups from an empty extra_proxy_group, so the
    // [Proxy Group] policies are replaced by the [Proxy] DIRECT/REJECT shims (interfaces.cpp:1062).
    const groups = conf["proxy-groups"] as Record<string, unknown>[];
    expect(groups.map((g) => g["name"])).toEqual(["DIRECT", "REJECT"]);
    expect(groups[0]).toMatchObject({ name: "DIRECT", type: "select", proxies: ["DIRECT"] });
    expect(groups[1]).toMatchObject({ name: "REJECT", type: "select", proxies: ["REJECT"] });

    const rules = conf["rules"] as string[];
    expect(rules).toEqual([
      "DOMAIN-SUFFIX,google.com,PROXY",
      "DOMAIN-KEYWORD,github,Auto",
      "GEOIP,CN,DIRECT",
      "FINAL,PROXY",
    ]);
  });
});
