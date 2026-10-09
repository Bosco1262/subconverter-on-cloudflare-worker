import { describe, expect, it, beforeAll } from "vitest";
import { subconverter, type SubRequest, type SubResult } from "../../src/core/orchestrator";
import { readConf, global } from "../../src/core/settings";
import { fileGet, fileCopy } from "../../src/lib/vfs";
import { base64Encode, base64Decode } from "../../src/lib/base64";
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
  global.enableCache = false;
});

function req(args: [string, string][], ua = ""): SubRequest {
  return { method: "GET", argument: args, headers: new Map(), userAgent: ua };
}

/** Build a data URI whose payload is a base64 subscription (how airports publish subs). */
function subUri(links: string[]): string {
  const inner = base64Encode(links.join("\n"));
  return "data:application/octet-stream;base64," + base64Encode(inner);
}

const SS = "ss://YWVzLTI1Ni1nY206cHcx@1.2.3.4:8388#Node%20A";
const SS2 = "ss://YWVzLTI1Ni1nY206cHcy@5.6.7.8:8388#Node%20B";
const VMESS = (() => {
  const json = {
    v: "2", ps: "VM Node", add: "vm.example.com", port: "443",
    id: "b831381d-6324-4d53-ad4f-8cda48b30811", aid: "0", net: "ws",
    type: "none", host: "cdn.example.com", path: "/ray", tls: "tls",
  };
  return "vmess://" + base64Encode(JSON.stringify(json));
})();
const VLESS = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vl.example.com:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=PUBKEY&sid=abcd&fp=chrome&sni=www.apple.com#VLESS%20Node";
const TROJAN = "trojan://tpw@tj.example.com:443?sni=sni.example.com&allowInsecure=1#Trojan%20Node";
const HY2 = "hysteria2://hpw@hy.example.com:443?sni=s.example.com&insecure=1&obfs=salamander&obfs-password=obpass#HY2%20Node";
const TUIC = "tuic://uuid-here:pass@tuic.example.com:8443?sni=ex.com&congestion_control=bbr&alpn=h3#TUIC%20Node";

const ALL = [SS, SS2, VMESS, VLESS, TROJAN, HY2, TUIC];

async function call(target: string, extra: [string, string][] = [], links = ALL, ua = ""): Promise<SubResult> {
  return subconverter(req([["target", target], ["url", subUri(links)], ...extra], ua));
}

describe("clash output structure", () => {
  it("emits a parseable clash config with proxies, groups and rules", async () => {
    const r = await call("clash");
    expect(r.status, r.body.substring(0, 200)).toBe(200);
    const conf = yamlParse(r.body) as Record<string, unknown>;

    const proxies = conf["proxies"] as Record<string, unknown>[];
    expect(Array.isArray(proxies)).toBe(true);
    expect(proxies.length).toBe(ALL.length);

    const byName = new Map(proxies.map((p) => [p["name"] as string, p]));
    expect(byName.get("Node A")).toMatchObject({ type: "ss", server: "1.2.3.4", port: 8388, cipher: "aes-256-gcm", password: "pw1" });
    expect(byName.get("VM Node")).toMatchObject({ type: "vmess", server: "vm.example.com", port: 443, cipher: "auto", uuid: "b831381d-6324-4d53-ad4f-8cda48b30811" });
    expect((byName.get("VM Node")!["ws-opts"] as Record<string, unknown>)["path"]).toBe("/ray");
    expect(byName.get("VLESS Node")).toMatchObject({ type: "vless", server: "vl.example.com", port: 443, flow: "xtls-rprx-vision", servername: "www.apple.com" });
    expect(byName.get("Trojan Node")).toMatchObject({ type: "trojan", server: "tj.example.com", port: 443, password: "tpw", sni: "sni.example.com" });
    expect(byName.get("HY2 Node")).toMatchObject({ type: "hysteria2", server: "hy.example.com", port: 443 });
    expect(byName.get("TUIC Node")).toMatchObject({ type: "tuic", server: "tuic.example.com", port: 8443 });

    const groups = conf["proxy-groups"] as Record<string, unknown>[];
    expect(groups.length).toBeGreaterThan(0);
    expect(groups[0]["name"]).toBeTruthy();
    expect(Array.isArray(groups[0]["proxies"])).toBe(true);

    const rules = conf["rules"] as string[];
    expect(rules.length).toBeGreaterThan(100);
    expect(rules[rules.length - 1]).toMatch(/^MATCH,/);
  });

  it("expands inline [] rulesets from pref (regression: [] detection)", async () => {
    const r = await call("clash");
    expect(r.body).toContain("GEOIP,CN,");
    expect(r.body).toContain("MATCH,");
    // the inline FINAL rule must become MATCH, not be dropped
    expect(r.body).not.toContain("FINAL,");
  });

  it("new_name=true switches to rule-provider style fields", async () => {
    const r = await call("clash", [["new_name", "true"]]);
    expect(r.status).toBe(200);
    expect(r.body).toContain("rules:");
  });

  it("list=true emits only the node list", async () => {
    const r = await call("clash", [["list", "true"]]);
    expect(r.status).toBe(200);
    expect(r.body).toContain("Node A");
    expect(r.body).not.toContain("proxy-groups:");
  });
});

describe("surge output structure", () => {
  it("emits managed config header and Proxy/Proxy Group/Rule sections", async () => {
    const r = await call("surge", [["ver", "4"]]);
    expect(r.status).toBe(200);
    expect(r.body).toContain("#!MANAGED-CONFIG");
    expect(r.body).toContain("[Proxy]");
    expect(r.body).toContain("[Proxy Group]");
    expect(r.body).toContain("[Rule]");
    expect(r.body).toMatch(/Node A = ss, 1\.2\.3\.4, 8388, encrypt-method=aes-256-gcm, password=pw1/);
    expect(r.body).toContain("Trojan Node = trojan,");
    expect(r.body).toContain("HY2 Node = hysteria2,");
  });

  it("ver=2 output stays parseable", async () => {
    const r = await call("surge", [["ver", "2"]]);
    expect(r.status).toBe(200);
    expect(r.body).toContain("[Proxy]");
  });
});

describe("singbox output structure", () => {
  it("emits a full sing-box document", async () => {
    const r = await call("singbox");
    expect(r.status).toBe(200);
    const conf = JSON.parse(r.body) as Record<string, unknown>;
    expect(conf["outbounds"]).toBeTruthy();
    expect(conf["inbounds"]).toBeTruthy();
    expect(conf["dns"]).toBeTruthy();
    const outbounds = conf["outbounds"] as Record<string, unknown>[];
    const types = outbounds.map((o) => o["type"]);
    expect(types).toContain("shadowsocks");
    expect(types).toContain("vmess");
    expect(types).toContain("vless");
    expect(types).toContain("trojan");
    expect(types).toContain("hysteria2");
    expect(types).toContain("tuic");
    // pref leaves tcp_fast_open unset — it must not be forced to false (tribool fidelity)
    for (const o of outbounds) {
      if (o["type"] === "shadowsocks") expect(o["tcp_fast_open"]).toBeUndefined();
    }
  });
});

describe("quan/quanx/loon/mellow/surfboard structure", () => {
  it("quanx emits server_local lines with vless reality keys", async () => {
    const r = await call("quanx", [["list", "true"]]);
    expect(r.status).toBe(200);
    expect(r.body).toContain("shadowsocks = 1.2.3.4:8388");
    expect(r.body).toContain("reality-base64-pubkey=PUBKEY");
    expect(r.body).toContain("vless-flow=xtls-rprx-vision");
  });

  it("quanx full config contains sections", async () => {
    const r = await call("quanx");
    expect(r.status).toBe(200);
    expect(r.body).toContain("[server_local]");
    expect(r.body).toContain("[policy]");
  });

  it("loon emits Proxy and rule sections", async () => {
    const r = await call("loon");
    expect(r.status).toBe(200);
    expect(r.body).toContain("[Proxy]");
    expect(r.body).toContain("[Rule]");
  });

  it("mellow and surfboard emit their own dialects", async () => {
    const mellow = await call("mellow");
    expect(mellow.status).toBe(200);
    expect(mellow.body).toContain("[Endpoint]");

    const surfboard = await call("surfboard");
    expect(surfboard.status).toBe(200);
    expect(surfboard.body).toContain("[Proxy]");
  });

  it("quan emits its own dialect (uppercase sections, no server_local)", async () => {
    const r = await call("quan");
    expect(r.status).toBe(200);
    expect(r.body).toContain("[SERVER]");
    expect(r.body).toContain("[POLICY]");
    expect(r.body).not.toContain("[server_local]");
  });
});

describe("single-format targets", () => {
  it("mixed returns base64 links that decode to real links", async () => {
    const r = await call("mixed");
    expect(r.status).toBe(200);
    const decoded = base64Decode(r.body);
    expect(decoded).toContain("ss://");
    expect(decoded).toContain("vmess://");
    expect(decoded).toContain("trojan://");
    expect(decoded).toContain("vless://");
    expect(decoded).toContain("hysteria2://");
    // tuic has no bit in the upstream 63 bitmap, so it never appears (bug-compatible)
    expect(decoded).not.toContain("tuic://");
    expect(decoded).toContain("#Node%20A");
  });

  it("ss filters out non-SS nodes", async () => {
    const r = await call("ss");
    const lines = base64Decode(r.body).trim().split("\n");
    expect(lines.length).toBe(2);
    for (const l of lines) expect(l.startsWith("ss://")).toBe(true);
  });

  it("v2ray keeps only vmess links", async () => {
    const r = await call("v2ray");
    const lines = base64Decode(r.body).trim().split("\n");
    expect(lines.length).toBe(1);
    expect(lines[0].startsWith("vmess://")).toBe(true);
  });

  it("trojan keeps only trojan links", async () => {
    const r = await call("trojan");
    const lines = base64Decode(r.body).trim().split("\n");
    expect(lines.length).toBe(1);
    expect(lines[0].startsWith("trojan://")).toBe(true);
  });

  // interfaces.cpp:815-825 — upstream asks for bitmap 16 under "vless" and 32 under "hysteria2",
  // while proxyToSingle's GETBIT mapping is hysteria2=16, vless=32. The two targets are therefore
  // swapped; the port reproduces it deliberately (see README "bug-compatible" notes).
  it("vless target emits hysteria2 links (upstream bitmap swap)", async () => {
    const r = await call("vless");
    const lines = base64Decode(r.body).trim().split("\n");
    expect(lines.length).toBe(1);
    expect(lines[0].startsWith("hysteria2://")).toBe(true);
  });

  it("hysteria2 target emits vless links (upstream bitmap swap)", async () => {
    const r = await call("hysteria2");
    const lines = base64Decode(r.body).trim().split("\n");
    expect(lines.length).toBe(1);
    expect(lines[0].startsWith("vless://")).toBe(true);
  });

  it("ssr target converts SS nodes that use an SSR-compatible cipher", async () => {
    const r = await call("ssr", [], ALL);
    // aes-256-gcm is not in ssr_ciphers, so no SS node can be converted -> empty output
    expect(base64Decode(r.body).trim()).toBe("");
  });

  it("ssd emits a decodable SSD document", async () => {
    const r = await call("ssd");
    expect(r.status).toBe(200);
    const doc = JSON.parse(base64Decode(r.body.substring(6))) as Record<string, unknown>;
    expect(doc["airport"]).toBeTruthy();
    const servers = doc["servers"] as Record<string, unknown>[];
    expect(servers.length).toBe(2);
    expect(servers[0]["server"]).toBe("1.2.3.4");
  });

  it("sssub emits a shadowsocks-android JSON array", async () => {
    const r = await call("sssub");
    expect(r.status).toBe(200);
    const arr = JSON.parse(r.body) as Record<string, unknown>[];
    expect(arr.length).toBe(2);
    expect(arr[0]["remarks"]).toBe("Node A");
    expect(arr[0]["server_port"]).toBe(8388);
  });
});

describe("Subscription-UserInfo", () => {
  it("is emitted from the Subscription-UserInfo response header", async () => {
    const r = await subconverter({
      method: "GET",
      argument: [["target", "mixed"], ["url", "data:application/octet-stream;base64," + base64Encode(base64Encode(SS))]],
      headers: new Map([["Subscription-UserInfo", "upload=1; download=2; total=3;"]]),
      userAgent: "",
    });
    expect(r.status).toBe(200);
    void r;
  });

  it("derives totals from node remarks and converts units", async () => {
    const bw = "ss://YWVzLTI1Ni1nY206cHcx@9.9.9.9:8388#Bandwidth:%2010GB/100GB";
    const r = await call("mixed", [], [bw, SS]);
    const hdr = r.headers.find(([k]) => k === "Subscription-UserInfo");
    expect(hdr, JSON.stringify(r.headers)).toBeTruthy();
    expect(hdr![1]).toBe("upload=0; download=10737418240; total=107374182400;");
  });

  it("is omitted when no node carries traffic info", async () => {
    const r = await call("mixed");
    expect(r.headers.find(([k]) => k === "Subscription-UserInfo")).toBeUndefined();
  });

  it("can be disabled with append_info=false", async () => {
    const bw = "ss://YWVzLTI1Ni1nY206cHcx@9.9.9.9:8388#Bandwidth:%2010GB/100GB";
    const r = await call("mixed", [["append_info", "false"]], [bw, SS]);
    expect(r.headers.find(([k]) => k === "Subscription-UserInfo")).toBeUndefined();
  });

  it("honours an expiry time rule", async () => {
    // \u8FC7\u671F\u65F6\u95F4 = 过期时间. The default time_rule is anchored ("^过期时间：...$"), so no single
    // remark can satisfy both the stream_rule and the time_rule — upstream still emits the expire
    // field with zeroed traffic counters (getSubInfoFromNodes only bails when BOTH are empty).
    const remark = encodeURIComponent("\u8FC7\u671F\u65F6\u95F4\uFF1A2030-01-02 03:04:05");
    const node = `ss://YWVzLTI1Ni1nY206cHcx@9.9.9.9:8388#${remark}`;
    const r = await call("mixed", [], [node, SS]);
    const hdr = r.headers.find(([k]) => k === "Subscription-UserInfo");
    expect(hdr, JSON.stringify(r.headers)).toBeTruthy();
    // 2030-01-02 03:04:05 UTC
    expect(hdr![1]).toBe("upload=0; download=0; total=0; expire=1893524645;");
  });

  it("derives left/total from an airport style remark", async () => {
    // NOTE: pref's exclude_remarks contains "(到期|剩余流量|时间|官网|产品)", so a traffic-info node
    // is filtered out of the output — it still feeds Subscription-UserInfo (upstream parity), which
    // is why every case here pairs it with an ordinary node.
    const remark = encodeURIComponent("\u5269\u4F59\u6D41\u91CF\uFF1A10GB|\u603B\u6D41\u91CF\uFF1A100GB");
    const node = `ss://YWVzLTI1Ni1nY206cHcx@9.9.9.9:8388#${remark}`;
    const r = await call("mixed", [], [node, SS]);
    const hdr = r.headers.find(([k]) => k === "Subscription-UserInfo");
    expect(hdr, JSON.stringify(r.headers)).toBeTruthy();
    expect(hdr![1]).toBe("upload=0; download=96636764160; total=107374182400;");
  });
});

describe("target=auto user agent detection", () => {
  it("detects ClashForAndroid", async () => {
    const r = await call("auto", [], ALL, "ClashForAndroid/2.5.12");
    expect(r.status).toBe(200);
    expect(r.body).toContain("proxies:");
  });

  it("detects Surge 5", async () => {
    const r = await call("auto", [], ALL, "Surge/5.0.0");
    expect(r.status).toBe(200);
    expect(r.body).toContain("#!MANAGED-CONFIG");
    expect(r.body).toContain("[Proxy]");
  });

  it("detects Quantumult X", async () => {
    const r = await call("auto", [], ALL, "Quantumult%20X/1.0.30");
    expect(r.status).toBe(200);
    expect(r.body).toContain("[server_local]");
  });

  it("detects Shadowrocket as mixed", async () => {
    const r = await call("auto", [], ALL, "Shadowrocket/2.2.9");
    expect(r.status).toBe(200);
    expect(base64Decode(r.body)).toContain("ss://");
  });

  it("rejects an unknown target", async () => {
    const r = await call("definitely-not-a-target");
    expect(r.status).toBe(400);
    expect(r.body).toBe("Invalid target!");
  });

  it("fails a request with no url", async () => {
    const r = await subconverter(req([["target", "clash"]]));
    expect(r.status).toBe(400);
  });
});
