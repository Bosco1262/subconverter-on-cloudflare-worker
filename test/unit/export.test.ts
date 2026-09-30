import { describe, expect, it } from "vitest";
import { newProxy, Proxy, ProxyType } from "../../src/core/proxy";
import { proxyToClashCore, proxyToClash } from "../../src/core/export/clash";
import { proxyToSurge } from "../../src/core/export/surge";
import { proxyToSingle } from "../../src/core/export/single";
import { newExtraSettings, ProxyGroupConfig, ProxyGroupType } from "../../src/core/extra";
import { tribool } from "../../src/lib/tribool";
import { parse as yamlParse } from "yaml";

function tb(): tribool {
  return new tribool();
}

function makeNodes(): Proxy[] {
  const ss = newProxy();
  ss.Type = ProxyType.Shadowsocks;
  ss.Remark = "SS Node";
  ss.Hostname = "1.2.3.4";
  ss.Port = 8388;
  ss.EncryptMethod = "aes-256-gcm";
  ss.Password = "pw1";
  ss.UDP.set(true);

  const vm = newProxy();
  vm.Type = ProxyType.VMess;
  vm.Remark = "VM Node";
  vm.Hostname = "5.6.7.8";
  vm.Port = 443;
  vm.UserId = "b831381d-6324-4d53-ad4f-8cda48b30811";
  vm.EncryptMethod = "auto";
  vm.TransferProtocol = "ws";
  vm.Host = "cdn.example.com";
  vm.Path = "/ray";
  vm.TLSSecure = true;

  return [ss, vm];
}

describe("proxyToClash", () => {
  it("emits proxies and groups", () => {
    const nodes = makeNodes();
    const base: Record<string, unknown> = { port: 7890, mode: "rule" };
    const groups: ProxyGroupConfig[] = [
      {
        Name: "PROXY", Type: ProxyGroupType.Select, Proxies: ["VM Node", "[]DIRECT"], UsingProvider: [],
        Url: "", Interval: 0, Timeout: 0, Tolerance: 0, Strategy: 0, Lazy: tb(),
        DisableUdp: tb(), Persistent: tb(),
        EvaluateBeforeUse: tb(), Extras: {},
      },
    ];
    const ext = newExtraSettings();
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = false;
    proxyToClashCore(nodes, base, groups, false, ext);
    const proxies = base["proxies"] as Record<string, unknown>[];
    expect(proxies.length).toBe(2);
    expect(proxies[0]["type"]).toBe("ss");
    expect(proxies[0]["server"]).toBe("1.2.3.4");
    expect(proxies[0]["port"]).toBe(8388);
    expect(proxies[0]["udp"]).toBe(true);
    expect(proxies[1]["type"]).toBe("vmess");
    expect((proxies[1]["ws-opts"] as Record<string, unknown>)["path"]).toBe("/ray");
    const grps = base["proxy-groups"] as Record<string, unknown>[];
    expect(grps.length).toBe(1);
    expect(grps[0]["type"]).toBe("select");
    expect(grps[0]["proxies"]).toEqual(["VM Node", "DIRECT"]);
  });

  it("full clash output parses back as YAML", () => {
    const nodes = makeNodes();
    const baseConf = "port: 7890\nmode: rule\n";
    const ext = newExtraSettings();
    ext.clash_new_field_name = true;
    ext.enable_rule_generator = false;
    const out = proxyToClash(nodes, baseConf, [], [], false, ext);
    const parsed = yamlParse(out) as Record<string, unknown>;
    expect(parsed["port"]).toBe(7890);
    const proxies = parsed["proxies"] as Record<string, unknown>[];
    expect(proxies.length).toBe(2);
    expect(proxies[0]["cipher"]).toBe("aes-256-gcm");
  });
});

describe("proxyToSurge", () => {
  it("emits surge ini with proxies", () => {
    const nodes = makeNodes();
    const baseConf = "[General]\nsome = value\n";
    const ext = newExtraSettings();
    ext.enable_rule_generator = false;
    const out = proxyToSurge(nodes, baseConf, [], [], 4, ext);
    expect(out).toContain("DIRECT = direct");
    expect(out).toContain("SS Node = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pw1");
    expect(out).toContain("VM Node = vmess, 5.6.7.8, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811");
    expect(out).toContain("udp-relay=true");
    expect(out).toContain("[General]");
  });
});

describe("proxyToSingle", () => {
  it("emits base64 mixed links", () => {
    const nodes = makeNodes();
    const ext = newExtraSettings();
    ext.nodelist = true;
    const out = proxyToSingle(nodes, 63, ext);
    expect(out).toContain("ss://");
    expect(out).toContain("vmess://");
  });
});
