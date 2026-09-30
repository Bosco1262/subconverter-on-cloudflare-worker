import { describe, expect, it } from "vitest";
import { newProxy, Proxy, ProxyType } from "../../src/core/proxy";
import { explode, explodeSub } from "../../src/core/parser";

describe("explodeSS", () => {
  it("plain (SIP002-ish legacy) format", () => {
    // ss://base64(method:password@server:port)
    const link = "ss://" + Buffer.from("aes-256-gcm:pass1@1.2.3.4:8388", "utf8").toString("base64");
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Shadowsocks);
    expect(node.Hostname).toBe("1.2.3.4");
    expect(node.Port).toBe(8388);
    expect(node.EncryptMethod).toBe("aes-256-gcm");
    expect(node.Password).toBe("pass1");
    expect(node.Remark).toBe("1.2.3.4:8388");
  });

  it("SIP002 with userinfo and remark", () => {
    const userinfo = Buffer.from("chacha20-ietf-poly1305:secretpw").toString("base64url");
    const link = `ss://${userinfo}@example.com:443#My%20Node`;
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Shadowsocks);
    expect(node.Hostname).toBe("example.com");
    expect(node.Port).toBe(443);
    expect(node.Password).toBe("secretpw");
    expect(node.Remark).toBe("My Node");
  });
});

describe("explodeSSR", () => {
  it("full ssr link (SSR-specific protocol 鈫?SSR node)", () => {
    const inner = `1.2.3.4:8388:auth_aes128_md5:aes-128-cfb:plain:${Buffer.from("ssrpass").toString("base64")}/?obfsparam=${Buffer.from("ob").toString("base64")}&remarks=${Buffer.from("TestSSR").toString("base64")}&group=${Buffer.from("MyGroup").toString("base64")}`;
    const link2 = "ssr://" + Buffer.from(inner, "utf8").toString("base64");
    const node = newProxy();
    explode(link2, node);
    expect(node.Type).toBe(ProxyType.ShadowsocksR);
    expect(node.Hostname).toBe("1.2.3.4");
    expect(node.Port).toBe(8388);
    expect(node.Protocol).toBe("auth_aes128_md5");
    expect(node.OBFS).toBe("plain");
    expect(node.Password).toBe("ssrpass");
    expect(node.Remark).toBe("TestSSR");
    expect(node.Group).toBe("MyGroup");
  });

  it("origin/plain + ss cipher is converted to plain SS node (upstream behavior)", () => {
    const inner = `1.2.3.4:8388:origin:aes-128-cfb:plain:${Buffer.from("ssrpass").toString("base64")}/?remarks=${Buffer.from("TestSS").toString("base64")}`;
    const link = "ssr://" + Buffer.from(inner, "utf8").toString("base64");
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Shadowsocks);
    expect(node.EncryptMethod).toBe("aes-128-cfb");
    expect(node.Remark).toBe("TestSS");
  });
});

describe("explodeVMess", () => {
  it("standard v2rayN base64 json link", () => {
    const json = { v: "2", ps: "JP Node", add: "jp.example.com", port: "443", id: "b831381d-6324-4d53-ad4f-8cda48b30811", aid: "0", net: "ws", type: "none", host: "cdn.example.com", path: "/ws", tls: "tls" };
    const link = "vmess://" + Buffer.from(JSON.stringify(json), "utf8").toString("base64");
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.VMess);
    expect(node.UserId).toBe("b831381d-6324-4d53-ad4f-8cda48b30811");
    expect(node.TransferProtocol).toBe("ws");
    expect(node.Host).toBe("cdn.example.com");
    expect(node.Path).toBe("/ws");
    expect(node.TLSSecure).toBe(true);
    expect(node.Remark).toBe("JP Node");
  });

  it("port 0 rejected", () => {
    const json = { v: "2", ps: "bad", add: "x.com", port: "0", id: "b831381d-6324-4d53-ad4f-8cda48b30811", aid: "0", net: "tcp", tls: "" };
    const link = "vmess://" + Buffer.from(JSON.stringify(json), "utf8").toString("base64");
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Unknown);
  });
});

describe("explodeTrojan", () => {
  it("trojan link with sni", () => {
    const link = "trojan://pass123@example.com:443?sni=sni.example.com&allowInsecure=1#TJ";
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Trojan);
    expect(node.Password).toBe("pass123");
    expect(node.Hostname).toBe("example.com");
    expect(node.Port).toBe(443);
    expect(node.ServerName).toBe("sni.example.com");
    expect(node.Remark).toBe("TJ");
    expect(node.AllowInsecure.get()).toBe(true);
  });

  it("trojan v2rayN ws style", () => {
    const link = "trojan://pw@1.1.1.1:443?type=ws&security=tls&path=%2Fwspath&sni=h.com#n1";
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Trojan);
    expect(node.TransferProtocol).toBe("ws");
    expect(node.Path).toBe("/wspath");
    expect(node.Host).toBe("h.com");
  });
});

describe("explodeVless", () => {
  it("vless reality link", () => {
    const link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=PUBKEY&sid=abcd&fp=chrome&sni=www.apple.com#VL";
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.VLESS);
    expect(node.TLSSecure).toBe(true);
    expect(node.TLSStr).toBe("reality");
    expect(node.PublicKey).toBe("PUBKEY");
    expect(node.ShortId).toBe("abcd");
    expect(node.Flow).toBe("xtls-rprx-vision");
    expect(node.Fingerprint).toBe("chrome");
  });
});

describe("explodeHysteria2", () => {
  it("hysteria2 link", () => {
    const link = "hysteria2://pw@1.2.3.4:443?sni=s.example.com&insecure=1&obfs=salamander&obfs-password=obpass#HY2";
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.Hysteria2);
    expect(node.Password).toBe("pw");
    expect(node.ServerName).toBe("s.example.com");
    expect(node.OBFSPassword).toBe("obpass");
    expect(node.Remark).toBe("HY2");
  });
});

describe("explodeTuic", () => {
  it("tuic v5 link", () => {
    const link = "tuic://uuid-here:pass@1.2.3.4:8443?sni=ex.com&congestion_control=bbr&alpn=h3#TUIC";
    const node = newProxy();
    explode(link, node);
    expect(node.Type).toBe(ProxyType.TUIC);
    expect(node.UserId).toBe("uuid-here");
    expect(node.Password).toBe("pass");
    expect(node.CongestionControl).toBe("bbr");
  });
});

describe("explodeSub", () => {
  it("parses base64 subscription of mixed links", () => {
    const links = [
      "ss://" + Buffer.from("aes-256-gcm:p1@1.1.1.1:8388", "utf8").toString("base64"),
      "trojan://pw@2.2.2.2:443?sni=s.com#troj",
    ];
    const sub = Buffer.from(links.join("\n"), "utf8").toString("base64");
    const nodes: Proxy[] = [];
    explodeSub(sub, nodes);
    expect(nodes.length).toBe(2);
    expect(nodes[0].Type).toBe(ProxyType.Shadowsocks);
    expect(nodes[1].Type).toBe(ProxyType.Trojan);
  });

  it("parses clash yaml", () => {
    const yaml = `
proxies:
  - name: "ss1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "pw"
    udp: true
  - name: "vm1"
    type: vmess
    server: 5.6.7.8
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    ws-opts:
      path: /ray
      headers:
        Host: v.example.com
`;
    const nodes: Proxy[] = [];
    explodeSub(yaml, nodes);
    expect(nodes.length).toBe(2);
    expect(nodes[0].Type).toBe(ProxyType.Shadowsocks);
    expect(nodes[0].UDP.get()).toBe(true);
    expect(nodes[1].Type).toBe(ProxyType.VMess);
    expect(nodes[1].Host).toBe("v.example.com");
    expect(nodes[1].Path).toBe("/ray");
  });

  it("parses surge ini", () => {
    const ini = `[Proxy]
SS1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=abc123, udp-relay=true
VM1 = vmess, 5.6.7.8, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, tls=true, ws=true, ws-path=/ws
`;
    const nodes: Proxy[] = [];
    explodeSub(ini, nodes);
    expect(nodes.length).toBe(2);
    expect(nodes[0].Type).toBe(ProxyType.Shadowsocks);
    expect(nodes[0].Password).toBe("abc123");
    expect(nodes[0].UDP.get()).toBe(true);
    expect(nodes[1].Type).toBe(ProxyType.VMess);
    expect(nodes[1].TransferProtocol).toBe("ws");
  });

  it("parses sing-box json", () => {
    const json = JSON.stringify({
      inbounds: [],
      outbounds: [
        { type: "shadowsocks", tag: "sb1", server: "1.2.3.4", server_port: 8388, method: "aes-256-gcm", password: "pw" },
        { type: "trojan", tag: "sb2", server: "5.6.7.8", server_port: 443, password: "tpw", tls: { enabled: true, server_name: "s.example.com" } },
      ],
      route: { rules: [] },
    });
    const nodes: Proxy[] = [];
    explodeSub(json, nodes);
    expect(nodes.length).toBe(2);
    expect(nodes[0].Type).toBe(ProxyType.Shadowsocks);
    expect(nodes[1].Type).toBe(ProxyType.Trojan);
    expect(nodes[1].ServerName).toBe("s.example.com");
  });
});
