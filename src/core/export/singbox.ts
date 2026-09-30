// Port of src/generator/config/subexport.cpp proxyToSingBox (2602-3159)

import { Proxy, ProxyType, getProxyTypeName } from "../proxy";
import { split, trim } from "../../lib/string";
import { tribool } from "../../lib/tribool";
import { global } from "../settings";
import type { extra_settings, ProxyGroupConfig, RulesetContent } from "../extra";
import { ProxyGroupType } from "../extra";
import { processRemark, groupGenerate } from "./common";

function remarkRef(x: Proxy): { v: string } {
  return { get v() { return x.Remark; }, set v(val: string) { x.Remark = val; } };
}

function formatSingBoxInterval(interval: number): string {
  let result = "";
  let v = interval;
  if (v >= 3600) {
    result += Math.floor(v / 3600) + "h";
    v %= 3600;
  }
  if (v >= 60) {
    result += Math.floor(v / 60) + "m";
    v %= 60;
  }
  if (v > 0) result += v + "s";
  return result;
}

function buildSingBoxTransport(proxy: Proxy): Record<string, unknown> {
  const transport: Record<string, unknown> = {};
  switch (proxy.TransferProtocol) {
    case "http": {
      if (proxy.Host.length > 0) transport["host"] = proxy.Host;
      transport["type"] = proxy.TransferProtocol;
      transport["path"] = proxy.Path.length === 0 ? "/" : proxy.Path;
      const headers: Record<string, unknown> = {};
      if (proxy.Host.length > 0) headers["Host"] = proxy.Host;
      if (proxy.Edge.length > 0) headers["Edge"] = proxy.Edge;
      transport["headers"] = headers;
      break;
    }
    case "ws": {
      transport["type"] = proxy.TransferProtocol;
      transport["path"] = proxy.Path.length === 0 ? "/" : proxy.Path;
      const headers: Record<string, unknown> = {};
      if (proxy.Host.length > 0) headers["Host"] = proxy.Host;
      if (proxy.Edge.length > 0) headers["Edge"] = proxy.Edge;
      transport["headers"] = headers;
      break;
    }
    case "grpc": {
      transport["type"] = "grpc";
      if (proxy.Path.length > 0) transport["service_name"] = proxy.Path;
      break;
    }
    default:
      break;
  }
  return transport;
}

function addSingBoxCommonMembers(proxy: Record<string, unknown>, x: Proxy, type: string): void {
  proxy["type"] = type;
  proxy["tag"] = x.Remark;
  proxy["server"] = x.Hostname;
  proxy["server_port"] = x.Port;
}

function addHeadersTo(transport: Record<string, unknown>, x: Proxy): void {
  const headers: Record<string, unknown> = {};
  if (x.Host.length > 0) headers["Host"] = x.Host;
  if (x.Edge.length > 0) headers["Edge"] = x.Edge;
  transport["headers"] = headers;
}

function stringArrayToJsonArray(array: string, delimiter: string): string[] {
  return split(array, delimiter).map((x) => trim(x));
}

function vectorToJsonArray(array: string[]): string[] {
  return array.map((x) => trim(x));
}

function isNumeric(str: string): boolean {
  if (str.length === 0) return false;
  for (const c of str) if (c < "0" || c > "9") return false;
  return true;
}

function parseIntSafe(s: string): number {
  const n = parseInt(s, 10);
  return isNaN(n) ? 0 : n;
}

export function proxyToSingBoxCore(
  nodes: Proxy[], json: Record<string, unknown>, rulesetContentArray: RulesetContent[],
  extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): void {
  void rulesetContentArray;
  const outbounds: Record<string, unknown>[] = [];
  const nodelist: Proxy[] = [];
  const remarksList: string[] = [];
  const search = " Mbps";

  if (!ext.nodelist) {
    outbounds.push({ type: "direct", tag: "DIRECT" });
  }

  for (const x of nodes) {
    const type = getProxyTypeName(x.Type);
    if (ext.append_proxy_type) x.Remark = "[" + type + "] " + x.Remark;

    processRemark(remarkRef(x), remarksList, false);

    const udp = new tribool(ext.udp), tfo = new tribool(ext.tfo), scv = new tribool(ext.skip_cert_verify), xudp = new tribool(ext.xudp);
    udp.define(x.UDP);
    xudp.define(x.XUDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);

    const proxy: Record<string, unknown> = {};
    let skip = false;
    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        addSingBoxCommonMembers(proxy, x, "shadowsocks");
        proxy["method"] = x.EncryptMethod;
        proxy["password"] = x.Password;
        if (x.Plugin.length > 0 && x.PluginOption.length > 0) {
          const plugin = x.Plugin;
          if (plugin === "simple-obfs" || plugin === "obfs") x.Plugin = "obfs-local";
          if (x.Plugin !== "obfs-local" && x.Plugin !== "v2ray-plugin") {
            skip = true;
            break;
          }
          proxy["plugin"] = plugin;
          proxy["plugin_opts"] = x.PluginOption;
        }
        break;
      }
      case ProxyType.VMess: {
        addSingBoxCommonMembers(proxy, x, "vmess");
        proxy["uuid"] = x.UserId;
        proxy["alter_id"] = x.AlterId;
        proxy["security"] = x.EncryptMethod;
        const transport = buildSingBoxTransport(x);
        if (Object.keys(transport).length > 0) proxy["transport"] = transport;
        break;
      }
      case ProxyType.VLESS: {
        addSingBoxCommonMembers(proxy, x, "vless");
        proxy["uuid"] = x.UserId;
        if (x.Encryption.length > 0 && x.Encryption !== "none") proxy["encryption"] = x.Encryption;
        if (xudp.get() && udp.get()) proxy["packet_encoding"] = "xudp";
        if (x.Flow.length > 0) proxy["flow"] = x.Flow;
        if (x.PacketEncoding.length > 0) proxy["packet_encoding"] = x.PacketEncoding;
        const vlesstransport: Record<string, unknown> = {};
        switch (x.TransferProtocol) {
          case "tcp":
            break;
          case "ws": {
            vlesstransport["path"] = x.Path.length === 0 ? "/" : x.Path;
            if (x.Host.length > 0) vlesstransport["Host"] = x.Host;
            if (x.Edge.length > 0) vlesstransport["Edge"] = x.Edge;
            vlesstransport["type"] = "ws";
            addHeadersTo(vlesstransport, x);
            proxy["transport"] = vlesstransport;
            break;
          }
          case "http": {
            vlesstransport["type"] = "http";
            vlesstransport["host"] = x.Host;
            vlesstransport["method"] = "GET";
            vlesstransport["path"] = x.Path;
            addHeadersTo(vlesstransport, x);
            proxy["transport"] = vlesstransport;
            break;
          }
          case "h2": {
            vlesstransport["type"] = "httpupgrade";
            vlesstransport["host"] = x.Host;
            vlesstransport["path"] = x.Path;
            proxy["transport"] = vlesstransport;
            break;
          }
          case "grpc": {
            vlesstransport["type"] = "grpc";
            vlesstransport["service_name"] = x.GRPCServiceName;
            proxy["transport"] = vlesstransport;
            break;
          }
          default:
            skip = true;
            break;
        }
        break;
      }
      case ProxyType.Trojan: {
        addSingBoxCommonMembers(proxy, x, "trojan");
        proxy["password"] = x.Password;
        const transport = buildSingBoxTransport(x);
        if (Object.keys(transport).length > 0) proxy["transport"] = transport;
        break;
      }
      case ProxyType.WireGuard: {
        proxy["type"] = "wireguard";
        proxy["tag"] = x.Remark;
        proxy["inet4_bind_address"] = x.SelfIP;
        const addresses = [x.SelfIP + "/32"];
        proxy["local_address"] = addresses;
        if (x.SelfIPv6.length > 0) proxy["inet6_bind_address"] = x.SelfIPv6;
        proxy["private_key"] = x.PrivateKey;
        const peer: Record<string, unknown> = {};
        peer["server"] = x.Hostname;
        peer["server_port"] = x.Port;
        peer["public_key"] = x.PublicKey;
        if (x.PreSharedKey.length > 0) peer["pre_shared_key"] = x.PreSharedKey;
        if (x.AllowedIPs.length > 0) peer["allowed_ips"] = stringArrayToJsonArray(x.AllowedIPs, ",");
        if (x.ClientId.length > 0) peer["reserved"] = stringArrayToJsonArray(x.ClientId, ",");
        if (x.Password.length > 0) proxy["pre_shared_key"] = x.Password;
        proxy["peers"] = [peer];
        proxy["mtu"] = x.Mtu;
        break;
      }
      case ProxyType.HTTP:
      case ProxyType.HTTPS: {
        addSingBoxCommonMembers(proxy, x, "http");
        proxy["username"] = x.Username;
        proxy["password"] = x.Password;
        break;
      }
      case ProxyType.SOCKS5: {
        addSingBoxCommonMembers(proxy, x, "socks");
        proxy["version"] = "5";
        proxy["username"] = x.Username;
        proxy["password"] = x.Password;
        break;
      }
      case ProxyType.Hysteria: {
        addSingBoxCommonMembers(proxy, x, "hysteria");
        proxy["auth_str"] = x.Auth;
        if (isNumeric(x.UpMbps)) {
          proxy["up_mbps"] = parseIntSafe(x.UpMbps);
        } else {
          x.UpMbps = x.UpMbps.replace(" Mbps", "");
          proxy["up_mbps"] = parseIntSafe(x.UpMbps);
        }
        if (isNumeric(x.DownMbps)) {
          proxy["down_mbps"] = parseIntSafe(x.DownMbps);
        } else {
          x.DownMbps = x.DownMbps.replace(" Mbps", "");
          proxy["down_mbps"] = parseIntSafe(x.DownMbps);
        }
        if (!x.TLSSecure) {
          const tls: Record<string, unknown> = {};
          tls["enabled"] = true;
          if (x.Alpn.length > 0) tls["alpn"] = stringArrayToJsonArray(x.Alpn, ",");
          if (x.ServerName.length > 0) tls["server_name"] = x.ServerName;
          tls["insecure"] = scv.get();
          proxy["tls"] = tls;
        }
        if (x.FakeType.length > 0 && x.FakeType !== "none") proxy["network"] = x.FakeType;
        if (x.OBFSParam.length > 0) proxy["obfs"] = x.OBFSParam;
        break;
      }
      case ProxyType.Hysteria2: {
        addSingBoxCommonMembers(proxy, x, "hysteria2");
        proxy["password"] = x.Password;
        if (!x.TLSSecure) {
          const tls: Record<string, unknown> = {};
          tls["enabled"] = true;
          if (x.ServerName.length > 0) tls["server_name"] = x.ServerName;
          if (x.Alpn.length > 0) tls["alpn"] = stringArrayToJsonArray(x.Alpn, ",");
          if (x.PublicKey.length > 0) tls["certificate"] = x.PublicKey;
          tls["insecure"] = scv.get();
          proxy["tls"] = tls;
        }
        if (x.UpMbps.length > 0) {
          let up = x.UpMbps;
          if (!isNumeric(up)) up = up.replace(" Mbps", "");
          proxy["up_mbps"] = parseIntSafe(up);
        }
        if (x.DownMbps.length > 0) {
          let down = x.DownMbps;
          if (!isNumeric(down)) down = down.replace(" Mbps", "");
          proxy["down_mbps"] = parseIntSafe(down);
        }
        if (x.OBFSParam.length > 0) {
          const obfs: Record<string, unknown> = {};
          obfs["type"] = x.OBFSParam;
          if (x.OBFSPassword.length > 0) obfs["password"] = x.OBFSPassword;
          proxy["obfs"] = obfs;
        }
        break;
      }
      case ProxyType.TUIC: {
        addSingBoxCommonMembers(proxy, x, "tuic");
        proxy["password"] = x.Password;
        proxy["uuid"] = x.UserId;
        if (!x.TLSSecure && x.Alpn.length > 0) {
          const tls: Record<string, unknown> = {};
          tls["enabled"] = true;
          if (!scv.isUndef()) tls["insecure"] = scv.get();
          if (x.ServerName.length > 0) tls["server_name"] = x.ServerName;
          if (x.Alpn.length > 0) tls["alpn"] = stringArrayToJsonArray(x.Alpn, ",");
          if (!x.DisableSni.isUndef()) tls["disable_sni"] = x.DisableSni.get();
          proxy["tls"] = tls;
        }
        if (x.CongestionControl.length > 0) proxy["congestion_control"] = x.CongestionControl;
        if (x.UdpRelayMode.length > 0) proxy["udp_relay_mode"] = x.UdpRelayMode;
        if (!x.ReduceRtt.isUndef()) proxy["zero_rtt_handshake"] = x.ReduceRtt.get();
        break;
      }
      case ProxyType.AnyTLS: {
        addSingBoxCommonMembers(proxy, x, "anytls");
        proxy["password"] = x.Password;
        const tls: Record<string, unknown> = {};
        tls["enabled"] = true;
        if (!scv.isUndef()) tls["insecure"] = scv.get();
        if (x.SNI.length > 0) tls["server_name"] = x.SNI;
        if (x.AlpnList.length > 0) tls["alpn"] = vectorToJsonArray(x.AlpnList);
        if (x.Fingerprint.length > 0) {
          const utls: Record<string, unknown> = {};
          utls["enabled"] = true;
          utls["fingerprint"] = x.Fingerprint;
          tls["utls"] = utls;
        }
        proxy["tls"] = tls;
        break;
      }
      default:
        skip = true;
        break;
    }
    if (skip) continue;

    if (x.TLSSecure) {
      const tls: Record<string, unknown> = {};
      tls["enabled"] = true;
      if (x.ServerName.length > 0) tls["server_name"] = x.ServerName;
      if (x.AlpnList.length > 0) tls["alpn"] = vectorToJsonArray(x.AlpnList);
      else if (x.Alpn.length > 0) tls["alpn"] = stringArrayToJsonArray(x.Alpn, ",");
      tls["insecure"] = scv.get();
      if (x.Type === ProxyType.VLESS) {
        const reality: Record<string, unknown> = {};
        if (x.PublicKey.length > 0 || x.ShortId.length > 0) {
          const utls: Record<string, unknown> = {};
          utls["enabled"] = true;
          utls["fingerprint"] = "chrome";
          tls["utls"] = utls;
          reality["enabled"] = true;
          if (x.PublicKey.length > 0) reality["public_key"] = x.PublicKey;
          if (x.ShortId.length > 0) reality["short_id"] = x.ShortId;
          else reality["short_id"] = "";
          tls["reality"] = reality;
        }
      }
      proxy["tls"] = tls;
    }
    if (x.UnderlyingProxy.length > 0) proxy["detour"] = x.UnderlyingProxy;
    if (!udp.isUndef() && !udp.get()) proxy["network"] = "tcp";
    if (!tfo.isUndef()) proxy["tcp_fast_open"] = tfo.get();

    nodelist.push(x);
    remarksList.push(x.Remark);
    outbounds.push(proxy);
  }

  if (ext.nodelist) {
    json["outbounds"] = outbounds;
    return;
  }

  for (const x of extraProxyGroup) {
    const filteredNodelist: string[] = [];
    let type: string;
    switch (x.Type) {
      case ProxyGroupType.Select:
        type = "selector";
        break;
      case ProxyGroupType.URLTest:
      case ProxyGroupType.Fallback:
      case ProxyGroupType.LoadBalance:
        type = "urltest";
        break;
      default:
        continue;
    }
    for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, true, ext);

    if (filteredNodelist.length === 0) filteredNodelist.push("DIRECT");

    const group: Record<string, unknown> = {};
    group["type"] = type;
    group["tag"] = x.Name;
    group["outbounds"] = [...filteredNodelist];

    if (x.Type === ProxyGroupType.URLTest) {
      group["url"] = x.Url;
      group["interval"] = formatSingBoxInterval(x.Interval);
      if (x.Tolerance > 0) group["tolerance"] = x.Tolerance;
    }
    outbounds.push(group);
  }

  if (global.singBoxAddClashModes) {
    const globalGroup: Record<string, unknown> = {};
    globalGroup["type"] = "selector";
    globalGroup["tag"] = "GLOBAL";
    globalGroup["outbounds"] = ["DIRECT", ...remarksList];
    outbounds.push(globalGroup);
  }

  json["outbounds"] = outbounds;
}

export function proxyToSingBox(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): string {
  let json: Record<string, unknown>;
  if (!ext.nodelist) {
    try {
      json = JSON.parse(baseConf) as Record<string, unknown>;
    } catch {
      console.error("sing-box base loader failed");
      return "";
    }
    if (!json || typeof json !== "object" || Array.isArray(json)) {
      console.error("sing-box base loader failed");
      return "";
    }
  } else {
    json = {};
  }

  proxyToSingBoxCore(nodes, json, rulesetContentArray, extraProxyGroup, ext);

  if (ext.nodelist || !ext.enable_rule_generator) return JSON.stringify(json);

  rulesetToSingBox(json, rulesetContentArray, ext.overwrite_original_rules);

  return JSON.stringify(json);
}

import { rulesetToSingBox } from "../ruleconvert";
