// Port of src/generator/config/subexport.cpp proxyToClash (lines 252-927)

import { Document, Scalar, YAMLMap, YAMLSeq, stringify as yamlStringify, parse as yamlParse } from "yaml";
import { Proxy, ProxyType, getProxyTypeName } from "../proxy";
import { replaceAllDistinct, startsWith, getUrlArg, toInt, join } from "../../lib/string";
import { urlDecode, urlEncode } from "../../lib/urlencode";
import { tribool } from "../../lib/tribool";
import { loadYaml } from "../../lib/yaml";
import { global } from "../settings";
import type { extra_settings, ProxyGroupConfig, RulesetContent } from "../extra";
import { proxyGroupTypeStr, proxyGroupStrategyStr, ProxyGroupType, BalanceStrategy } from "../extra";
import { clashr_protocols, clashr_obfs, clash_ssr_ciphers, processRemark, groupGenerate, ScalarStr, yamlScalarFromString, formatterShortId, replaceAll } from "./common";
import { rulesetToClashStr, renderClashScript } from "../ruleconvert";
import { newProxy } from "../proxy";

type YValue = string | number | boolean | ScalarStr | Record<string, unknown> | unknown[];

function pushAlpn(target: Record<string, unknown>, key: string, x: Proxy): void {
  if (x.AlpnList.length > 0) {
    target[key] = [...x.AlpnList];
  } else if (x.Alpn.length > 0) {
    target[key] = [x.Alpn];
  }
}

function digitStr(v: string): boolean {
  if (v.length === 0) return false;
  for (const c of v) if (c < "0" || c > "9") return false;
  return true;
}

function digitPassword(target: Record<string, unknown>, x: Proxy): void {
  if (digitStr(x.Password)) target["password"] = new ScalarStr(x.Password);
}

function remarkRef(x: Proxy): { v: string } {
  return { get v() { return x.Remark; }, set v(val: string) { x.Remark = val; } };
}

export function proxyToClashCore(
  nodes: Proxy[], yamlnode: Record<string, unknown>, extraProxyGroup: ProxyGroupConfig[], clashR: boolean, ext: extra_settings,
): void {
  const proxies: YValue[] = [];
  const nodelist: Proxy[] = [];
  const remarksList: string[] = [];
  let original_groups: unknown[] = Array.isArray(yamlnode["proxy-groups"]) ? (yamlnode["proxy-groups"] as unknown[]) : Array.isArray(yamlnode["Proxy Group"]) ? (yamlnode["Proxy Group"] as unknown[]) : [];

  for (const x of nodes) {
    const singleproxy: Record<string, unknown> = {};
    const type = getProxyTypeName(x.Type);
    const pluginopts = replaceAllDistinct(x.PluginOption, ";", "&");
    if (ext.append_proxy_type) x.Remark = "[" + type + "] " + x.Remark;

    processRemark(remarkRef(x), remarksList, false);

    const udp = new tribool(ext.udp);
    const xudp = new tribool(ext.xudp);
    const scv = new tribool(ext.skip_cert_verify);
    const tfo = new tribool(ext.tfo);
    udp.define(x.UDP);
    xudp.define(x.XUDP);
    scv.define(x.AllowInsecure);
    tfo.define(x.TCPFastOpen);
    singleproxy["name"] = x.Remark;
    singleproxy["server"] = x.Hostname;
    singleproxy["port"] = x.Port;

    let skip = false;
    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        // latest clash core removed support for chacha20 encryption
        if (ext.filter_deprecated && x.EncryptMethod === "chacha20") {
          skip = true;
          break;
        }
        singleproxy["type"] = "ss";
        singleproxy["cipher"] = x.EncryptMethod;
        singleproxy["password"] = x.Password;
        digitPassword(singleproxy, x);
        switch (x.Plugin) {
          case "simple-obfs":
          case "obfs-local": {
            const opts: Record<string, unknown> = {};
            opts["mode"] = urlDecode(getUrlArg(pluginopts, "obfs"));
            opts["host"] = urlDecode(getUrlArg(pluginopts, "obfs-host"));
            singleproxy["plugin"] = "obfs";
            singleproxy["plugin-opts"] = opts;
            break;
          }
          case "v2ray-plugin": {
            const opts: Record<string, unknown> = {};
            opts["mode"] = getUrlArg(pluginopts, "mode");
            opts["host"] = getUrlArg(pluginopts, "host");
            opts["path"] = getUrlArg(pluginopts, "path");
            opts["tls"] = pluginopts.includes("tls");
            opts["mux"] = pluginopts.includes("mux");
            if (!scv.isUndef()) opts["skip-cert-verify"] = scv.get();
            singleproxy["plugin"] = "v2ray-plugin";
            singleproxy["plugin-opts"] = opts;
            break;
          }
        }
        break;
      }
      case ProxyType.VMess: {
        singleproxy["type"] = "vmess";
        singleproxy["uuid"] = x.UserId;
        singleproxy["alterId"] = x.AlterId;
        singleproxy["cipher"] = x.EncryptMethod;
        singleproxy["tls"] = x.TLSSecure;
        pushAlpn(singleproxy, "alpn", x);
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        if (x.ServerName.length > 0) singleproxy["servername"] = x.ServerName;
        switch (x.TransferProtocol) {
          case "tcp":
            break;
          case "ws": {
            singleproxy["network"] = x.TransferProtocol;
            const opts: Record<string, unknown> = {};
            if (ext.clash_new_field_name) {
              opts["path"] = x.Path;
              const headers: Record<string, unknown> = {};
              if (x.Host.length > 0) headers["Host"] = x.Host;
              if (x.Edge.length > 0) headers["Edge"] = x.Edge;
              if (Object.keys(headers).length > 0) opts["headers"] = headers;
              singleproxy["ws-opts"] = opts;
            } else {
              singleproxy["ws-path"] = x.Path;
              const headers: Record<string, unknown> = {};
              if (x.Host.length > 0) headers["Host"] = x.Host;
              if (x.Edge.length > 0) headers["Edge"] = x.Edge;
              if (Object.keys(headers).length > 0) singleproxy["ws-headers"] = headers;
              opts["path"] = x.Path;
              const headers2: Record<string, unknown> = {};
              if (x.Host.length > 0) headers2["Host"] = x.Host;
              if (x.Edge.length > 0) headers2["Edge"] = x.Edge;
              if (Object.keys(headers2).length > 0) opts["headers"] = headers2;
              singleproxy["ws-opts"] = opts;
            }
            break;
          }
          case "http": {
            singleproxy["network"] = x.TransferProtocol;
            const opts: Record<string, unknown> = {};
            opts["method"] = "GET";
            opts["path"] = [x.Path];
            const headers: Record<string, unknown> = {};
            if (x.Host.length > 0) headers["Host"] = [x.Host];
            if (x.Edge.length > 0) headers["Edge"] = [x.Edge];
            if (Object.keys(headers).length > 0) opts["headers"] = headers;
            singleproxy["http-opts"] = opts;
            break;
          }
          case "h2": {
            singleproxy["network"] = x.TransferProtocol;
            const opts: Record<string, unknown> = {};
            opts["path"] = x.Path;
            if (x.Host.length > 0) opts["host"] = [x.Host];
            singleproxy["h2-opts"] = opts;
            break;
          }
          case "grpc":
            singleproxy["network"] = x.TransferProtocol;
            singleproxy["servername"] = x.Host;
            singleproxy["grpc-opts"] = { "grpc-service-name": x.Path };
            break;
          default:
            skip = true;
            break;
        }
        break;
      }
      case ProxyType.ShadowsocksR: {
        // ignoring all nodes with unsupported obfs, protocols and encryption
        if (ext.filter_deprecated) {
          if (!clashR && !clash_ssr_ciphers.includes(x.EncryptMethod)) {
            skip = true;
            break;
          }
          if (!clashr_protocols.includes(x.Protocol)) {
            skip = true;
            break;
          }
          if (!clashr_obfs.includes(x.OBFS)) {
            skip = true;
            break;
          }
        }
        singleproxy["type"] = "ssr";
        singleproxy["cipher"] = x.EncryptMethod === "none" ? "dummy" : x.EncryptMethod;
        singleproxy["password"] = x.Password;
        digitPassword(singleproxy, x);
        singleproxy["protocol"] = x.Protocol;
        singleproxy["obfs"] = x.OBFS;
        if (clashR) {
          singleproxy["protocolparam"] = x.ProtocolParam;
          singleproxy["obfsparam"] = x.OBFSParam;
        } else {
          singleproxy["protocol-param"] = x.ProtocolParam;
          singleproxy["obfs-param"] = x.OBFSParam;
        }
        break;
      }
      case ProxyType.SOCKS5: {
        singleproxy["type"] = "socks5";
        if (x.Username.length > 0) singleproxy["username"] = x.Username;
        if (x.Password.length > 0) {
          singleproxy["password"] = x.Password;
          if (digitStr(x.Password)) singleproxy["password"] = new ScalarStr(x.Password);
        }
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        break;
      }
      case ProxyType.HTTP:
      case ProxyType.HTTPS: {
        singleproxy["type"] = "http";
        if (x.Username.length > 0) singleproxy["username"] = x.Username;
        if (x.Password.length > 0) {
          singleproxy["password"] = x.Password;
          if (digitStr(x.Password)) singleproxy["password"] = new ScalarStr(x.Password);
        }
        singleproxy["tls"] = x.TLSSecure;
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        break;
      }
      case ProxyType.Trojan: {
        singleproxy["type"] = "trojan";
        singleproxy["password"] = x.Password;
        if (x.ServerName.length > 0) singleproxy["sni"] = x.ServerName;
        else if (x.Host.length > 0) singleproxy["sni"] = x.Host;
        pushAlpn(singleproxy, "alpn", x);
        if (digitStr(x.Password)) singleproxy["password"] = new ScalarStr(x.Password);
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        switch (x.TransferProtocol) {
          case "tcp":
            break;
          case "grpc":
            singleproxy["network"] = x.TransferProtocol;
            if (x.Path.length > 0) singleproxy["grpc-opts"] = { "grpc-service-name": x.Path };
            break;
          case "ws":
            singleproxy["network"] = x.TransferProtocol;
            singleproxy["ws-opts"] = { path: x.Path, ...(x.Host.length > 0 ? { headers: { Host: x.Host } } : {}) };
            break;
        }
        break;
      }
      case ProxyType.Snell: {
        singleproxy["type"] = "snell";
        singleproxy["psk"] = x.Password;
        if (x.SnellVersion !== 0) singleproxy["version"] = x.SnellVersion;
        if (x.OBFS.length > 0) {
          const opts: Record<string, unknown> = {};
          opts["mode"] = x.OBFS;
          if (x.Host.length > 0) opts["host"] = x.Host;
          singleproxy["obfs-opts"] = opts;
        }
        if (digitStr(x.Password)) singleproxy["password"] = new ScalarStr(x.Password);
        break;
      }
      case ProxyType.WireGuard: {
        singleproxy["type"] = "wireguard";
        singleproxy["public-key"] = x.PublicKey;
        singleproxy["private-key"] = x.PrivateKey;
        singleproxy["ip"] = x.SelfIP;
        if (x.SelfIPv6.length > 0) singleproxy["ipv6"] = x.SelfIPv6;
        if (x.PreSharedKey.length > 0) singleproxy["preshared-key"] = x.PreSharedKey;
        if (x.DnsServers.length > 0) singleproxy["dns"] = [...x.DnsServers];
        if (x.Mtu > 0) singleproxy["mtu"] = x.Mtu;
        break;
      }
      case ProxyType.Hysteria: {
        singleproxy["type"] = "hysteria";
        singleproxy["auth_str"] = x.Auth;
        singleproxy["auth-str"] = x.Auth;
        singleproxy["up"] = x.UpMbps;
        singleproxy["down"] = x.DownMbps;
        if (x.Ports.length > 0) singleproxy["ports"] = x.Ports;
        if (!tfo.isUndef()) singleproxy["fast-open"] = tfo.get();
        if (x.FakeType.length > 0) singleproxy["protocol"] = x.FakeType;
        if (x.ServerName.length > 0) singleproxy["sni"] = x.ServerName;
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        if (x.Insecure === "1") singleproxy["skip-cert-verify"] = true;
        pushAlpn(singleproxy, "alpn", x);
        if (x.OBFSParam.length > 0) singleproxy["obfs"] = x.OBFSParam;
        break;
      }
      case ProxyType.Hysteria2: {
        singleproxy["type"] = "hysteria2";
        singleproxy["password"] = x.Password;
        singleproxy["auth"] = x.Password;
        if (x.PublicKey.length > 0) singleproxy["ca-str"] = x.PublicKey;
        if (x.Fingerprint.length > 0) singleproxy["fingerprint"] = x.Fingerprint;
        if (x.ServerName.length > 0) singleproxy["sni"] = x.ServerName;
        if (x.UpMbps.length > 0) singleproxy["up"] = x.UpMbps;
        if (x.DownMbps.length > 0) singleproxy["down"] = x.DownMbps;
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        pushAlpn(singleproxy, "alpn", x);
        if (x.OBFSParam.length > 0) singleproxy["obfs"] = x.OBFSParam;
        if (x.OBFSPassword.length > 0) singleproxy["obfs-password"] = x.OBFSPassword;
        if (x.Ports.length > 0) singleproxy["ports"] = x.Ports;
        break;
      }
      case ProxyType.TUIC: {
        singleproxy["type"] = "tuic";
        if (x.Password.length > 0) singleproxy["password"] = x.Password;
        if (x.UserId.length > 0) singleproxy["uuid"] = x.UserId;
        if (x.token.length > 0) singleproxy["token"] = x.token;
        if (x.ServerName.length > 0) singleproxy["sni"] = x.ServerName;
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        pushAlpn(singleproxy, "alpn", x);
        singleproxy["disable-sni"] = x.DisableSni.get();
        singleproxy["reduce-rtt"] = x.ReduceRtt.get();
        singleproxy["request-timeout"] = x.RequestTimeout;
        if (x.UdpRelayMode.length > 0 && (x.UdpRelayMode === "native" || x.UdpRelayMode === "quic")) {
          singleproxy["udp-relay-mode"] = x.UdpRelayMode;
        }
        if (x.CongestionControl.length > 0) singleproxy["congestion-controller"] = x.CongestionControl;
        break;
      }
      case ProxyType.AnyTLS: {
        singleproxy["type"] = "anytls";
        if (x.Password.length > 0) singleproxy["password"] = x.Password;
        if (x.Fingerprint.length > 0) singleproxy["fingerprint"] = x.Fingerprint;
        if (!udp.isUndef()) singleproxy["udp"] = udp.get();
        if (x.SNI.length > 0) singleproxy["sni"] = x.SNI;
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        if (x.AlpnList.length > 0) singleproxy["alpn"] = [...x.AlpnList];
        break;
      }
      case ProxyType.Mieru: {
        singleproxy["type"] = "mieru";
        if (x.Password.length > 0) singleproxy["password"] = x.Password;
        if (x.Username.length > 0) singleproxy["username"] = x.Username;
        if (x.Multiplexing.length > 0) singleproxy["multiplexing"] = x.Multiplexing;
        if (x.TransferProtocol.length > 0) singleproxy["transport"] = x.TransferProtocol;
        if (x.Ports.length > 0) {
          singleproxy["port-range"] = x.Ports;
          delete singleproxy["port"];
        }
        break;
      }
      case ProxyType.VLESS: {
        singleproxy["type"] = "vless";
        singleproxy["uuid"] = x.UserId;
        singleproxy["tls"] = x.TLSSecure;
        if (x.AlpnList.length > 0) singleproxy["alpn"] = [...x.AlpnList];
        if (!tfo.isUndef()) singleproxy["tfo"] = tfo.get();
        if (xudp.get() && udp.get()) singleproxy["xudp"] = true;
        if (x.PacketEncoding.length > 0) singleproxy["packet-encoding"] = x.PacketEncoding;
        if (x.Flow.length > 0) singleproxy["flow"] = x.Flow;
        if (x.Encryption.length > 0 && x.Encryption !== "none") singleproxy["encryption"] = x.Encryption;
        if (!scv.isUndef()) singleproxy["skip-cert-verify"] = scv.get();
        if (x.PublicKey.length > 0 || x.ServerName.length > 0 || x.ShortId.length > 0) {
          const reality: Record<string, unknown> = {};
          if (x.PublicKey.length > 0) reality["public-key"] = x.PublicKey;
          if (x.ShortId.length > 0) reality["short-id"] = "" + x.ShortId;
          if (Object.keys(reality).length > 0) singleproxy["reality-opts"] = reality;
        }
        if (x.ServerName.length > 0) singleproxy["servername"] = x.ServerName;
        if (x.PublicKey.length > 0 || x.Flow === "xtls-rprx-vision") singleproxy["client-fingerprint"] = "chrome";
        if (x.Fingerprint.length > 0) singleproxy["client-fingerprint"] = x.Fingerprint;
        switch (x.TransferProtocol) {
          case "tcp":
            singleproxy["network"] = x.TransferProtocol;
            break;
          case "ws": {
            singleproxy["network"] = x.TransferProtocol;
            if (ext.clash_new_field_name) {
              const opts: Record<string, unknown> = {};
              opts["path"] = x.Path;
              const headers: Record<string, unknown> = {};
              if (x.Host.length > 0) headers["Host"] = x.Host;
              if (x.Edge.length > 0) headers["Edge"] = x.Edge;
              if (Object.keys(headers).length > 0) opts["headers"] = headers;
              if (!x.V2rayHttpUpgrade.isUndef()) opts["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
              singleproxy["ws-opts"] = opts;
            } else {
              singleproxy["ws-path"] = x.Path;
              const headers: Record<string, unknown> = {};
              if (x.Host.length > 0) headers["Host"] = x.Host;
              if (x.Edge.length > 0) headers["Edge"] = x.Edge;
              if (Object.keys(headers).length > 0) singleproxy["ws-headers"] = headers;
              const opts: Record<string, unknown> = {};
              opts["path"] = x.Path;
              const headers2: Record<string, unknown> = {};
              if (x.Host.length > 0) headers2["Host"] = x.Host;
              if (x.Edge.length > 0) headers2["Edge"] = x.Edge;
              if (Object.keys(headers2).length > 0) opts["headers"] = headers2;
              if (!x.V2rayHttpUpgrade.isUndef()) opts["v2ray-http-upgrade"] = x.V2rayHttpUpgrade.get();
              singleproxy["ws-opts"] = opts;
            }
            break;
          }
          case "http": {
            singleproxy["network"] = x.TransferProtocol;
            const opts: Record<string, unknown> = {};
            opts["method"] = "GET";
            opts["path"] = [x.Path];
            const headers: Record<string, unknown> = {};
            if (x.Host.length > 0) headers["Host"] = [x.Host];
            if (x.Edge.length > 0) headers["Edge"] = [x.Edge];
            if (Object.keys(headers).length > 0) opts["headers"] = headers;
            singleproxy["http-opts"] = opts;
            break;
          }
          case "h2": {
            singleproxy["network"] = x.TransferProtocol;
            const opts: Record<string, unknown> = {};
            opts["path"] = x.Path;
            if (x.Host.length > 0) opts["host"] = [x.Host];
            singleproxy["h2-opts"] = opts;
            break;
          }
          case "xhttp": {
            singleproxy["network"] = x.TransferProtocol;
            const opts: Record<string, unknown> = {};
            opts["path"] = x.Path;
            if (x.Host.length > 0) opts["host"] = x.Host;
            for (const [k, v] of Object.entries(x.XHTTPOptions)) {
              opts[k] = yamlScalarFromString(v);
            }
            if (x.Edge.length > 0) {
              opts["headers"] = { Edge: x.Edge };
            }
            singleproxy["xhttp-opts"] = opts;
            break;
          }
          case "grpc":
            singleproxy["network"] = x.TransferProtocol;
            singleproxy["grpc-opts"] = { "grpc-mode": x.GRPCMode, "grpc-service-name": x.GRPCServiceName };
            break;
          default:
            skip = true;
            break;
        }
        break;
      }
      default:
        skip = true;
        break;
    }
    if (skip) continue;

    // Snell UDP is available in mihomo-compatible Snell v3+ nodes.
    if (udp.get() && (x.Type !== ProxyType.Snell || x.SnellVersion >= 3) && x.Type !== ProxyType.TUIC)
      singleproxy["udp"] = true;
    if (!clashR && x.UnderlyingProxy.length > 0) singleproxy["dialer-proxy"] = x.UnderlyingProxy;

    proxies.push(singleproxy);
    remarksList.push(x.Remark);
    nodelist.push(x);
  }

  if (ext.nodelist) {
    const provider: Record<string, unknown> = { proxies: proxies };
    Object.keys(yamlnode).forEach((k) => delete yamlnode[k]);
    Object.assign(yamlnode, provider);
    return;
  }

  if (ext.clash_new_field_name) yamlnode["proxies"] = proxies;
  else yamlnode["Proxy"] = proxies;

  const originalGroups: unknown[] = [];
  for (const x of extraProxyGroup) {
    const singlegroup: Record<string, unknown> = {};
    const filteredNodelist: string[] = [];

    singlegroup["name"] = x.Name;
    if (x.Type === ProxyGroupType.Smart) singlegroup["type"] = "url-test";
    else singlegroup["type"] = proxyGroupTypeStr(x.Type);

    switch (x.Type) {
      case ProxyGroupType.Select:
      case ProxyGroupType.Relay:
        break;
      case ProxyGroupType.LoadBalance:
        singlegroup["strategy"] = proxyGroupStrategyStr(x.Strategy);
        // fallthrough
      case ProxyGroupType.Smart:
      case ProxyGroupType.URLTest:
        if (!x.Lazy.isUndef()) singlegroup["lazy"] = x.Lazy.get();
        // fallthrough
      case ProxyGroupType.Fallback:
        singlegroup["url"] = x.Url;
        if (x.Interval > 0) singlegroup["interval"] = x.Interval;
        if (x.Tolerance > 0) singlegroup["tolerance"] = x.Tolerance;
        break;
      default:
        continue;
    }
    if (!x.DisableUdp.isUndef()) singlegroup["disable-udp"] = x.DisableUdp.get();
    for (const [key, value] of Object.entries(x.Extras)) {
      singlegroup[key] = yamlScalarFromString(value);
    }

    for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, true, ext);

    if (x.UsingProvider.length > 0) singlegroup["use"] = [...x.UsingProvider];
    else {
      if (filteredNodelist.length === 0) filteredNodelist.push("DIRECT");
    }
    if (filteredNodelist.length > 0) singlegroup["proxies"] = [...filteredNodelist];

    let replaceFlag = false;
    for (let i = 0; i < originalGroups.length; i++) {
      const og = originalGroups[i];
      if (og && typeof og === "object" && (og as Record<string, unknown>)["name"] === x.Name) {
        originalGroups[i] = singlegroup;
        replaceFlag = true;
        break;
      }
    }
    if (!replaceFlag) originalGroups.push(singlegroup);
  }

  if (ext.clash_new_field_name) yamlnode["proxy-groups"] = originalGroups;
  else yamlnode["Proxy Group"] = originalGroups;
}

function dumpYaml(yamlnode: Record<string, unknown>, proxyBlock = false, groupBlock = false): string {
  const doc = new Document(yamlnode, { version: "1.1" });
  const walk = (node: unknown) => {
    if (node instanceof YAMLSeq) {
      for (const item of node.items) {
        if (!proxyBlock && item instanceof YAMLMap) item.flow = true;
        walk(item);
      }
    } else if (node instanceof YAMLMap) {
      for (const pair of node.items) walk(pair.value);
    }
  };
  // apply flow style to proxies and proxy-groups entries unless block requested
  const applyFlow = (key: string) => {
    const v = doc.get(key, true);
    if (v instanceof YAMLSeq) {
      for (const item of v.items) {
        if (item instanceof YAMLMap) item.flow = !proxyBlock;
        if (!groupBlock && key !== "proxies" && key !== "Proxy") {
          // groups handled below
        }
      }
    }
  };
  applyFlow("proxies");
  applyFlow("Proxy");
  applyFlow("proxy-groups");
  applyFlow("Proxy Group");
  return yamlStringify(doc, { lineWidth: 0 });
}

export function proxyToClash(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[],
  clashR: boolean, ext: extra_settings,
): string {
  const yamlnode = loadYaml(baseConf);
  if (!yamlnode) {
    console.error("Clash base loader failed");
    return "";
  }

  proxyToClashCore(nodes, yamlnode, extraProxyGroup, clashR, ext);

  if (ext.nodelist) return formatterShortId(dumpYaml(yamlnode));

  if (!ext.enable_rule_generator) return formatterShortId(dumpYaml(yamlnode));

  if (ext.managed_config_prefix.length > 0 || ext.clash_script) {
    if (yamlnode["mode"] !== undefined) {
      if (ext.clash_new_field_name) yamlnode["mode"] = ext.clash_script ? "script" : "rule";
      else yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
    }
    renderClashScript(yamlnode, rulesetContentArray, ext.managed_config_prefix, ext.clash_script, ext.overwrite_original_rules, ext.clash_classical_ruleset);
    return formatterShortId(dumpYaml(yamlnode));
  }

  const rulesStr = rulesetToClashStr(yamlnode, rulesetContentArray, ext.overwrite_original_rules, ext.clash_new_field_name);
  const yamlnodeStr = dumpYaml(yamlnode);
  let outputContent = yamlnodeStr + rulesStr;
  outputContent = replaceAll(outputContent, "!<str> ", "");
  return formatterShortId(outputContent);
}

export function proxyToClashNodelist(nodes: Proxy[], yamlnodeObj: Record<string, unknown>, extraProxyGroup: ProxyGroupConfig[], clashR: boolean, ext: extra_settings): string {
  proxyToClashCore(nodes, yamlnodeObj, extraProxyGroup, clashR, ext);
  return formatterShortId(dumpYaml(yamlnodeObj));
}
