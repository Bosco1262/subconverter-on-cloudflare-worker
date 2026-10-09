// Port of src/generator/config/subexport.cpp proxyToSurge (lines 953-1283)

import { INIReader } from "../../lib/ini";
import { getProxyTypeName, Proxy, ProxyType } from "../proxy";
import { join, randomStr, replaceAllDistinct, startsWith } from "../../lib/string";
import { tribool } from "../../lib/tribool";
import { global } from "../settings";
import type { extra_settings, ProxyGroupConfig, RulesetContent } from "../extra";
import { proxyGroupTypeStr, ProxyGroupType } from "../extra";
import { processRemark, groupGenerate, generatePeer, isNumeric } from "./common";
import { isIPv4, isIPv6 } from "../parser/util";
import { rulesetToSurge } from "../ruleconvert";

function remarkRef(x: Proxy): { v: string } {
  return { get v() { return x.Remark; }, set v(val: string) { x.Remark = val; } };
}

export function proxyToSurge(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[],
  surgeVer: number, ext: extra_settings,
): string {
  const ini = new INIReader();
  let outputNodelist = "";
  const nodelist: Proxy[] = [];
  let localPort = 1080;
  const remarksList: string[] = [];

  ini.store_any_line = true;
  ini.addDirectSaveSection("General");
  ini.addDirectSaveSection("Replica");
  ini.addDirectSaveSection("Rule");
  ini.addDirectSaveSection("MITM");
  ini.addDirectSaveSection("Script");
  ini.addDirectSaveSection("Host");
  ini.addDirectSaveSection("URL Rewrite");
  ini.addDirectSaveSection("Header Rewrite");
  if (ini.parse(baseConf) !== 0 && !ext.nodelist) {
    console.error("Surge base loader failed");
    return "";
  }

  ini.setCurrentSection("Proxy");
  ini.eraseSection("Proxy");
  ini.set("Proxy", "{NONAME}", "DIRECT = direct");

  for (const x of nodes) {
    if (ext.append_proxy_type) {
      const type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }
    processRemark(remarkRef(x), remarksList);

    const hostname = x.Hostname, sni = x.ServerName, username = x.Username, password = x.Password, method = x.EncryptMethod;
    const id = x.UserId, transproto = x.TransferProtocol, host = x.Host, edge = x.Edge, path = x.Path;
    const protocol = x.Protocol, protoparam = x.ProtocolParam, obfs = x.OBFS, obfsparam = x.OBFSParam;
    const plugin = x.Plugin, pluginopts = x.PluginOption, underlying_proxy = x.UnderlyingProxy;
    const port = String(x.Port);
    const tlssecure = x.TLSSecure;

    const udp = new tribool(ext.udp), tfo = new tribool(ext.tfo), scv = new tribool(ext.skip_cert_verify), tls13 = new tribool(ext.tls13);
    udp.define(x.UDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);
    tls13.define(x.TLS13);

    let proxy = "";
    const headers: string[] = [];
    const search = " Mbps";
    let skip = false;

    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        if (surgeVer >= 3 || surgeVer === -3) {
          proxy = "ss, " + hostname + ", " + port + ", encrypt-method=" + method + ", password=" + password;
        } else {
          proxy = "custom, " + hostname + ", " + port + ", " + method + ", " + password + ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module";
        }
        if (plugin.length > 0) {
          switch (plugin) {
            case "simple-obfs":
            case "obfs-local":
              if (pluginopts.length > 0) proxy += "," + replaceAllDistinct(pluginopts, ";", ",");
              break;
            default:
              skip = true;
              break;
          }
        }
        break;
      }
      case ProxyType.VMess: {
        if (surgeVer < 4 && surgeVer !== -3) {
          skip = true;
          break;
        }
        proxy = "vmess, " + hostname + ", " + port + ", username=" + id + ", tls=" + (tlssecure ? "true" : "false") + ", vmess-aead=" + (x.AlterId === 0 ? "true" : "false");
        if (tlssecure && !tls13.isUndef()) proxy += ", tls13=" + (tls13.get() ? "true" : "false");
        switch (transproto) {
          case "tcp":
            break;
          case "ws":
            if (host.length === 0) proxy += ", ws=true, ws-path=" + path + ", sni=" + hostname;
            else proxy += ", ws=true, ws-path=" + path + ", sni=" + host;
            if (host.length > 0) headers.push("Host:" + host);
            if (edge.length > 0) headers.push("Edge:" + edge);
            if (headers.length > 0) proxy += ", ws-headers=" + join(headers, "|");
            break;
          default:
            skip = true;
            break;
        }
        if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
        break;
      }
      case ProxyType.ShadowsocksR: {
        if (ext.surge_ssr_path.length === 0 || surgeVer < 2) {
          skip = true;
          break;
        }
        const args = [
          "-l", String(localPort), "-s", hostname, "-p", port, "-m", method, "-k", password, "-o", obfs, "-O", protocol,
        ];
        if (obfsparam.length > 0) {
          args.push("-g");
          args.push(obfsparam);
        }
        if (protoparam.length > 0) {
          args.push("-G");
          args.push(protoparam);
        }
        proxy = 'external, exec="' + ext.surge_ssr_path + '", args="';
        proxy += join(args, '", args="');
        proxy += '", local-port=' + localPort;
        if (isIPv4(hostname) || isIPv6(hostname)) proxy += ", addresses=" + hostname;
        else if (global.surgeResolveHostname) proxy += ", addresses="; // DNS resolution unavailable on Workers
        localPort++;
        break;
      }
      case ProxyType.SOCKS5: {
        proxy = "socks5, " + hostname + ", " + port;
        if (username.length > 0) proxy += ", username=" + username;
        if (password.length > 0) proxy += ", password=" + password;
        if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
        break;
      }
      case ProxyType.HTTPS: {
        if (surgeVer === -3) {
          proxy = "https, " + hostname + ", " + port + ", " + username + ", " + password;
          if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
          break;
        }
        proxy = "http, " + hostname + ", " + port;
        if (username.length > 0) proxy += ", username=" + username;
        if (password.length > 0) proxy += ", password=" + password;
        proxy += ", tls=" + (x.TLSSecure ? "true" : "false");
        if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
        break;
      }
      case ProxyType.HTTP: {
        proxy = "http, " + hostname + ", " + port;
        if (username.length > 0) proxy += ", username=" + username;
        if (password.length > 0) proxy += ", password=" + password;
        proxy += ", tls=" + (x.TLSSecure ? "true" : "false");
        if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
        break;
      }
      case ProxyType.Trojan: {
        if (surgeVer < 4 && surgeVer !== -3) {
          skip = true;
          break;
        }
        proxy = "trojan, " + hostname + ", " + port + ", password=" + password;
        if (x.SnellVersion !== 0) proxy += ", version=" + x.SnellVersion;
        if (sni.length > 0) proxy += ", sni=" + sni;
        else if (host.length > 0) proxy += ", sni=" + host;
        if (transproto === "ws") {
          proxy += ", ws=true, ws-path=" + path;
          if (host.length > 0) headers.push('Host:"' + host + '"');
          if (headers.length > 0) proxy += ", ws-headers=" + join(headers, "|");
        }
        if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
        break;
      }
      case ProxyType.Snell: {
        proxy = "snell, " + hostname + ", " + port + ", psk=" + password;
        if (obfs.length > 0) {
          proxy += ", obfs=" + obfs;
          if (host.length > 0) proxy += ", obfs-host=" + host;
        }
        if (x.SnellVersion !== 0) proxy += ", version=" + x.SnellVersion;
        break;
      }
      case ProxyType.Hysteria2: {
        if (surgeVer < 4) {
          skip = true;
          break;
        }
        proxy = "hysteria2, " + hostname + ", " + port + ", password=" + password;
        if (x.DownMbps.length > 0) {
          if (!isNumeric(x.DownMbps)) {
            x.DownMbps = x.DownMbps.replace(" Mbps", "");
          }
          proxy += ", download-bandwidth=" + x.DownMbps;
        }
        if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        if (x.Fingerprint.length > 0) proxy += ",server-cert-fingerprint-sha256=" + x.Fingerprint;
        if (x.ServerName.length > 0) proxy += ",sni=" + x.ServerName;
        if (x.Ports.length > 0) proxy += ",port-hopping=" + x.Ports;
        break;
      }
      case ProxyType.AnyTLS: {
        if (surgeVer < 4) {
          skip = true;
          break;
        }
        proxy = "anytls, " + hostname + ", " + port + ", password=" + password;
        if (x.SNI.length > 0) proxy += ", sni=" + x.SNI;
        if (!scv.isUndef()) proxy += ", skip-cert-verify=" + scv.getStr();
        if (x.Fingerprint.length > 0) proxy += ", server-cert-fingerprint-sha256=" + x.Fingerprint;
        if (!tls13.isUndef()) proxy += ", tls13=" + (tls13.get() ? "true" : "false");
        break;
      }
      case ProxyType.WireGuard: {
        if (surgeVer < 4 && surgeVer !== -3) {
          skip = true;
          break;
        }
        const section = randomStr(5);
        const realSection = "WireGuard " + section;
        proxy = "wireguard, section-name=" + section;
        if (x.TestUrl.length > 0) proxy += ", test-url=" + x.TestUrl;
        ini.set(realSection, "private-key", x.PrivateKey);
        ini.set(realSection, "self-ip", x.SelfIP);
        if (x.SelfIPv6.length > 0) ini.set(realSection, "self-ip-v6", x.SelfIPv6);
        if (x.PreSharedKey.length > 0) ini.set(realSection, "preshared-key", x.PreSharedKey);
        if (x.DnsServers.length > 0) ini.set(realSection, "dns-server", join(x.DnsServers, ","));
        if (x.Mtu > 0) ini.set(realSection, "mtu", String(x.Mtu));
        if (x.KeepAlive > 0) ini.set(realSection, "keepalive", String(x.KeepAlive));
        ini.set(realSection, "peer", "(" + generatePeer(x) + ")");
        break;
      }
      default:
        skip = true;
        break;
    }
    if (skip) continue;

    if (!tfo.isUndef()) proxy += ", tfo=" + tfo.getStr();
    if (!udp.isUndef()) proxy += ", udp-relay=" + udp.getStr();
    if (underlying_proxy !== "") proxy += ", underlying-proxy=" + underlying_proxy;
    if (ext.nodelist) outputNodelist += x.Remark + " = " + proxy + "\n";
    else {
      ini.set("Proxy", "{NONAME}", x.Remark + " = " + proxy);
      nodelist.push(x);
    }
    remarksList.push(x.Remark);
  }

  if (ext.nodelist) return outputNodelist;

  ini.setCurrentSection("Proxy Group");
  ini.eraseSection("Proxy Group");
  for (const x of extraProxyGroup) {
    const filteredNodelist: string[] = [];
    let group = "";

    switch (x.Type) {
      case ProxyGroupType.Select:
      case ProxyGroupType.Smart:
      case ProxyGroupType.URLTest:
      case ProxyGroupType.Fallback:
        break;
      case ProxyGroupType.LoadBalance:
        if (surgeVer < 1 && surgeVer !== -3) continue;
        break;
      case ProxyGroupType.SSID:
        group = x.Proxies[0] !== undefined ? proxyGroupTypeStr(x.Type) + ",default=" + x.Proxies[0] + "," : proxyGroupTypeStr(x.Type) + ",default=,";
        group += join(x.Proxies.slice(1), ",");
        ini.set("Proxy Group", "{NONAME}", x.Name + " = " + group);
        continue;
      default:
        continue;
    }

    for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, true, ext);

    if (filteredNodelist.length === 0) filteredNodelist.push("DIRECT");

    if (filteredNodelist.length === 1) {
      const g = filteredNodelist[0].toLowerCase();
      if (g === "direct" || g === "reject" || g === "reject-tinygif") {
        ini.set("Proxy", "{NONAME}", x.Name + " = " + g);
        continue;
      }
    }

    // upstream uses x.TypeStr() for every target here (subexport.cpp:1260), and TypeStr() maps Smart
    // to "smart" (proxygroup.h:50). The Smart→url-test substitution belongs only to the Clash
    // exporter (:781-782); applying it here produced an unusable `NAME = url-test,node` line with no
    // url=, because the url/interval branch below only covers url-test/fallback/load-balance.
    group = proxyGroupTypeStr(x.Type) + ",";
    group += join(filteredNodelist, ",");
    if (x.Type === ProxyGroupType.URLTest || x.Type === ProxyGroupType.Fallback || x.Type === ProxyGroupType.LoadBalance) {
      group += ",url=" + x.Url + ",interval=" + x.Interval;
      if (x.Tolerance > 0) group += ",tolerance=" + x.Tolerance;
      if (x.Timeout > 0) group += ",timeout=" + x.Timeout;
      if (!x.Persistent.isUndef()) group += ",persistent=" + x.Persistent.getStr();
      if (!x.EvaluateBeforeUse.isUndef()) group += ",evaluate-before-use=" + x.EvaluateBeforeUse.getStr();
    }

    ini.set("Proxy Group", "{NONAME}", x.Name + " = " + group);
  }

  if (ext.enable_rule_generator) rulesetToSurge(ini, rulesetContentArray, surgeVer, ext.overwrite_original_rules, ext.managed_config_prefix);

  return ini.toString();
}
