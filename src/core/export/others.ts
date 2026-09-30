// Port of proxyToQuan (1520-1746), proxyToQuanX (1748-2052), proxyToMellow (2152-2303), proxyToLoon (2305-2600)

import { INIReader } from "../../lib/ini";
import { Proxy, ProxyType, getProxyTypeName } from "../proxy";
import { join, replaceAllDistinct, split, startsWith, trim, trimOf, getUrlArg } from "../../lib/string";
import { base64Encode, urlSafeBase64Encode } from "../../lib/base64";
import { urlEncode } from "../../lib/urlencode";
import { tribool } from "../../lib/tribool";
import { regGetMatch } from "../../lib/regex";
import { global } from "../settings";
import type { extra_settings, ProxyGroupConfig, RulesetContent } from "../extra";
import { proxyGroupTypeStr, ProxyGroupType, BalanceStrategy } from "../extra";
import { processRemark, groupGenerate } from "./common";
import { rulesetToSurge } from "../ruleconvert";
import { isIPv4, isIPv6 } from "../parser/util";

function remarkRef(x: Proxy): { v: string } {
  return { get v() { return x.Remark; }, set v(val: string) { x.Remark = val; } };
}

export function proxyToQuan(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): string {
  const ini = new INIReader();
  ini.store_any_line = true;
  if (!ext.nodelist && ini.parse(baseConf) !== 0) {
    console.error("Quantumult base loader failed");
    return "";
  }
  proxyToQuanCore(nodes, ini, rulesetContentArray, extraProxyGroup, ext);
  if (ext.nodelist) {
    const allnodes = ini.getAll("SERVER", "{NONAME}");
    if (allnodes.length > 0) return base64Encode(join(allnodes, "\n"));
    return base64Encode("");
  }
  return ini.toString();
}

function proxyToQuanCore(
  nodes: Proxy[], ini: INIReader, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): void {
  const nodelist: Proxy[] = [];
  const remarksList: string[] = [];

  ini.setCurrentSection("SERVER");
  ini.eraseSection("SERVER");
  for (const x of nodes) {
    if (ext.append_proxy_type) {
      const type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }
    processRemark(remarkRef(x), remarksList);

    const hostname = x.Hostname, password = x.Password, id = x.UserId, transproto = x.TransferProtocol;
    const host = x.Host, path = x.Path, edge = x.Edge, protocol = x.Protocol, protoparam = x.ProtocolParam;
    const obfs = x.OBFS, obfsparam = x.OBFSParam, plugin = x.Plugin, pluginopts = x.PluginOption, username = x.Username;
    const port = String(x.Port);
    const tlssecure = x.TLSSecure;
    let proxyStr = "";
    let scv = new tribool();
    let method = x.EncryptMethod;

    switch (x.Type) {
      case ProxyType.VMess: {
        scv = new tribool(ext.skip_cert_verify);
        scv.define(x.AllowInsecure);
        if (method === "auto") method = "chacha20-ietf-poly1305";
        proxyStr = x.Remark + " = vmess, " + hostname + ", " + port + ", " + method + ', "' + id + '", group=' + x.Group;
        if (tlssecure) {
          proxyStr += ", over-tls=true, tls-host=" + host;
          if (!scv.isUndef()) proxyStr += ", certificate=" + (scv.get() ? "0" : "1");
        }
        if (transproto === "ws") {
          proxyStr += ', obfs=ws, obfs-path="' + path + '", obfs-header="Host: ' + host;
          if (edge.length > 0) proxyStr += "[Rr][Nn]Edge: " + edge;
          proxyStr += '"';
        }
        if (ext.nodelist) proxyStr = "vmess://" + urlSafeBase64Encode(proxyStr);
        break;
      }
      case ProxyType.ShadowsocksR: {
        if (ext.nodelist) {
          proxyStr = "ssr://" + urlSafeBase64Encode(
            hostname + ":" + port + ":" + protocol + ":" + x.EncryptMethod + ":" + obfs + ":" + urlSafeBase64Encode(password) +
            "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(x.Remark) +
            "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" + urlSafeBase64Encode(protoparam));
        } else {
          proxyStr = x.Remark + " = shadowsocksr, " + hostname + ", " + port + ", " + x.EncryptMethod + ', "' + password + '", group=' + x.Group + ", protocol=" + protocol + ", obfs=" + obfs;
          if (protoparam.length > 0) proxyStr += ", protocol_param=" + protoparam;
          if (obfsparam.length > 0) proxyStr += ", obfs_param=" + obfsparam;
        }
        break;
      }
      case ProxyType.Shadowsocks: {
        if (ext.nodelist) {
          proxyStr = "ss://" + urlSafeBase64Encode(x.EncryptMethod + ":" + password) + "@" + hostname + ":" + port;
          if (plugin.length > 0 && pluginopts.length > 0) proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
          proxyStr += "&group=" + urlSafeBase64Encode(x.Group) + "#" + urlEncode(x.Remark);
        } else {
          proxyStr = x.Remark + " = shadowsocks, " + hostname + ", " + port + ", " + x.EncryptMethod + ', "' + password + '", group=' + x.Group;
          if (plugin === "obfs-local" && pluginopts.length > 0) proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
        }
        break;
      }
      case ProxyType.HTTP:
      case ProxyType.HTTPS: {
        proxyStr = x.Remark + " = http, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port + ", group=" + x.Group;
        if (username.length > 0 && password.length > 0) proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username + ", upstream-proxy-password=" + password;
        else proxyStr += ", upstream-proxy-auth=false";
        if (tlssecure) {
          proxyStr += ", over-tls=true";
          if (host.length > 0) proxyStr += ", tls-host=" + host;
          if (!scv.isUndef()) proxyStr += ", certificate=" + (scv.get() ? "0" : "1");
        }
        if (ext.nodelist) proxyStr = "http://" + urlSafeBase64Encode(proxyStr);
        break;
      }
      case ProxyType.SOCKS5: {
        proxyStr = x.Remark + " = socks, upstream-proxy-address=" + hostname + ", upstream-proxy-port=" + port + ", group=" + x.Group;
        if (username.length > 0 && password.length > 0) proxyStr += ", upstream-proxy-auth=true, upstream-proxy-username=" + username + ", upstream-proxy-password=" + password;
        else proxyStr += ", upstream-proxy-auth=false";
        if (tlssecure) {
          proxyStr += ", over-tls=true";
          if (host.length > 0) proxyStr += ", tls-host=" + host;
          if (!scv.isUndef()) proxyStr += ", certificate=" + (scv.get() ? "0" : "1");
        }
        if (ext.nodelist) proxyStr = "socks://" + urlSafeBase64Encode(proxyStr);
        break;
      }
      default:
        continue;
    }
    ini.set("SERVER", "{NONAME}", proxyStr);
    remarksList.push(x.Remark);
    nodelist.push(x);
  }

  if (ext.nodelist) return;

  ini.setCurrentSection("POLICY");
  ini.eraseSection("POLICY");

  for (const x of extraProxyGroup) {
    const filteredNodelist: string[] = [];
    let type = "";
    let singlegroup = "";
    let celluar = "";

    switch (x.Type) {
      case ProxyGroupType.Select:
      case ProxyGroupType.Fallback:
        type = "static";
        break;
      case ProxyGroupType.URLTest:
        type = "auto";
        break;
      case ProxyGroupType.LoadBalance:
        type = "balance, round-robin";
        break;
      case ProxyGroupType.SSID: {
        singlegroup = x.Name + " : wifi = " + x.Proxies[0];
        const celluar_matcher = "^(.*?),?celluar\\s?=\\s?(.*?)(,.*)$";
        let content = "";
        for (const iter of x.Proxies.slice(1)) {
          const m = regGetMatch(iter, celluar_matcher);
          if (!m) {
            content += iter + "\n";
            continue;
          }
          celluar = m[2];
          content += (m[1] ?? "") + (m[3] ?? "") + "\n";
        }
        if (celluar.length > 0) singlegroup += ", celluar = " + celluar;
        singlegroup += "\n" + replaceAllDistinct(trimOf(content, ","), ",", "\n");
        ini.set("POLICY", "{NONAME}", base64Encode(singlegroup));
        continue;
      }
      default:
        continue;
    }

    for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, true, ext);

    if (filteredNodelist.length === 0) filteredNodelist.push("direct");
    if (filteredNodelist.length < 2) type = "static";

    const proxies = join(filteredNodelist, "\n");
    singlegroup = x.Name + " : " + type;
    if (type === "static") singlegroup += ", " + filteredNodelist[0];
    singlegroup += "\n" + proxies + "\n";
    ini.set("POLICY", "{NONAME}", base64Encode(singlegroup));
  }

  if (ext.enable_rule_generator) rulesetToSurge(ini, rulesetContentArray, -2, ext.overwrite_original_rules, "");
}

export function proxyToQuanX(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): string {
  const ini = new INIReader();
  ini.store_any_line = true;
  ini.addDirectSaveSection("general");
  ini.addDirectSaveSection("dns");
  ini.addDirectSaveSection("rewrite_remote");
  ini.addDirectSaveSection("rewrite_local");
  ini.addDirectSaveSection("task_local");
  ini.addDirectSaveSection("mitm");
  ini.addDirectSaveSection("server_remote");
  if (!ext.nodelist && ini.parse(baseConf) !== 0) {
    console.error("QuantumultX base loader failed");
    return "";
  }
  proxyToQuanXCore(nodes, ini, rulesetContentArray, extraProxyGroup, ext);
  if (ext.nodelist) {
    const allnodes = ini.getAll("server_local", "{NONAME}");
    if (allnodes.length > 0) return join(allnodes, "\n");
    return "";
  }
  return ini.toString();
}

function proxyToQuanXCore(
  nodes: Proxy[], ini: INIReader, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): void {
  const nodelist: Proxy[] = [];
  const remarksList: string[] = [];

  ini.setCurrentSection("server_local");
  ini.eraseSection("server_local");
  for (const x of nodes) {
    if (ext.append_proxy_type) {
      const type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }
    processRemark(remarkRef(x), remarksList);

    const hostname = x.Hostname, id = x.UserId, transproto = x.TransferProtocol, host = x.Host, path = x.Path;
    const password = x.Password, plugin = x.Plugin, pluginopts = x.PluginOption, protocol = x.Protocol;
    const protoparam = x.ProtocolParam, obfs = x.OBFS, obfsparam = x.OBFSParam, username = x.Username;
    const sni = x.ServerName, publickey = x.PublicKey, shortid = x.ShortId, flow = x.Flow;
    const port = String(x.Port);
    let method = x.EncryptMethod;
    const tlssecure = x.TLSSecure;
    let proxyStr = "";

    const udp = new tribool(ext.udp), tfo = new tribool(ext.tfo), scv = new tribool(ext.skip_cert_verify), tls13 = new tribool(ext.tls13);
    udp.define(x.UDP);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);
    tls13.define(x.TLS13);

    switch (x.Type) {
      case ProxyType.VMess: {
        if (method === "auto") method = "chacha20-ietf-poly1305";
        proxyStr = "vmess = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
        if (x.AlterId !== 0) proxyStr += ", aead=false";
        if (tlssecure && !tls13.isUndef()) proxyStr += ", tls13=" + (tls13.get() ? "true" : "false");
        if (transproto === "ws") {
          if (tlssecure) proxyStr += ", obfs=wss";
          else proxyStr += ", obfs=ws";
          proxyStr += ", obfs-host=" + host + ", obfs-uri=" + path;
        } else if (tlssecure) proxyStr += ", obfs=over-tls, obfs-host=" + host;
        break;
      }
      case ProxyType.VLESS: {
        method = "none";
        proxyStr = "vless = " + hostname + ":" + port + ", method=" + method + ", password=" + id;
        if (tlssecure && !tls13.isUndef()) proxyStr += ", tls13=" + (tls13.get() ? "true" : "false");
        if (transproto === "ws") {
          proxyStr += tlssecure ? ", obfs=wss" : ", obfs=ws";
          if (tlssecure && publickey.length > 0 && sni.length === 0)
            console.warn("Quantumult X vless reality: public key present but SNI missing; skipping reality output.");
          if (tlssecure && shortid.length > 0 && publickey.length === 0)
            console.warn("Quantumult X vless reality: shortid present but public key missing; skipping reality output.");
          if (tlssecure && publickey.length > 0 && sni.length > 0) proxyStr += ", obfs-host=" + sni;
          else if (host.length > 0) proxyStr += ", obfs-host=" + host;
          if (path.length > 0) proxyStr += ", obfs-uri=" + path;
          if (tlssecure && publickey.length > 0 && sni.length > 0) {
            proxyStr += ", reality-base64-pubkey=" + publickey;
            if (shortid.length > 0) proxyStr += ", reality-hex-shortid=" + shortid;
          }
        } else if (transproto === "http") {
          proxyStr += ", obfs=http";
          if (host.length > 0) proxyStr += ", obfs-host=" + host;
          if (path.length > 0) proxyStr += ", obfs-uri=" + path;
        } else if (tlssecure) {
          proxyStr += ", obfs=over-tls";
          if (publickey.length > 0 && sni.length === 0)
            console.warn("Quantumult X vless reality: public key present but SNI missing; skipping reality output.");
          if (shortid.length > 0 && publickey.length === 0)
            console.warn("Quantumult X vless reality: shortid present but public key missing; skipping reality output.");
          if (publickey.length > 0 && sni.length > 0) {
            proxyStr += ", obfs-host=" + sni;
            proxyStr += ", reality-base64-pubkey=" + publickey;
            if (shortid.length > 0) proxyStr += ", reality-hex-shortid=" + shortid;
            if (flow.length > 0) proxyStr += ", vless-flow=" + flow;
          } else if (sni.length > 0) proxyStr += ", obfs-host=" + sni;
          else if (host.length > 0) proxyStr += ", obfs-host=" + host;
        }
        break;
      }
      case ProxyType.Shadowsocks: {
        proxyStr = "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password;
        if (plugin.length > 0) {
          switch (plugin) {
            case "simple-obfs":
            case "obfs-local":
              if (pluginopts.length > 0) proxyStr += ", " + replaceAllDistinct(pluginopts, ";", ", ");
              break;
            case "v2ray-plugin": {
              const opts = replaceAllDistinct(pluginopts, ";", "&");
              let pl = getUrlArg(opts, "mode") === "websocket" ? "ws" : "";
              const h = getUrlArg(opts, "host");
              const p = getUrlArg(opts, "path");
              const tls = opts.includes("tls");
              if (tls && pl === "ws") {
                pl += "s";
                if (!tls13.isUndef()) proxyStr += ", tls13=" + (tls13.get() ? "true" : "false");
              }
              proxyStr += ", obfs=" + pl;
              if (h.length > 0) proxyStr += ", obfs-host=" + h;
              if (p.length > 0) proxyStr += ", obfs-uri=" + p;
              break;
            }
            default:
              continue;
          }
        }
        break;
      }
      case ProxyType.ShadowsocksR: {
        proxyStr = "shadowsocks = " + hostname + ":" + port + ", method=" + method + ", password=" + password + ", ssr-protocol=" + protocol;
        if (protoparam.length > 0) proxyStr += ", ssr-protocol-param=" + protoparam;
        proxyStr += ", obfs=" + obfs;
        if (obfsparam.length > 0) proxyStr += ", obfs-host=" + obfsparam;
        break;
      }
      case ProxyType.HTTP:
      case ProxyType.HTTPS: {
        proxyStr = "http = " + hostname + ":" + port + ", username=" + (username.length === 0 ? "none" : username) + ", password=" + (password.length === 0 ? "none" : password);
        if (tlssecure) {
          proxyStr += ", over-tls=true";
          if (!tls13.isUndef()) proxyStr += ", tls13=" + (tls13.get() ? "true" : "false");
        } else proxyStr += ", over-tls=false";
        break;
      }
      case ProxyType.Trojan: {
        proxyStr = "trojan = " + hostname + ":" + port + ", password=" + password;
        if (tlssecure) {
          proxyStr += ", over-tls=true, tls-host=" + host;
          if (!tls13.isUndef()) proxyStr += ", tls13=" + (tls13.get() ? "true" : "false");
        } else proxyStr += ", over-tls=false";
        break;
      }
      case ProxyType.SOCKS5: {
        proxyStr = "socks5 = " + hostname + ":" + port;
        if (username.length > 0 && password.length > 0) {
          proxyStr += ", username=" + username + ", password=" + password;
          if (tlssecure) {
            proxyStr += ", over-tls=true, tls-host=" + host;
            if (!tls13.isUndef()) proxyStr += ", tls13=" + (tls13.get() ? "true" : "false");
          } else proxyStr += ", over-tls=false";
        }
        break;
      }
      default:
        continue;
    }
    if (!tfo.isUndef()) proxyStr += ", fast-open=" + tfo.getStr();
    if (!udp.isUndef()) proxyStr += ", udp-relay=" + udp.getStr();
    if (tlssecure && !scv.isUndef() && (x.Type !== ProxyType.Shadowsocks && x.Type !== ProxyType.ShadowsocksR && x.Type !== ProxyType.VLESS))
      proxyStr += ", tls-verification=" + scv.reverse().getStr();
    proxyStr += ", tag=" + x.Remark;

    ini.set("server_local", "{NONAME}", proxyStr);
    remarksList.push(x.Remark);
    nodelist.push(x);
  }

  if (ext.nodelist) return;

  const originalGroups = ini.getItems("policy");
  ini.setCurrentSection("policy");
  ini.eraseSection("policy");

  for (const x of extraProxyGroup) {
    let type = "";
    const filteredNodelist: string[] = [];

    switch (x.Type) {
      case ProxyGroupType.Select:
        type = "static";
        break;
      case ProxyGroupType.URLTest:
        type = "url-latency-benchmark";
        break;
      case ProxyGroupType.Fallback:
        type = "available";
        break;
      case ProxyGroupType.LoadBalance:
        type = "round-robin";
        break;
      case ProxyGroupType.SSID:
        type = "ssid";
        for (const proxy of x.Proxies) filteredNodelist.push(replaceAllDistinct(proxy, "=", ":"));
        break;
      default:
        continue;
    }

    if (x.Type !== ProxyGroupType.SSID) {
      for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, true, ext);
      if (filteredNodelist.length === 0) filteredNodelist.push("direct");
      if (filteredNodelist.length < 2) type = "static";
    }

    const iter = originalGroups.find((n) => {
      const groupdata = n[1];
      const cpos = groupdata.indexOf(",");
      if (cpos !== -1) return trim(groupdata.substring(0, cpos)) === x.Name;
      return false;
    });
    if (iter) {
      const vArray = split(iter[1], ",");
      if (vArray.length > 1 && trim(vArray[vArray.length - 1]).startsWith("img-url")) {
        filteredNodelist.push(trim(vArray[vArray.length - 1]));
      }
    }

    const proxies = join(filteredNodelist, ", ");
    let singlegroup = type + "=" + x.Name + ", " + proxies;
    if (x.Type !== ProxyGroupType.Select && x.Type !== ProxyGroupType.SSID) {
      singlegroup += ", check-interval=" + x.Interval;
      if (x.Tolerance > 0) singlegroup += ", tolerance=" + x.Tolerance;
    }
    ini.set("policy", "{NONAME}", singlegroup);
  }

  if (ext.enable_rule_generator) rulesetToSurge(ini, rulesetContentArray, -1, ext.overwrite_original_rules, ext.managed_config_prefix);
}

export function proxyToMellow(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): string {
  const ini = new INIReader();
  ini.store_any_line = true;
  if (ini.parse(baseConf) !== 0) {
    console.error("Mellow base loader failed");
    return "";
  }
  proxyToMellowCore(nodes, ini, rulesetContentArray, extraProxyGroup, ext);
  return ini.toString();
}

function proxyToMellowCore(
  nodes: Proxy[], ini: INIReader, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): void {
  const nodelist: Proxy[] = [];
  const remarksList: string[] = [];

  ini.setCurrentSection("Endpoint");

  for (const x of nodes) {
    if (ext.append_proxy_type) {
      const type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }
    processRemark(remarkRef(x), remarksList);

    const hostname = x.Hostname;
    const port = String(x.Port);
    let proxy = "";

    const tfo = new tribool(ext.tfo), scv = new tribool(ext.skip_cert_verify);
    tfo.define(x.TCPFastOpen);
    scv.define(x.AllowInsecure);

    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        if (x.Plugin.length > 0) continue;
        proxy = x.Remark + ", ss, ss://" + urlSafeBase64Encode(x.EncryptMethod + ":" + x.Password) + "@" + hostname + ":" + port;
        break;
      }
      case ProxyType.VMess: {
        proxy = x.Remark + ", vmess1, vmess1://" + x.UserId + "@" + hostname + ":" + port;
        if (x.Path.length > 0) proxy += x.Path;
        proxy += "?network=" + x.TransferProtocol;
        switch (x.TransferProtocol) {
          case "ws":
            proxy += "&ws.host=" + urlEncode(x.Host);
            break;
          case "http":
            if (x.Host.length > 0) proxy += "&http.host=" + urlEncode(x.Host);
            break;
          case "quic":
            if (x.QUICSecure.length > 0) proxy += "&quic.security=" + x.QUICSecure + "&quic.key=" + x.QUICSecret;
            break;
          case "kcp":
          case "tcp":
            break;
        }
        proxy += "&tls=" + x.TLSSecure;
        if (x.TLSSecure) {
          if (x.Host.length > 0) proxy += "&tls.servername=" + urlEncode(x.Host);
        }
        if (!scv.isUndef()) proxy += "&tls.allowinsecure=" + scv.getStr();
        if (!tfo.isUndef()) proxy += "&sockopt.tcpfastopen=" + tfo.getStr();
        break;
      }
      case ProxyType.SOCKS5:
        proxy = x.Remark + ", builtin, socks, address=" + hostname + ", port=" + port + ", user=" + x.Username + ", pass=" + x.Password;
        break;
      case ProxyType.HTTP:
        proxy = x.Remark + ", builtin, http, address=" + hostname + ", port=" + port + ", user=" + x.Username + ", pass=" + x.Password;
        break;
      default:
        continue;
    }

    ini.set("Endpoint", "{NONAME}", proxy);
    remarksList.push(x.Remark);
    nodelist.push(x);
  }

  ini.setCurrentSection("EndpointGroup");

  for (const x of extraProxyGroup) {
    const filteredNodelist: string[] = [];

    switch (x.Type) {
      case ProxyGroupType.Select:
      case ProxyGroupType.URLTest:
      case ProxyGroupType.Fallback:
      case ProxyGroupType.LoadBalance:
        break;
      default:
        continue;
    }

    for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, false, ext);

    if (filteredNodelist.length === 0) {
      if (remarksList.length === 0) filteredNodelist.push("DIRECT");
      else filteredNodelist.push(...remarksList);
    }

    let proxy = x.Name + ", ";
    proxy += join(filteredNodelist, ":");
    proxy += ", latency, interval=300, timeout=6";
    ini.set("EndpointGroup", "{NONAME}", proxy);
  }

  if (ext.enable_rule_generator) rulesetToSurge(ini, rulesetContentArray, 0, ext.overwrite_original_rules, "");
}

export function proxyToLoon(
  nodes: Proxy[], baseConf: string, rulesetContentArray: RulesetContent[], extraProxyGroup: ProxyGroupConfig[], ext: extra_settings,
): string {
  const ini = new INIReader();
  let outputNodelist = "";
  const nodelist: Proxy[] = [];
  const remarksList: string[] = [];

  ini.store_any_line = true;
  ini.addDirectSaveSection("Plugin");
  if (ini.parse(baseConf) !== 0 && !ext.nodelist) {
    console.error("Loon base loader failed");
    return "";
  }

  ini.setCurrentSection("Proxy");
  ini.eraseSection("Proxy");

  for (const x of nodes) {
    if (ext.append_proxy_type) {
      const type = getProxyTypeName(x.Type);
      x.Remark = "[" + type + "] " + x.Remark;
    }
    processRemark(remarkRef(x), remarksList);

    const hostname = x.Hostname, password = x.Password, method = x.EncryptMethod, plugin = x.Plugin;
    const pluginopts = x.PluginOption, id = x.UserId, transproto = x.TransferProtocol, host = x.Host, path = x.Path;
    const protocol = x.Protocol, protoparam = x.ProtocolParam, obfs = x.OBFS, obfsparam = x.OBFSParam;
    let flow = x.Flow;
    const pk = x.PublicKey, shortId = x.ShortId, sni = x.ServerName;
    const port = String(x.Port);
    const tlssecure = x.TLSSecure;

    const scv = new tribool(ext.skip_cert_verify);
    scv.define(x.AllowInsecure);
    const udp = x.UDP.isUndef() ? (ext.udp.isUndef() ? new tribool(false) : new tribool(ext.udp.get())) : new tribool(x.UDP.get());
    let proxy = "";
    let skip = false;

    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        proxy = "Shadowsocks," + hostname + "," + port + "," + method + ',"' + password + '"';
        if (plugin === "simple-obfs" || plugin === "obfs-local") {
          if (pluginopts.length > 0) proxy += "," + replaceAllDistinct(replaceAllDistinct(pluginopts, ";obfs-host=", ","), "obfs=", "");
        } else if (plugin.length > 0) skip = true;
        break;
      }
      case ProxyType.VMess: {
        let methodV = method;
        if (methodV === "auto") methodV = "chacha20-ietf-poly1305";
        let hostV = host;
        proxy = "vmess," + hostname + "," + port + "," + methodV + ',"' + id + '",over-tls=' + (tlssecure ? "true" : "false");
        if (sni.length > 0) hostV = sni;
        if (tlssecure) proxy += ",tls-name=" + hostV;
        switch (transproto) {
          case "tcp":
            proxy += ",transport=tcp";
            break;
          case "ws":
            proxy += ",transport=ws,path=" + path + ",host=" + hostV;
            break;
          default:
            skip = true;
            break;
        }
        if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        break;
      }
      case ProxyType.VLESS: {
        if (flow !== "xtls-rprx-vision") {
          if (transproto === "ws") {
            proxy = "VLESS," + hostname + "," + port + ',"' + id + '",path=' + path + ",host=" + host + ",transport=" + transproto + ",udp=" + (udp.get() ? "true" : "false") + ",over-tls=" + (tlssecure ? "true" : "false") + ",sni=" + sni;
          } else {
            skip = true;
            break;
          }
        } else {
          proxy = "VLESS," + hostname + "," + port + ',"' + id + '",flow=' + flow + ',public-key="' + pk + '",short-id=' + shortId + ",udp=" + (udp.get() ? "true" : "false") + ",over-tls=" + (tlssecure ? "true" : "false") + ",sni=" + sni;
        }
        switch (transproto) {
          case "tcp":
            proxy += ",transport=tcp";
            break;
          default:
            if (transproto !== "ws") {
              skip = true;
            }
            break;
        }
        if (skip) break;
        if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        break;
      }
      case ProxyType.ShadowsocksR:
        proxy = "ShadowsocksR," + hostname + "," + port + "," + method + ',"' + password + '",protocol=' + protocol + ",protocol-param=" + protoparam + ",obfs=" + obfs + ",obfs-param=" + obfsparam;
        break;
      case ProxyType.HTTP:
        proxy = "http," + hostname + "," + port + "," + x.Username + ',"' + password + '"';
        break;
      case ProxyType.HTTPS: {
        proxy = "https," + hostname + "," + port + "," + x.Username + ',"' + password + '"';
        if (host.length > 0) proxy += ",tls-name=" + host;
        if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        break;
      }
      case ProxyType.Trojan: {
        proxy = "trojan," + hostname + "," + port + ',"' + password + '"';
        if (host.length > 0) proxy += ",tls-name=" + host;
        switch (transproto) {
          case "tcp":
            proxy += ",transport=tcp";
            break;
          case "ws":
            proxy += ",transport=ws,path=" + path + ",host=" + host;
            break;
          default:
            skip = true;
            break;
        }
        if (skip) break;
        if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        break;
      }
      case ProxyType.SOCKS5: {
        proxy = "socks5," + hostname + "," + port;
        if (x.Username.length > 0 && password.length > 0) proxy += "," + x.Username + ',"' + password + '"';
        proxy += ",over-tls=" + (tlssecure ? "true" : "false");
        if (tlssecure) {
          if (host.length > 0) proxy += ",tls-name=" + host;
          if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        }
        break;
      }
      case ProxyType.WireGuard: {
        proxy = "wireguard, interface-ip=" + x.SelfIP;
        if (x.SelfIPv6.length > 0) proxy += ", interface-ipv6=" + x.SelfIPv6;
        proxy += ", private-key=" + x.PrivateKey;
        for (const y of x.DnsServers) {
          if (isIPv4(y)) proxy += ", dns=" + y;
          else if (isIPv6(y)) proxy += ", dnsv6=" + y;
        }
        if (x.Mtu > 0) proxy += ", mtu=" + x.Mtu;
        if (x.KeepAlive > 0) proxy += ", keepalive=" + x.KeepAlive;
        proxy += ", peers=[{" + generatePeerForLoon(x) + "}]";
        break;
      }
      case ProxyType.Hysteria2: {
        proxy = "Hysteria2," + hostname + "," + port + ',"' + password + '"';
        if (x.ServerName.length > 0) proxy += ",sni=" + x.ServerName;
        if (x.UpMbps.length > 0) {
          let up = x.UpMbps;
          if (up.includes(" Mbps")) up = up.replace(" Mbps", "");
          else if (up.includes("Mbps")) up = up.replace("Mbps", "");
          proxy += ",download-bandwidth=" + up;
        } else {
          proxy += ",download-bandwidth=100";
        }
        if (!scv.isUndef()) proxy += ",skip-cert-verify=" + (scv.get() ? "true" : "false");
        break;
      }
      default:
        skip = true;
        break;
    }
    if (skip) continue;

    if (ext.tfo.get()) {
      proxy += ",fast-open=true";
    } else {
      if (x.Type === ProxyType.Hysteria2) proxy += ",fast-open=false";
    }
    if (ext.udp.get()) {
      proxy += ",udp=true";
    } else {
      if (x.Type === ProxyType.Hysteria2) proxy += ",udp=true";
    }

    if (ext.nodelist) outputNodelist += x.Remark + " = " + proxy + "\n";
    else {
      ini.set("Proxy", "{NONAME}", x.Remark + " = " + proxy);
      nodelist.push(x);
      remarksList.push(x.Remark);
    }
  }

  if (ext.nodelist) return outputNodelist;

  const originalGroups = ini.getItems("Proxy Group");
  ini.setCurrentSection("Proxy Group");
  ini.eraseSection("Proxy Group");

  for (const x of extraProxyGroup) {
    const filteredNodelist: string[] = [];
    let group = "";

    switch (x.Type) {
      case ProxyGroupType.Select:
      case ProxyGroupType.LoadBalance:
      case ProxyGroupType.URLTest:
      case ProxyGroupType.Fallback:
        break;
      case ProxyGroupType.SSID:
        if (x.Proxies.length < 2) continue;
        group = proxyGroupTypeStr(x.Type) + ",default=" + x.Proxies[0] + ",";
        group += join(x.Proxies.slice(1), ",");
        ini.set("Proxy Group", "{NONAME}", x.Name + " = " + group);
        continue;
      default:
        continue;
    }

    for (const y of x.Proxies) groupGenerate(y, nodelist, filteredNodelist, true, ext);

    if (filteredNodelist.length === 0) filteredNodelist.push("DIRECT");

    const iter = originalGroups.find((n) => trim(n[0]) === x.Name);
    if (iter) {
      const vArray = split(iter[1], ",");
      if (vArray.length > 1 && trim(vArray[vArray.length - 1]).startsWith("img-url")) {
        filteredNodelist.push(trim(vArray[vArray.length - 1]));
      }
    }

    group = proxyGroupTypeStr(x.Type) + ",";
    group += join(filteredNodelist, ",");
    if (x.Type !== ProxyGroupType.Select) {
      group += ",url=" + x.Url + ",interval=" + x.Interval;
      if (x.Type === ProxyGroupType.LoadBalance) {
        group += ",algorithm=" + (x.Strategy === BalanceStrategy.RoundRobin ? "round-robin" : "pcc");
        if (x.Timeout > 0) group += ",max-timeout=" + x.Timeout;
      }
      if (x.Type === ProxyGroupType.URLTest) {
        if (x.Tolerance > 0) group += ",tolerance=" + x.Tolerance;
      }
      if (x.Type === ProxyGroupType.Fallback) group += ",max-timeout=" + x.Timeout;
    }

    ini.set("Proxy Group", "{NONAME}", x.Name + " = " + group);
  }

  if (ext.enable_rule_generator) rulesetToSurge(ini, rulesetContentArray, -4, ext.overwrite_original_rules, ext.managed_config_prefix);

  return ini.toString();
}

import { generatePeer } from "./common";

function generatePeerForLoon(x: Proxy): string {
  return generatePeer(x, true);
}
