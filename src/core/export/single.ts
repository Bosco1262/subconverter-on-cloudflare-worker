// Port of src/generator/config/subexport.cpp proxyToSingle (1285-1465) + proxyToSSSub (1467-1518) + proxyToSSD (2054-2150)

import { Proxy, ProxyType } from "../proxy";
import { split, join, startsWith } from "../../lib/string";
import { base64Encode, urlSafeBase64Encode } from "../../lib/base64";
import { urlEncode } from "../../lib/urlencode";
import type { extra_settings, RulesetContent } from "../extra";
import { vmessLinkConstruct } from "./common";
import { ss_ciphers, ssr_ciphers } from "../parser/util";
import { getMember } from "../parser/util";
import { toNumber, getUrlArg, replaceAllDistinct, trimWhitespace, toInt } from "../../lib/string";
import { dateStringToTimestamp } from "../info";

export function proxyToSingle(nodes: Proxy[], types: number, ext: extra_settings): string {
  /// types bitmap, GETBIT is 1-based (bitwise.h): SS=1 SSR=2 VMess=4 Trojan=8 hysteria2=16 vless=32
  let proxyStr = "";
  let allLinks = "";
  const ss = ((types >> 0) & 1) !== 0, ssr = ((types >> 1) & 1) !== 0, vmess = ((types >> 2) & 1) !== 0;
  const trojan = ((types >> 3) & 1) !== 0, hysteria2 = ((types >> 4) & 1) !== 0, vless = ((types >> 5) & 1) !== 0;
  void startsWith;

  for (const x of nodes) {
    const remark = x.Remark;
    const hostname = x.Hostname, sni = x.ServerName, password = x.Password, method = x.EncryptMethod;
    const plugin = x.Plugin, pluginopts = x.PluginOption, protocol = x.Protocol, protoparam = x.ProtocolParam;
    const flow = x.Flow, pbk = x.PublicKey, sid = x.ShortId, fp = x.Fingerprint;
    const packet_encoding = x.PacketEncoding, fake_type = x.FakeType, mode = x.GRPCMode;
    const obfs = x.OBFS, obfsparam = x.OBFSParam, obfsPassword = x.OBFSPassword, id = x.UserId;
    const transproto = x.TransferProtocol, host = x.Host, tls = x.TLSStr, path = x.Path, ports = x.Ports;
    const tlssecure = x.TLSSecure;
    const alpns = x.AlpnList;
    const port = String(x.Port);
    const aid = String(x.AlterId);
    proxyStr = "";
    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        if (ss) {
          proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port;
          if (plugin.length > 0 && pluginopts.length > 0) {
            proxyStr += "/?plugin=" + urlEncode(plugin + ";" + pluginopts);
          }
          proxyStr += "#" + urlEncode(remark);
        } else if (ssr) {
          if (ssr_ciphers.includes(method) && plugin.length === 0)
            proxyStr =
              "ssr://" + urlSafeBase64Encode(
                hostname + ":" + port + ":origin:" + method + ":plain:" + urlSafeBase64Encode(password) +
                "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(remark));
        } else continue;
        break;
      }
      case ProxyType.ShadowsocksR: {
        if (ssr) {
          proxyStr = "ssr://" + urlSafeBase64Encode(
            hostname + ":" + port + ":" + protocol + ":" + method + ":" + obfs + ":" + urlSafeBase64Encode(password) +
            "/?group=" + urlSafeBase64Encode(x.Group) + "&remarks=" + urlSafeBase64Encode(remark) +
            "&obfsparam=" + urlSafeBase64Encode(obfsparam) + "&protoparam=" + urlSafeBase64Encode(protoparam));
        } else if (ss) {
          if (ss_ciphers.includes(method) && protocol === "origin" && obfs === "plain")
            proxyStr = "ss://" + urlSafeBase64Encode(method + ":" + password) + "@" + hostname + ":" + port + "#" + urlEncode(remark);
        } else continue;
        break;
      }
      case ProxyType.VMess: {
        if (!vmess) continue;
        proxyStr = "vmess://" + base64Encode(
          vmessLinkConstruct(remark, hostname, port, fake_type, id, aid, transproto, path, host, tlssecure ? "tls" : ""));
        break;
      }
      case ProxyType.Hysteria2: {
        if (!hysteria2) continue;
        proxyStr = "hysteria2://" + password + "@" + hostname + ":" + port + (ports.length === 0 ? "" : "," + ports) + "?insecure=" + (x.AllowInsecure.get() ? "1" : "0");
        if (obfsparam.length > 0) {
          proxyStr += "&obfs=" + obfsparam;
          if (obfsPassword.length > 0) {
            proxyStr += "&obfs-password=" + obfsparam;
          }
        }
        if (sni.length > 0) proxyStr += "&sni=" + sni;
        if (x.Fingerprint.length > 0) proxyStr += "&pinSHA256=" + x.Fingerprint;
        proxyStr += "#" + urlEncode(remark);
        break;
      }
      case ProxyType.VLESS: {
        if (!vless) continue;
        proxyStr = "vless://" + (id.length === 0 ? "00000000-0000-0000-0000-000000000000" : id) + "@" + hostname + ":" + port + "?";
        if (tls.length > 0) {
          if (pbk.length > 0) proxyStr += "&security=reality";
          else proxyStr += "&security=" + tls;
        }
        if (flow.length > 0) proxyStr += "&flow=" + flow;
        if (pbk.length > 0) proxyStr += "&pbk=" + pbk;
        if (sid.length > 0) proxyStr += "&sid=" + sid;
        if (fp.length > 0) proxyStr += "&fp=" + fp;
        if (packet_encoding.length > 0) proxyStr += "&packet-encoding=" + packet_encoding;
        if (alpns.length > 0) proxyStr += "&alpn=" + urlEncode(join(alpns, ","));
        if (sni.length > 0) proxyStr += "&sni=" + sni;
        if (transproto.length > 0) {
          proxyStr += "&type=" + transproto;
          switch (transproto) {
            case "tcp":
            case "ws":
            case "h2":
              proxyStr += "&headerType=" + fake_type;
              if (host.length > 0) proxyStr += "&host=" + host;
              proxyStr += "&path=" + urlEncode(path.length === 0 ? "/" : path);
              break;
            case "grpc":
              proxyStr += "&serviceName=" + path;
              proxyStr += "&mode=" + mode;
              break;
            case "quic":
              proxyStr += "&headerType=" + fake_type;
              proxyStr += "&quicSecurity=" + (host.length === 0 ? sni : host);
              proxyStr += "&key=" + path;
              break;
            default:
              break;
          }
        }
        proxyStr += "#" + urlEncode(remark);
        break;
      }
      case ProxyType.Trojan: {
        if (!trojan) continue;
        proxyStr = "trojan://" + password + "@" + hostname + ":" + port + "?allowInsecure=" + (x.AllowInsecure.get() ? "1" : "0");
        if (sni.length > 0) proxyStr += "&sni=" + sni;
        else if (host.length > 0) proxyStr += "&sni=" + host;
        if (transproto === "ws") {
          proxyStr += "&ws=1";
          if (path.length > 0) proxyStr += "&wspath=" + urlEncode(path);
        }
        proxyStr += "#" + urlEncode(remark);
        break;
      }
      default:
        continue;
    }
    allLinks += proxyStr + "\n";
  }

  if (ext.nodelist) return allLinks;
  return base64Encode(allLinks);
}

export function proxyToSSSub(baseConf0: string, nodes: Proxy[], ext: extra_settings): string {
  let baseConf = trimWhitespace(baseConf0);
  if (baseConf.length === 0) baseConf = "{}";
  let base: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(baseConf);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) base = parsed;
  } catch {
    // parse error logged upstream; keep empty base
  }

  const proxies: Record<string, unknown>[] = [];
  for (const x of nodes) {
    let plugin = x.Plugin;
    switch (x.Type) {
      case ProxyType.Shadowsocks:
        if (plugin === "simple-obfs") plugin = "obfs-local";
        break;
      case ProxyType.ShadowsocksR:
        if (!ss_ciphers.includes(x.EncryptMethod) || x.Protocol !== "origin" || x.OBFS !== "plain") continue;
        break;
      default:
        continue;
    }
    const proxy: Record<string, unknown> = { ...base };
    proxy["remarks"] = x.Remark;
    proxy["server"] = x.Hostname;
    proxy["server_port"] = x.Port;
    proxy["method"] = x.EncryptMethod;
    proxy["password"] = x.Password;
    proxy["plugin"] = plugin;
    proxy["plugin_opts"] = x.PluginOption;
    proxies.push(proxy);
  }
  return JSON.stringify(proxies);
}

export function proxyToSSD(nodes: Proxy[], group0: string, userinfo: string, ext: extra_settings): string {
  let group = group0;
  let index = 0;
  if (group.length === 0) group = "SSD";

  const root: Record<string, unknown> = {};
  root["airport"] = group;
  root["port"] = 1;
  root["encryption"] = "aes-128-gcm";
  root["password"] = "password";
  if (userinfo.length > 0) {
    const data = replaceAllDistinct(userinfo, "; ", "&");
    const upload = getUrlArg(data, "upload"), download = getUrlArg(data, "download");
    const total = getUrlArg(data, "total"), expiry = getUrlArg(data, "expire");
    const used = (toNumber(upload, 0) + toNumber(download, 0)) / Math.pow(1024, 3);
    const tot = toNumber(total, 0) / Math.pow(1024, 3);
    root["traffic_used"] = used;
    root["traffic_total"] = tot;
    if (expiry.length > 0) {
      // upstream: `const time_t rawtime = to_int(expiry);` → 0 for anything non-numeric, then
      // localtime + strftime (subexport.cpp:2083-2089). `Number(...)` produced NaN and the field was
      // emitted as "NaN-NaN-NaN NaN:NaN"; the Worker's local time is UTC, so format in UTC explicitly
      // to keep the value stable instead of host-dependent.
      const rawtime = toInt(expiry, 0) * 1000;
      const dt = new Date(rawtime);
      const pad = (n: number) => String(n).padStart(2, "0");
      root["expiry"] = `${dt.getUTCFullYear()}-${pad(dt.getUTCMonth() + 1)}-${pad(dt.getUTCDate())} ${pad(dt.getUTCHours())}:${pad(dt.getUTCMinutes())}`;
      void dateStringToTimestamp;
    }
  }
  const servers: Record<string, unknown>[] = [];
  for (const x of nodes) {
    let plugin = x.Plugin;
    switch (x.Type) {
      case ProxyType.Shadowsocks: {
        if (plugin === "obfs-local") plugin = "simple-obfs";
        servers.push({
          server: x.Hostname,
          port: x.Port,
          encryption: x.EncryptMethod,
          password: x.Password,
          plugin: plugin,
          plugin_options: x.PluginOption,
          remarks: x.Remark,
          id: index,
        });
        break;
      }
      case ProxyType.ShadowsocksR: {
        if (ss_ciphers.includes(x.EncryptMethod) && x.Protocol === "origin" && x.OBFS === "plain") {
          servers.push({
            server: x.Hostname,
            port: x.Port,
            encryption: x.EncryptMethod,
            password: x.Password,
            remarks: x.Remark,
            id: index,
          });
        } else continue;
        break;
      }
      default:
        continue;
    }
    index++;
  }
  root["servers"] = servers;
  return "ssd://" + base64Encode(JSON.stringify(root));
}
