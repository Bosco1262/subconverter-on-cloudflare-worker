// Port of src/parser/subparser.cpp explodeSurge (lines 2079-2893) — Surge INI config parsing

import { INIReader } from "../../lib/ini";
import { split, splitFirst, startsWith, strFind, toInt, trim, trimQuote, replaceAllDistinct } from "../../lib/string";
import { regGetAllMatch, regGetMatch, regMatch, regReplace } from "../../lib/regex";
import { urlSafeBase64Decode } from "../../lib/base64";
import { isIPv4, isIPv6 } from "./util";
import { tribool } from "../../lib/tribool";
import { Proxy, ProxyType, SS_DEFAULT_GROUP, SOCKS_DEFAULT_GROUP, V2RAY_DEFAULT_GROUP, HTTP_DEFAULT_GROUP, TROJAN_DEFAULT_GROUP, SNELL_DEFAULT_GROUP, WG_DEFAULT_GROUP, ANYTLS_DEFAULT_GROUP, SSR_DEFAULT_GROUP, XRAY_DEFAULT_GROUP } from "../proxy";
import { newProxy } from "../proxy";
import { ss_ciphers, ssConstruct, ssrConstruct, socksConstruct, httpConstruct, trojanConstruct, snellConstruct, wireguardConstruct, vmessConstruct, anyTlSConstruct, vlessConstruct, parsePeers, splitHostPortRfind } from "./util";

export function explodeSurge(surge0: string, nodes: Proxy[]): number {
  const index0 = nodes.length;
  const ini = new INIReader();

  ini.store_isolated_line = true;
  ini.keep_empty_section = false;
  ini.allow_dup_section_titles = true;
  ini.setIsolatedItemsSection("Proxy");
  ini.addDirectSaveSection("Proxy");
  let surge = surge0;
  if (surge.includes("[Proxy]")) surge = regReplace(surge, "^[\\S\\s]*?\\[", "[", false);
  ini.parse(surge);

  if (!ini.sectionExist("Proxy")) return 0;
  ini.enterSection("Proxy");
  const proxies = ini.getItemsCurrent();

  const proxystr = "(.*?)\\s*=\\s*(.*)";
  let index = nodes.length;

  for (const [, line] of proxies) {
    let remarks = "", config = "";
    const m0 = regGetMatch(line, proxystr);
    if (!m0) continue;
    [, remarks, config] = m0;
    const configs = split(config, ",");
    if (configs.length < 3) continue;

    let server = "", port = "", method = "", username = "", password = "", sni = "";
    let plugin = "", pluginopts = "", pluginopts_mode = "", pluginopts_host = "";
    let id = "", net = "", tls = "", host = "", edge = "", path = "", fp = "";
    let protocol = "", protoparam = "";
    let section = "", ip = "", ipv6 = "", private_key = "", public_key = "", mtu = "", test_url = "", client_id = "", peer = "", keepalive = "";
    const dns_servers: string[] = [];
    let version = "", aead = "1";
    let itemName = "", itemVal = "";
    let vArray: string[] = [];
    const udp = new tribool(), tfo = new tribool(), scv = new tribool(), tls13 = new tribool();
    const node = newProxy();

    switch (configs[0]) {
      case "direct":
      case "reject":
      case "reject-tinygif":
        continue;
      case "custom": {
        // surge 2 style custom proxy (module detection removed upstream)
        if (configs.length < 5) continue;
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        method = trim(configs[3]);
        password = trim(configs[4]);

        for (let i = 6; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length < 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "obfs":
              plugin = "simple-obfs";
              pluginopts_mode = itemVal;
              break;
            case "obfs-host":
              pluginopts_host = itemVal;
              break;
            case "udp-relay":
              udp.setString(itemVal);
              break;
            case "tfo":
              tfo.setString(itemVal);
              break;
            case "shadow-tls-sni":
            case "shadow-tls-password":
            case "shadow-tls-version":
              port = "0";
              break;
            default:
              continue;
          }
        }
        if (port === "0") continue;
        if (plugin.length > 0) {
          pluginopts = "obfs=" + pluginopts_mode;
          pluginopts += pluginopts_host.length === 0 ? "" : ";obfs-host=" + pluginopts_host;
        }
        ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv);
        break;
      }
      case "ss": {
        // surge 3 style ss proxy
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        for (let i = 3; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length < 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "encrypt-method":
              method = itemVal;
              break;
            case "password":
              password = itemVal;
              break;
            case "obfs":
              plugin = "simple-obfs";
              pluginopts_mode = itemVal;
              break;
            case "obfs-host":
              pluginopts_host = itemVal;
              break;
            case "udp-relay":
              udp.setString(itemVal);
              break;
            case "tfo":
              tfo.setString(itemVal);
              break;
            case "shadow-tls-sni":
            case "shadow-tls-password":
            case "shadow-tls-version":
              port = "0";
              break;
            default:
              continue;
          }
        }
        if (port === "0") continue;
        if (plugin.length > 0) {
          pluginopts = "obfs=" + pluginopts_mode;
          pluginopts += pluginopts_host.length === 0 ? "" : ";obfs-host=" + pluginopts_host;
        }
        ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv);
        break;
      }
      case "socks5": {
        // surge 3 style socks5 proxy
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        if (configs.length >= 5) {
          username = trim(configs[3]);
          password = trim(configs[4]);
        }
        for (let i = 5; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length < 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "udp-relay":
              udp.setString(itemVal);
              break;
            case "tfo":
              tfo.setString(itemVal);
              break;
            case "skip-cert-verify":
              scv.setString(itemVal);
              break;
            default:
              continue;
          }
        }
        socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv);
        break;
      }
      case "vmess": {
        // surge 4 style vmess proxy
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        net = "tcp";
        method = "auto";
        for (let i = 3; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length !== 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "username":
              id = itemVal;
              break;
            case "ws":
              net = itemVal === "true" ? "ws" : "tcp";
              break;
            case "tls":
              tls = itemVal === "true" ? "tls" : "";
              break;
            case "ws-path":
              path = itemVal;
              break;
            case "obfs-host":
              host = itemVal;
              break;
            case "ws-headers": {
              const headers = split(itemVal, "|");
              for (const y of headers) {
                const header = split(trim(y), ":");
                if (header.length !== 2) continue;
                else if (regMatch(header[0], "(?i)host")) host = trimQuote(header[1]);
                else if (regMatch(header[0], "(?i)edge")) edge = trimQuote(header[1]);
              }
              break;
            }
            case "udp-relay":
              udp.setString(itemVal);
              break;
            case "tfo":
              tfo.setString(itemVal);
              break;
            case "skip-cert-verify":
              scv.setString(itemVal);
              break;
            case "tls13":
              tls13.setString(itemVal);
              break;
            case "vmess-aead":
              aead = itemVal === "true" ? "0" : "1";
              break;
            default:
              continue;
          }
        }
        vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, edge, tls, "", [], udp, tfo, scv, tls13);
        break;
      }
      case "http": {
        // http proxy
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        for (let i = 3; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length < 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "username":
              username = itemVal;
              break;
            case "password":
              password = itemVal;
              break;
            case "skip-cert-verify":
              scv.setString(itemVal);
              break;
            default:
              continue;
          }
        }
        httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, false, tfo, scv);
        break;
      }
      case "trojan": {
        // surge 4 style trojan proxy
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        for (let i = 3; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length !== 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "password":
              password = itemVal;
              break;
            case "sni":
              host = itemVal;
              sni = itemVal;
              break;
            case "udp-relay":
              udp.setString(itemVal);
              break;
            case "tfo":
              tfo.setString(itemVal);
              break;
            case "skip-cert-verify":
              scv.setString(itemVal);
              break;
            case "fingerprint":
              fp = itemVal;
              break;
            default:
              continue;
          }
        }
        trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp, sni, [], true, udp, tfo, scv);
        break;
      }
      case "snell": {
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        for (let i = 3; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length !== 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "psk":
              password = itemVal;
              break;
            case "obfs":
              plugin = itemVal;
              break;
            case "obfs-host":
              host = itemVal;
              break;
            case "udp-relay":
              udp.setString(itemVal);
              break;
            case "tfo":
              tfo.setString(itemVal);
              break;
            case "skip-cert-verify":
              scv.setString(itemVal);
              break;
            case "version":
              version = itemVal;
              break;
            default:
              continue;
          }
        }
        snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server, port, password, plugin, host, toInt(version, 0), udp, tfo, scv);
        break;
      }
      case "wireguard": {
        for (let i = 1; i < configs.length; i++) {
          vArray = splitFirst(trim(configs[i]), "=");
          if (vArray.length !== 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "section-name":
              section = itemVal;
              break;
            case "test-url":
              test_url = itemVal;
              break;
          }
        }
        if (section.length === 0) continue;
        const wireguard_config = ini.getItems("WireGuard " + section);
        if (wireguard_config.length === 0) continue;

        for (const [cName, cVal] of wireguard_config) {
          itemName = trim(cName);
          itemVal = trim(cVal);
          switch (itemName) {
            case "self-ip":
              ip = itemVal;
              break;
            case "self-ip-v6":
              ipv6 = itemVal;
              break;
            case "private-key":
              private_key = itemVal;
              break;
            case "dns-server": {
              const vArray2 = split(itemVal, ",");
              for (const y of vArray2) dns_servers.push(trim(y));
              break;
            }
            case "mtu":
              mtu = itemVal;
              break;
            case "peer":
              peer = itemVal;
              break;
            case "keepalive":
              keepalive = itemVal;
              break;
          }
        }
        wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers, mtu, keepalive, test_url, "", udp, "");
        parsePeers(node, peer);
        break;
      }
      case "anytls": {
        // Surge style anytls proxy
        server = trim(configs[1]);
        port = trim(configs[2]);
        if (port === "0") continue;
        for (let i = 3; i < configs.length; i++) {
          vArray = splitFirst(configs[i], "=");
          if (vArray.length !== 2) continue;
          itemName = trim(vArray[0]);
          itemVal = trim(vArray[1]);
          switch (itemName) {
            case "password":
              password = itemVal;
              break;
            case "sni":
              sni = itemVal;
              break;
            case "skip-cert-verify":
              scv.setString(itemVal);
              break;
            case "fingerprint":
              fp = itemVal;
              break;
            case "tls13":
              tls13.setString(itemVal);
              break;
            default:
              continue;
          }
        }
        anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, port, password, server, [], fp, sni, udp, new tribool(), scv, new tribool(), "", 30, 30, 0);
        break;
      }
      default: {
        switch (remarks) {
          case "shadowsocks": {
            // quantumult x style ss/ssr link
            {
              const hp = splitHostPortRfind(configs[0]);
              server = trim(hp[0]);
              port = trim(hp[1]);
            }
            if (port === "0") continue;
            for (let i = 1; i < configs.length; i++) {
              vArray = splitFirst(trim(configs[i]), "=");
              if (vArray.length !== 2) continue;
              itemName = trim(vArray[0]);
              itemVal = trim(vArray[1]);
              switch (itemName) {
                case "method":
                  method = itemVal;
                  break;
                case "password":
                  password = itemVal;
                  break;
                case "tag":
                  remarks = itemVal;
                  break;
                case "ssr-protocol":
                  protocol = itemVal;
                  break;
                case "ssr-protocol-param":
                  protoparam = itemVal;
                  break;
                case "obfs": {
                  switch (itemVal) {
                    case "http":
                    case "tls":
                      plugin = "simple-obfs";
                      pluginopts_mode = itemVal;
                      break;
                    case "wss":
                      tls = "tls";
                      pluginopts_mode = "websocket";
                      plugin = "v2ray-plugin";
                      break;
                    case "ws":
                      pluginopts_mode = "websocket";
                      plugin = "v2ray-plugin";
                      break;
                    default:
                      pluginopts_mode = itemVal;
                  }
                  break;
                }
                case "obfs-host":
                  pluginopts_host = itemVal;
                  break;
                case "obfs-uri":
                  path = itemVal;
                  break;
                case "udp-relay":
                  udp.setString(itemVal);
                  break;
                case "fast-open":
                  tfo.setString(itemVal);
                  break;
                case "tls13":
                  tls13.setString(itemVal);
                  break;
                default:
                  continue;
              }
            }
            if (remarks.length === 0) remarks = server + ":" + port;
            switch (plugin) {
              case "simple-obfs":
                pluginopts = "obfs=" + pluginopts_mode;
                if (pluginopts_host.length > 0) pluginopts += ";obfs-host=" + pluginopts_host;
                break;
              case "v2ray-plugin":
                if (pluginopts_host.length === 0 && !isIPv4(server) && !isIPv6(server)) pluginopts_host = server;
                pluginopts = "mode=" + pluginopts_mode;
                if (pluginopts_host.length > 0) pluginopts += ";host=" + pluginopts_host;
                if (path.length > 0) pluginopts += ";path=" + path;
                pluginopts += ";" + tls;
                break;
            }
            if (protocol.length > 0) {
              ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, pluginopts_mode, password, pluginopts_host, protoparam, udp, tfo, scv);
            } else {
              ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv, tls13);
            }
            break;
          }
          case "vmess": {
            // quantumult x style vmess link
            {
              const hp = splitHostPortRfind(configs[0]);
              server = trim(hp[0]);
              port = trim(hp[1]);
            }
            if (port === "0") continue;
            net = "tcp";
            for (let i = 1; i < configs.length; i++) {
              vArray = splitFirst(trim(configs[i]), "=");
              if (vArray.length !== 2) continue;
              itemName = trim(vArray[0]);
              itemVal = trim(vArray[1]);
              switch (itemName) {
                case "method":
                  method = itemVal;
                  break;
                case "password":
                  id = itemVal;
                  break;
                case "tag":
                  remarks = itemVal;
                  break;
                case "obfs":
                  switch (itemVal) {
                    case "ws":
                      net = "ws";
                      break;
                    case "over-tls":
                      tls = "tls";
                      break;
                    case "wss":
                      net = "ws";
                      tls = "tls";
                      break;
                  }
                  break;
                case "obfs-host":
                  host = itemVal;
                  break;
                case "obfs-uri":
                  path = itemVal;
                  break;
                case "over-tls":
                  tls = itemVal === "true" ? "tls" : "";
                  break;
                case "udp-relay":
                  udp.setString(itemVal);
                  break;
                case "fast-open":
                  tfo.setString(itemVal);
                  break;
                case "tls13":
                  tls13.setString(itemVal);
                  break;
                case "aead":
                  aead = itemVal === "true" ? "0" : "1";
                  break;
                default:
                  continue;
              }
            }
            if (remarks.length === 0) remarks = server + ":" + port;
            vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, "", tls, "", [], udp, tfo, scv, tls13);
            break;
          }
          case "vless": {
            // quantumult x style vless link
            {
              const hp = splitHostPortRfind(configs[0]);
              server = trim(hp[0]);
              port = trim(hp[1]);
            }
            if (port === "0") continue;
            net = "tcp";
            for (let i = 1; i < configs.length; i++) {
              vArray = splitFirst(trim(configs[i]), "=");
              if (vArray.length !== 2) continue;
              itemName = trim(vArray[0]);
              itemVal = trim(vArray[1]);
              switch (itemName) {
                case "method":
                  method = itemVal;
                  break;
                case "password":
                  id = itemVal;
                  break;
                case "tag":
                  remarks = itemVal;
                  break;
                case "obfs":
                  switch (itemVal) {
                    case "ws":
                      net = "ws";
                      break;
                    case "over-tls":
                      tls = "tls";
                      break;
                    case "wss":
                      net = "ws";
                      tls = "tls";
                      break;
                  }
                  break;
                case "obfs-host":
                  host = itemVal;
                  break;
                case "obfs-uri":
                  path = itemVal;
                  break;
                case "over-tls":
                  tls = itemVal === "true" ? "tls" : "";
                  break;
                case "udp-relay":
                  udp.setString(itemVal);
                  break;
                case "fast-open":
                  tfo.setString(itemVal);
                  break;
                case "tls13":
                  tls13.setString(itemVal);
                  break;
                case "aead":
                  aead = itemVal === "true" ? "0" : "1";
                  break;
                default:
                  continue;
              }
            }
            if (remarks.length === 0) remarks = server + ":" + port;
            vlessConstruct(node, XRAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, "chrome", "", path, host, "", tls, "", "", fp, sni, [], "", "", udp, tfo, scv, tls13);
            break;
          }
          case "trojan": {
            // quantumult x style trojan link
            {
              const hp = splitHostPortRfind(configs[0]);
              server = trim(hp[0]);
              port = trim(hp[1]);
            }
            if (port === "0") continue;
            for (let i = 1; i < configs.length; i++) {
              vArray = splitFirst(trim(configs[i]), "=");
              if (vArray.length !== 2) continue;
              itemName = trim(vArray[0]);
              itemVal = trim(vArray[1]);
              switch (itemName) {
                case "password":
                  password = itemVal;
                  break;
                case "tag":
                  remarks = itemVal;
                  break;
                case "over-tls":
                  tls = itemVal;
                  break;
                case "tls-host":
                  host = itemVal;
                  sni = itemVal;
                  break;
                case "udp-relay":
                  udp.setString(itemVal);
                  break;
                case "fast-open":
                  tfo.setString(itemVal);
                  break;
                case "tls-verification":
                  scv.setString(itemVal === "false" ? "true" : "false");
                  break;
                case "tls13":
                  tls13.setString(itemVal);
                  break;
                case "fp":
                  fp = itemVal;
                  break;
                default:
                  continue;
              }
            }
            if (remarks.length === 0) remarks = server + ":" + port;
            trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", fp, sni, [], tls === "true", udp, tfo, scv, tls13);
            break;
          }
          case "http": {
            // quantumult x style http links
            {
              const hp = splitHostPortRfind(configs[0]);
              server = trim(hp[0]);
              port = trim(hp[1]);
            }
            if (port === "0") continue;
            for (let i = 1; i < configs.length; i++) {
              vArray = splitFirst(trim(configs[i]), "=");
              if (vArray.length !== 2) continue;
              itemName = trim(vArray[0]);
              itemVal = trim(vArray[1]);
              switch (itemName) {
                case "username":
                  username = itemVal;
                  break;
                case "password":
                  password = itemVal;
                  break;
                case "tag":
                  remarks = itemVal;
                  break;
                case "over-tls":
                  tls = itemVal;
                  break;
                case "tls-verification":
                  scv.setString(itemVal === "false" ? "true" : "false");
                  break;
                case "tls13":
                  tls13.setString(itemVal);
                  break;
                case "fast-open":
                  tfo.setString(itemVal);
                  break;
                default:
                  continue;
              }
            }
            if (remarks.length === 0) remarks = server + ":" + port;
            if (username === "none") username = "";
            if (password === "none") password = "";
            httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, tls === "true", tfo, scv, tls13);
            break;
          }
          default:
            continue;
        }
        break;
      }
    }

    node.Id = index;
    nodes.push(node);
    index++;
  }
  return index;
}
