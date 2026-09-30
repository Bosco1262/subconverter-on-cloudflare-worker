// Port of src/parser/subparser.cpp explodeClash (lines 1295-1743) — Clash YAML subscription parsing

import { Proxy, V2RAY_DEFAULT_GROUP, SS_DEFAULT_GROUP, SOCKS_DEFAULT_GROUP, SSR_DEFAULT_GROUP, HTTP_DEFAULT_GROUP, TROJAN_DEFAULT_GROUP, SNELL_DEFAULT_GROUP, WG_DEFAULT_GROUP, XRAY_DEFAULT_GROUP, HYSTERIA_DEFAULT_GROUP, HYSTERIA2_DEFAULT_GROUP, TUIC_DEFAULT_GROUP, ANYTLS_DEFAULT_GROUP, MIERU_DEFAULT_GROUP } from "../proxy";
import { newProxy } from "../proxy";
import { yAsStr, yAsStrList, yIsDefined, yStr, type YNode } from "../../lib/yaml";
import { replaceAllDistinct, toInt, toLower } from "../../lib/string";
import { ssConstruct, ssrConstruct, socksConstruct, httpConstruct, trojanConstruct, snellConstruct, wireguardConstruct, vmessConstruct, vlessConstruct, hysteriaConstruct, hysteria2Construct, tuicConstruct, anyTlSConstruct, mieruConstruct, isIPv4, isIPv6, xhttp_option_keys } from "./util";
import { tribool } from "../../lib/tribool";

function asObj(v: unknown): Record<string, unknown> | null {
  if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
  return null;
}

export function explodeClash(yamlnode: Record<string, unknown>, nodes: Proxy[]): void {
  let index = nodes.length;
  const section = Array.isArray(yamlnode["proxies"]) ? "proxies" : "Proxy";
  const proxies = yamlnode[section];
  if (!Array.isArray(proxies)) return;

  for (const singleproxyUnknown of proxies) {
    const singleproxy = asObj(singleproxyUnknown);
    if (!singleproxy) continue;
    const node = newProxy();
    try {
      const proxytype = yStr(singleproxy["type"]);
      let ps = yStr(singleproxy["name"]);
      let server = yStr(singleproxy["server"]);
      let port = yStr(singleproxy["port"]);
      let portRange = yStr(singleproxy["port-range"]);
      if ((port.length === 0 || port === "0") && portRange.length === 0) continue;
      const udp = new tribool(yStr(singleproxy["udp"]));
      const scv = new tribool(yStr(singleproxy["skip-cert-verify"]));
      const underlying_proxy = yStr(singleproxy["dialer-proxy"]);
      let group: string;
      let cipher = "", password = "", id = "", aid = "0", net = "tcp", path = "", host = "", edge = "", tls = "", sni = "", type = "none";
      let plugin = "", pluginopts = "", pluginopts_mode = "", pluginopts_host = "", pluginopts_mux = "";
      let protocol = "", protoparam = "", obfs = "", obfsparam = "";
      let flow = "", mode = "";
      let user = "";
      let ip = "", ipv6 = "", private_key = "", public_key = "", mtu = "";
      let auth = "", up = "", down = "", obfsParam = "", insecure = "", alpn = "";
      let obfsPassword = "";
      let congestion_control = "", udp_relay_mode = "", token = "";
      let fp = "chrome", pbk = "", sid = "", packet_encoding = "", encryption = "";
      let fingerprint = "", multiplexing = "", transfer_protocol = "", v2ray_http_upgrade = "";
      let ports = "";
      let alpnList: string[] = [];
      const alpns: string[] = [];
      let alpn2 = "";

      switch (proxytype) {
        case "vmess": {
          group = V2RAY_DEFAULT_GROUP;
          id = yStr(singleproxy["uuid"]);
          if (id.length < 36) break;
          aid = yStr(singleproxy["alterId"], "0");
          cipher = yStr(singleproxy["cipher"]);
          net = yIsDefined(singleproxy["network"]) ? yStr(singleproxy["network"]) : "tcp";
          sni = yStr(singleproxy["servername"]);
          switch (net) {
            case "http": {
              const httpOpts = asObj(singleproxy["http-opts"]);
              const httpPath = httpOpts && Array.isArray(httpOpts["path"]) ? httpOpts["path"] : null;
              if (httpPath) path = yAsStr(httpPath[0]);
              const headers = httpOpts ? asObj(httpOpts["headers"]) : null;
              const hostArr = headers && Array.isArray(headers["Host"]) ? headers["Host"] : null;
              if (hostArr) host = yAsStr(hostArr[0]);
              edge = "";
              break;
            }
            case "ws": {
              const wsOpts = asObj(singleproxy["ws-opts"]);
              if (wsOpts) {
                path = yIsDefined(wsOpts["path"]) ? yStr(wsOpts["path"]) : "/";
                const headers = asObj(wsOpts["headers"]);
                host = headers ? yStr(headers["Host"]) : "";
                if (host.length === 0) host = headers ? yStr(headers["host"]) : "";
                edge = headers ? yStr(headers["Edge"]) : "";
              } else {
                path = yIsDefined(singleproxy["ws-path"]) ? yStr(singleproxy["ws-path"]) : "/";
                const headers = asObj(singleproxy["ws-headers"]);
                host = headers ? yStr(headers["Host"]) : "";
                edge = headers ? yStr(headers["Edge"]) : "";
              }
              break;
            }
            case "h2": {
              const h2 = asObj(singleproxy["h2-opts"]);
              path = h2 ? yStr(h2["path"]) : "";
              const hostArr = h2 && Array.isArray(h2["host"]) ? h2["host"] : null;
              if (hostArr) host = yAsStr(hostArr[0]);
              edge = "";
              break;
            }
            case "grpc": {
              host = yStr(singleproxy["servername"]);
              const grpcOpts = asObj(singleproxy["grpc-opts"]);
              path = grpcOpts ? yStr(grpcOpts["grpc-service-name"]) : "";
              edge = "";
              break;
            }
          }
          tls = yStr(singleproxy["tls"]) === "true" ? "tls" : "";
          try {
            alpnList = yAsStrList(singleproxy["alpn"]);
          } catch {
            alpnList = [];
          }
          vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, alpnList, udp, new tribool(), scv, new tribool(), underlying_proxy);
          break;
        }
        case "ss": {
          group = SS_DEFAULT_GROUP;
          cipher = yStr(singleproxy["cipher"]);
          password = yStr(singleproxy["password"]);
          if (yIsDefined(singleproxy["plugin"])) {
            switch (yStr(singleproxy["plugin"])) {
              case "obfs": {
                plugin = "obfs-local";
                const opts = asObj(singleproxy["plugin-opts"]);
                if (opts) {
                  pluginopts_mode = yStr(opts["mode"]);
                  pluginopts_host = yStr(opts["host"]);
                }
                break;
              }
              case "v2ray-plugin": {
                plugin = "v2ray-plugin";
                const opts = asObj(singleproxy["plugin-opts"]);
                if (opts) {
                  pluginopts_mode = yStr(opts["mode"]);
                  pluginopts_host = yStr(opts["host"]);
                  tls = yAsStr(opts["tls"]) === "true" ? "tls;" : "";
                  path = yStr(opts["path"]);
                  pluginopts_mux = yAsStr(opts["mux"]) === "true" ? "4" : "";
                }
                break;
              }
              default:
                break;
            }
          } else if (yIsDefined(singleproxy["obfs"])) {
            plugin = "obfs-local";
            pluginopts_mode = yStr(singleproxy["obfs"]);
            pluginopts_host = yStr(singleproxy["obfs-host"]);
          } else plugin = "";

          switch (plugin) {
            case "simple-obfs":
            case "obfs-local":
              pluginopts = "obfs=" + pluginopts_mode;
              pluginopts += pluginopts_host.length === 0 ? "" : ";obfs-host=" + pluginopts_host;
              break;
            case "v2ray-plugin":
              pluginopts = "mode=" + pluginopts_mode + ";" + tls;
              if (pluginopts_host.length > 0) pluginopts += "host=" + pluginopts_host + ";";
              if (path.length > 0) pluginopts += "path=" + path + ";";
              if (pluginopts_mux.length > 0) pluginopts += "mux=" + pluginopts_mux + ";";
              break;
          }

          // support for go-shadowsocks2
          if (cipher === "AEAD_CHACHA20_POLY1305") cipher = "chacha20-ietf-poly1305";
          else if (cipher.includes("AEAD")) {
            cipher = toLower(replaceAllDistinct(replaceAllDistinct(cipher, "AEAD_", ""), "_", "-"));
          }

          ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, new tribool(), scv, new tribool(), underlying_proxy);
          break;
        }
        case "socks5": {
          group = SOCKS_DEFAULT_GROUP;
          user = yStr(singleproxy["username"]);
          password = yStr(singleproxy["password"]);
          socksConstruct(node, group, ps, server, port, user, password, new tribool(), new tribool(), new tribool(), underlying_proxy);
          break;
        }
        case "ssr": {
          group = SSR_DEFAULT_GROUP;
          cipher = yStr(singleproxy["cipher"]);
          if (cipher === "dummy") cipher = "none";
          password = yStr(singleproxy["password"]);
          protocol = yStr(singleproxy["protocol"]);
          obfs = yStr(singleproxy["obfs"]);
          protoparam = yIsDefined(singleproxy["protocol-param"]) ? yStr(singleproxy["protocol-param"]) : yStr(singleproxy["protocolparam"]);
          obfsparam = yIsDefined(singleproxy["obfs-param"]) ? yStr(singleproxy["obfs-param"]) : yStr(singleproxy["obfsparam"]);
          ssrConstruct(node, group, ps, server, port, protocol, cipher, obfs, password, obfsparam, protoparam, udp, new tribool(), scv, underlying_proxy);
          break;
        }
        case "http": {
          group = HTTP_DEFAULT_GROUP;
          user = yStr(singleproxy["username"]);
          password = yStr(singleproxy["password"]);
          tls = yStr(singleproxy["tls"]);
          httpConstruct(node, group, ps, server, port, user, password, tls === "true", new tribool(), scv, new tribool(), underlying_proxy);
          break;
        }
        case "trojan": {
          group = TROJAN_DEFAULT_GROUP;
          password = yStr(singleproxy["password"]);
          host = yStr(singleproxy["sni"]);
          sni = yStr(singleproxy["sni"]);
          net = yStr(singleproxy["network"]);
          switch (net) {
            case "grpc": {
              const grpcOpts = asObj(singleproxy["grpc-opts"]);
              path = grpcOpts ? yStr(grpcOpts["grpc-service-name"]) : "";
              break;
            }
            case "ws": {
              const wsOpts = asObj(singleproxy["ws-opts"]);
              path = wsOpts ? yStr(wsOpts["path"]) : "";
              break;
            }
            default:
              net = "tcp";
              path = "";
              break;
          }
          try {
            alpnList = yAsStrList(singleproxy["alpn"]);
          } catch {
            alpnList = [];
          }
          trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList, true, udp, new tribool(), scv, new tribool(), underlying_proxy);
          break;
        }
        case "snell": {
          group = SNELL_DEFAULT_GROUP;
          password = yStr(singleproxy["psk"]);
          const obfsOpts = asObj(singleproxy["obfs-opts"]);
          obfs = obfsOpts ? yStr(obfsOpts["mode"]) : "";
          host = obfsOpts ? yStr(obfsOpts["host"]) : "";
          aid = yStr(singleproxy["version"], "0");
          snellConstruct(node, group, ps, server, port, password, obfs, host, toInt(aid, 0), udp, new tribool(), scv, underlying_proxy);
          break;
        }
        case "wireguard": {
          group = WG_DEFAULT_GROUP;
          public_key = yStr(singleproxy["public-key"]);
          private_key = yStr(singleproxy["private-key"]);
          const dnsList = singleproxy["dns"];
          const dns_server: string[] = Array.isArray(dnsList) ? dnsList.map((x) => yAsStr(x)) : [];
          mtu = yStr(singleproxy["mtu"]);
          password = yStr(singleproxy["preshared-key"]);
          ip = yStr(singleproxy["ip"]);
          ipv6 = yStr(singleproxy["ipv6"]);
          wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password, dns_server, mtu, "0", "", "", udp, underlying_proxy);
          break;
        }
        case "vless": {
          group = XRAY_DEFAULT_GROUP;
          id = yStr(singleproxy["uuid"]);
          aid = yStr(singleproxy["alterId"], "0");
          net = yIsDefined(singleproxy["network"]) ? yStr(singleproxy["network"]) : "tcp";
          sni = yIsDefined(singleproxy["sni"]) ? yStr(singleproxy["sni"]) : yStr(singleproxy["servername"]);
          switch (net) {
            case "tcp":
            case "http": {
              const httpOpts = asObj(singleproxy["http-opts"]);
              const httpPath = httpOpts && Array.isArray(httpOpts["path"]) ? httpOpts["path"] : null;
              if (httpPath) path = yAsStr(httpPath[0]);
              const headers = httpOpts ? asObj(httpOpts["headers"]) : null;
              const hostArr = headers && Array.isArray(headers["Host"]) ? headers["Host"] : null;
              if (hostArr) host = yAsStr(hostArr[0]);
              edge = "";
              break;
            }
            case "ws": {
              const wsOpts = asObj(singleproxy["ws-opts"]);
              if (wsOpts) {
                path = yIsDefined(wsOpts["path"]) ? yStr(wsOpts["path"]) : "/";
                const headers = asObj(wsOpts["headers"]);
                host = headers ? yStr(headers["Host"]) : "";
                if (host.length === 0) host = headers ? yStr(headers["host"]) : "";
                edge = headers ? yStr(headers["Edge"]) : "";
                if (yIsDefined(wsOpts["v2ray-http-upgrade"])) {
                  v2ray_http_upgrade = yStr(wsOpts["v2ray-http-upgrade"]);
                }
              } else {
                path = yIsDefined(singleproxy["ws-path"]) ? yStr(singleproxy["ws-path"]) : "/";
                const headers = asObj(singleproxy["ws-headers"]);
                host = headers ? yStr(headers["Host"]) : "";
                edge = headers ? yStr(headers["Edge"]) : "";
              }
              break;
            }
            case "h2": {
              const h2 = asObj(singleproxy["h2-opts"]);
              path = h2 ? yStr(h2["path"]) : "";
              const hostArr = h2 && Array.isArray(h2["host"]) ? h2["host"] : null;
              if (hostArr) host = yAsStr(hostArr[0]);
              edge = "";
              break;
            }
            case "xhttp": {
              const xhttpOpts = asObj(singleproxy["xhttp-opts"]);
              if (xhttpOpts) {
                path = yIsDefined(xhttpOpts["path"]) ? yStr(xhttpOpts["path"]) : "/";
                host = yStr(xhttpOpts["host"]);
                if (host.length === 0) {
                  const headers = asObj(xhttpOpts["headers"]);
                  host = headers ? yStr(headers["Host"]) : "";
                }
                edge = asObj(xhttpOpts["headers"]) ? yStr((asObj(xhttpOpts["headers"]) as Record<string, unknown>)["Edge"]) : "";
                if (asObj(xhttpOpts)) {
                  for (const key of xhttp_option_keys) {
                    if (typeof xhttpOpts[key] === "string" || typeof xhttpOpts[key] === "number" || typeof xhttpOpts[key] === "boolean") {
                      node.XHTTPOptions[key] = yAsStr(xhttpOpts[key]);
                    }
                  }
                }
              }
              break;
            }
            case "grpc": {
              host = yStr(singleproxy["servername"]);
              const grpcOpts = asObj(singleproxy["grpc-opts"]);
              path = grpcOpts ? yStr(grpcOpts["grpc-service-name"]) : "";
              edge = "";
              break;
            }
            default:
              continue;
          }

          tls = yStr(singleproxy["tls"]) === "true" ? "tls" : "";
          const realityOpts = asObj(singleproxy["reality-opts"]);
          if (realityOpts) {
            host = yIsDefined(singleproxy["sni"]) ? yStr(singleproxy["sni"]) : yStr(singleproxy["servername"]);
            pbk = yStr(realityOpts["public-key"]);
            sid = yStr(realityOpts["short-id"]);
          }
          flow = yStr(singleproxy["flow"]);
          fp = yStr(singleproxy["client-fingerprint"]);
          if (fp.length === 0) fp = "chrome";
          try {
            alpnList = yAsStrList(singleproxy["alpn"]);
          } catch {
            alpnList = [];
          }
          packet_encoding = yStr(singleproxy["packet-encoding"]);
          encryption = yStr(singleproxy["encryption"]);
          vlessConstruct(node, XRAY_DEFAULT_GROUP, ps, server, port, type, id, aid, net, "auto", flow, mode, path, host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, encryption, udp, new tribool(), new tribool(), new tribool(), underlying_proxy, new tribool(v2ray_http_upgrade));
          break;
        }
        case "hysteria": {
          group = HYSTERIA_DEFAULT_GROUP;
          auth = yStr(singleproxy["auth_str"]);
          if (auth.length === 0) {
            auth = yStr(singleproxy["auth-str"]);
            if (auth.length === 0) auth = yStr(singleproxy["password"]);
          }
          up = yStr(singleproxy["up"]);
          down = yStr(singleproxy["down"]);
          obfsParam = yStr(singleproxy["obfs"]);
          type = yStr(singleproxy["protocol"]);
          host = yStr(singleproxy["sni"]);
          const alpnNode = singleproxy["alpn"];
          if (Array.isArray(alpnNode) && alpnNode.length > 0) alpn = yAsStr(alpnNode[0]);
          try {
            alpnList = yAsStrList(singleproxy["alpn"]);
          } catch {
            alpnList = [];
          }
          insecure = yStr(singleproxy["protocol"]);
          ports = yStr(singleproxy["ports"]);
          sni = host;
          hysteriaConstruct(node, group, ps, server, port, type, auth, "", host, up, down, alpn, obfsParam, insecure, ports, sni, udp, new tribool(), scv, new tribool(), underlying_proxy);
          break;
        }
        case "hysteria2": {
          group = HYSTERIA2_DEFAULT_GROUP;
          password = yStr(singleproxy["password"]);
          if (password.length === 0) password = yStr(singleproxy["auth"]);
          if (yIsDefined(singleproxy["up"])) {
            up = yStr(singleproxy["up"]);
          }
          if (yIsDefined(singleproxy["down"])) {
            down = yStr(singleproxy["down"]);
          }
          obfsParam = yStr(singleproxy["obfs"]);
          obfsPassword = yStr(singleproxy["obfs-password"]);
          host = yStr(singleproxy["sni"]);
          const alpnNode = singleproxy["alpn"];
          if (Array.isArray(alpnNode) && alpnNode.length > 0) alpn = yAsStr(alpnNode[0]);
          ports = yStr(singleproxy["ports"]);
          fingerprint = yStr(singleproxy["fingerprint"]);
          sni = host;
          hysteria2Construct(node, group, ps, server, port, password, host, up, down, alpn, obfsParam, obfsPassword, sni, public_key, fingerprint, ports, udp, new tribool(), scv, underlying_proxy);
          break;
        }
        case "tuic": {
          group = TUIC_DEFAULT_GROUP;
          let request_timeout = 15000;
          password = yStr(singleproxy["password"]);
          id = yStr(singleproxy["uuid"]);
          congestion_control = yStr(singleproxy["congestion-controller"]);
          udp_relay_mode = yStr(singleproxy["udp-relay-mode"]);
          sni = yStr(singleproxy["sni"]);
          const alpnNode = singleproxy["alpn"];
          if (alpnNode !== null && alpnNode !== undefined) {
            if (Array.isArray(alpnNode) && alpnNode.length > 0) alpn = yAsStr(alpnNode[0]);
          }
          const disableSni = new tribool(yStr(singleproxy["disable-sni"]));
          const reduceRtt = new tribool(yStr(singleproxy["reduce-rtt"]));
          token = yStr(singleproxy["token"]);
          {
            const rt = yStr(singleproxy["request-timeout"]);
            if (rt.length > 0) {
              const n = toInt(rt, 0);
              request_timeout = n > 0 && n < 65536 ? n : 15000;
            }
          }
          tuicConstruct(node, TUIC_DEFAULT_GROUP, ps, server, port, password, congestion_control, alpn, sni, id, udp_relay_mode, token, new tribool(), new tribool(), scv, reduceRtt, disableSni, request_timeout, underlying_proxy);
          break;
        }
        case "anytls": {
          group = ANYTLS_DEFAULT_GROUP;
          password = yStr(singleproxy["password"]);
          sni = yStr(singleproxy["sni"]);
          const alpnNode = singleproxy["alpn"];
          if (alpnNode !== null && alpnNode !== undefined && Array.isArray(alpnNode) && alpnNode.length >= 1) {
            alpn = yAsStr(alpnNode[0]);
            alpns.push(alpn);
            if (alpnNode.length >= 2 && alpnNode[1] !== null) {
              alpn2 = yAsStr(alpnNode[1]);
              alpns.push(alpn2);
            }
          }
          fingerprint = yStr(singleproxy["fingerprint"]);
          anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, port, password, server, alpns, fingerprint, sni, udp, new tribool(), scv, new tribool(), underlying_proxy, 30, 30, 0);
          break;
        }
        case "mieru": {
          group = MIERU_DEFAULT_GROUP;
          password = yStr(singleproxy["password"]);
          user = yStr(singleproxy["username"]);
          {
            const portsVal = yStr(singleproxy["port-range"]);
            if (portsVal) ports = portsVal;
          }
          if (singleproxy["multiplexing"] !== null && singleproxy["multiplexing"] !== undefined) {
            multiplexing = yStr(singleproxy["multiplexing"]);
          }
          transfer_protocol = "TCP";
          if (singleproxy["transport"] !== null && singleproxy["transport"] !== undefined) {
            transfer_protocol = yStr(singleproxy["transport"]);
          }
          mieruConstruct(node, MIERU_DEFAULT_GROUP, ps, port, password, server, ports, user, multiplexing, transfer_protocol, udp, new tribool(), scv, new tribool(), underlying_proxy);
          break;
        }
        default:
          continue;
      }

      node.Id = index;
      nodes.push(node);
      index++;
    } catch {
      // yaml-cpp type errors skip the node in practice; keep parsing the rest
      continue;
    }
  }
}
