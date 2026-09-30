// Port of src/parser/subparser.cpp explodeSingboxTransport + explodeSingbox (lines 3017-3302)

import { Proxy, V2RAY_DEFAULT_GROUP, SS_DEFAULT_GROUP, SOCKS_DEFAULT_GROUP, TROJAN_DEFAULT_GROUP, WG_DEFAULT_GROUP, XRAY_DEFAULT_GROUP, HYSTERIA_DEFAULT_GROUP, HYSTERIA2_DEFAULT_GROUP, TUIC_DEFAULT_GROUP, ANYTLS_DEFAULT_GROUP, HTTP_DEFAULT_GROUP } from "../proxy";
import { newProxy } from "../proxy";
import { getMember, jsonToString, vmessConstruct, ssConstruct, trojanConstruct, vlessConstruct, httpConstruct, wireguardConstruct, socksConstruct, hysteriaConstruct, hysteria2Construct, tuicConstruct, anyTlSConstruct } from "./util";
import { tribool } from "../../lib/tribool";

function asObj(v: unknown): Record<string, unknown> | null {
  if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
  return null;
}

function explodeSingboxTransport(singboxNode: Record<string, unknown>, refs: { net: string; host: string; path: string; edge: string }): void {
  const transport = asObj(singboxNode["transport"]);
  if (transport) {
    refs.net = getMember(transport, "type");
    switch (refs.net) {
      case "http":
        refs.host = getMember(transport, "host");
        break;
      case "ws":
        refs.path = getMember(transport, "path");
        {
          const headers = asObj(transport["headers"]);
          if (headers) {
            refs.host = getMember(headers, "Host");
            refs.edge = getMember(headers, "Edge");
          }
        }
        break;
      case "grpc":
        refs.path = getMember(transport, "service_name");
        break;
      default:
        refs.net = "tcp";
        refs.path = "";
        break;
    }
  } else {
    refs.net = "tcp";
    refs.host = "";
    refs.edge = "";
    refs.path = "";
  }
}

export function explodeSingbox(outbounds: unknown[], nodes: Proxy[]): void {
  let index = nodes.length;

  for (const obUnknown of outbounds) {
    const singboxNode = asObj(obUnknown);
    if (!singboxNode) continue;
    if (!("type" in singboxNode) || typeof singboxNode["type"] !== "string") continue;
    const node = newProxy();
    const proxytype = singboxNode["type"] as string;
    let ps = getMember(singboxNode, "tag");
    const server = getMember(singboxNode, "server");
    let port = getMember(singboxNode, "server_port");
    const underlying_proxy = getMember(singboxNode, "detour");
    const tfo = new tribool(getMember(singboxNode, "tcp_fast_open"));
    let alpnList: string[] = [];
    let tls = "", sni = "", alpn = "";
    let scv = new tribool();
    let fp = "chrome", pbk = "", sid = "";
    let disableSni = new tribool();
    let group: string;
    let id = "", aid = "0", net = "tcp", path = "", host = "", edge = "", cipher = "", password = "", plugin = "", pluginopts = "";
    let type = "none", flow = "", encryption = "", packet_encoding = "";
    let user = "", ip = "", ipv6 = "", private_key = "", public_key = "", mtu = "";
    let auth = "", up = "", down = "", obfsParam = "", insecure = "", ports = "";
    let obfsPassword = "", fingerprint = "";
    let congestion_control = "", udp_relay_mode = "";
    const rrt = new tribool();
    const udp = new tribool();

    const tlsObj = asObj(singboxNode["tls"]);
    if (tlsObj) {
      if (tlsObj["enabled"] === true) tls = "tls";
      sni = getMember(tlsObj, "server_name");
      const alpns = tlsObj["alpn"];
      if (Array.isArray(alpns) && alpns.length > 0) {
        alpn = jsonToString(alpns[0]);
        for (const item of alpns) {
          if (typeof item === "string") alpnList.push(item);
        }
      }
      if (typeof tlsObj["insecure"] === "boolean") {
        scv = new tribool(tlsObj["insecure"]);
      }
      if (typeof tlsObj["disable_sni"] === "boolean") {
        disableSni = new tribool(tlsObj["disable_sni"]);
      }
      if (typeof tlsObj["certificate"] === "string") {
        public_key = tlsObj["certificate"] as string;
      }
      const certFps = tlsObj["certificate_public_key_sha256"];
      if (Array.isArray(certFps) && certFps.length > 0 && typeof certFps[0] === "string") {
        fingerprint = certFps[0] as string;
      }
      const reality = asObj(tlsObj["reality"]);
      if (reality) {
        tls = "reality";
        if (typeof reality["server_name"] === "string") host = reality["server_name"] as string;
        if (typeof reality["public_key"] === "string") pbk = reality["public_key"] as string;
        if (typeof reality["short_id"] === "string") sid = reality["short_id"] as string;
      }
      const utls = asObj(tlsObj["utls"]);
      if (utls && typeof utls["fingerprint"] === "string") {
        fingerprint = utls["fingerprint"] as string;
      }
    } else {
      tls = "false";
    }

    let skip = false;
    switch (proxytype) {
      case "vmess": {
        group = V2RAY_DEFAULT_GROUP;
        id = getMember(singboxNode, "uuid");
        if (id.length < 36) {
          skip = true;
          break;
        }
        aid = getMember(singboxNode, "alter_id");
        cipher = getMember(singboxNode, "security");
        const refs = { net, host, path, edge };
        explodeSingboxTransport(singboxNode, refs);
        net = refs.net;
        host = refs.host;
        path = refs.path;
        edge = refs.edge;
        vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, alpnList, udp, tfo, scv, new tribool(), underlying_proxy);
        break;
      }
      case "shadowsocks": {
        group = SS_DEFAULT_GROUP;
        cipher = getMember(singboxNode, "method");
        password = getMember(singboxNode, "password");
        plugin = getMember(singboxNode, "plugin");
        pluginopts = getMember(singboxNode, "plugin_opts");
        ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv, new tribool(), underlying_proxy);
        break;
      }
      case "trojan": {
        group = TROJAN_DEFAULT_GROUP;
        password = getMember(singboxNode, "password");
        const refs = { net, host, path, edge };
        explodeSingboxTransport(singboxNode, refs);
        net = refs.net;
        host = refs.host;
        path = refs.path;
        edge = refs.edge;
        trojanConstruct(node, group, ps, server, port, password, net, host, path, fp, sni, alpnList, true, udp, tfo, scv, new tribool(), underlying_proxy);
        break;
      }
      case "vless": {
        group = XRAY_DEFAULT_GROUP;
        id = getMember(singboxNode, "uuid");
        flow = getMember(singboxNode, "flow");
        encryption = getMember(singboxNode, "encryption");
        packet_encoding = getMember(singboxNode, "packet_encoding");
        const transport = asObj(singboxNode["transport"]);
        if (transport) {
          net = getMember(transport, "type");
          switch (net) {
            case "tcp":
              break;
            case "ws": {
              path = getMember(transport, "path");
              const headers = asObj(transport["headers"]);
              if (headers) {
                host = getMember(headers, "Host");
                edge = getMember(headers, "Edge");
              }
              break;
            }
            case "http":
              host = getMember(transport, "host");
              path = getMember(transport, "path");
              edge = "";
              break;
            case "httpupgrade":
              net = "h2";
              host = getMember(transport, "host");
              path = getMember(transport, "path");
              edge = "";
              break;
            case "grpc":
              host = server;
              path = getMember(transport, "service_name");
              break;
          }
        }
        vlessConstruct(node, group, ps, server, port, type, id, aid, net, "auto", flow, "", path, host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, encryption, udp, new tribool(), new tribool(), new tribool(), underlying_proxy);
        break;
      }
      case "http": {
        group = HTTP_DEFAULT_GROUP;
        password = getMember(singboxNode, "password");
        user = getMember(singboxNode, "username");
        httpConstruct(node, group, ps, server, port, user, password, tls === "tls", tfo, scv, new tribool(), underlying_proxy);
        break;
      }
      case "wireguard": {
        group = WG_DEFAULT_GROUP;
        ip = getMember(singboxNode, "inet4_bind_address");
        ipv6 = getMember(singboxNode, "inet6_bind_address");
        // NOTE: upstream swaps private/public keys here (faithful port)
        public_key = getMember(singboxNode, "private_key");
        private_key = getMember(singboxNode, "public_key");
        mtu = getMember(singboxNode, "mtu");
        password = getMember(singboxNode, "pre_shared_key");
        const dns_server = ["8.8.8.8"];
        wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password, dns_server, mtu, "0", "", "", udp, underlying_proxy);
        break;
      }
      case "socks": {
        group = SOCKS_DEFAULT_GROUP;
        user = getMember(singboxNode, "username");
        password = getMember(singboxNode, "password");
        socksConstruct(node, group, ps, server, port, user, password, new tribool(), new tribool(), new tribool(), underlying_proxy);
        break;
      }
      case "hysteria": {
        group = HYSTERIA_DEFAULT_GROUP;
        up = getMember(singboxNode, "up");
        if (up.length === 0) up = getMember(singboxNode, "up_mbps");
        down = getMember(singboxNode, "down");
        if (down.length === 0) down = getMember(singboxNode, "down_mbps");
        auth = getMember(singboxNode, "auth_str");
        type = getMember(singboxNode, "network");
        obfsParam = getMember(singboxNode, "obfs");
        hysteriaConstruct(node, group, ps, server, port, type, auth, "", host, up, down, alpn, obfsParam, insecure, ports, sni, udp, tfo, scv, new tribool(), underlying_proxy);
        break;
      }
      case "anytls": {
        group = ANYTLS_DEFAULT_GROUP;
        password = getMember(singboxNode, "password");
        anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, ps, port, password, server, alpnList, fingerprint, sni, udp, new tribool(), scv, new tribool(), underlying_proxy, 30, 30, 0);
        break;
      }
      case "hysteria2": {
        group = HYSTERIA2_DEFAULT_GROUP;
        password = getMember(singboxNode, "password");
        up = getMember(singboxNode, "up");
        down = getMember(singboxNode, "down");
        const obfsOpt = asObj(singboxNode["obfs"]);
        if (obfsOpt) {
          obfsParam = getMember(obfsOpt, "type");
          obfsPassword = getMember(obfsOpt, "password");
        }
        hysteria2Construct(node, group, ps, server, port, password, host, up, down, alpn, obfsParam, obfsPassword, sni, public_key, fingerprint, "", udp, tfo, scv, underlying_proxy);
        break;
      }
      case "tuic": {
        group = TUIC_DEFAULT_GROUP;
        password = getMember(singboxNode, "password");
        id = getMember(singboxNode, "uuid");
        congestion_control = getMember(singboxNode, "congestion_control");
        if (typeof singboxNode["zero_rtt_handshake"] === "boolean") {
          rrt.set(singboxNode["zero_rtt_handshake"] as boolean);
        }
        udp_relay_mode = getMember(singboxNode, "udp_relay_mode");
        tuicConstruct(node, TUIC_DEFAULT_GROUP, ps, server, port, password, congestion_control, alpn, sni, id, udp_relay_mode, "", new tribool(), new tribool(), scv, rrt, disableSni, 15000, underlying_proxy);
        break;
      }
      default:
        continue;
    }
    if (skip) continue;
    node.Id = index;
    nodes.push(node);
    index++;
  }
}
