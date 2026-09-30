// Port of src/parser/subparser.cpp �?per-link explode functions

import { base64Encode, urlSafeBase64Decode } from "../../lib/base64";
import { countLeast, replaceAllDistinct, split, splitFirst, startsWith, strFind, toInt, trim, trimQuote } from "../../lib/string";
import { urlDecode, urlEncode } from "../../lib/urlencode";
import { regFind, regGetAllMatch, regGetMatch, regMatch, regReplace } from "../../lib/regex";
import { getUrlArg } from "../../lib/string";
import { newProxy, Proxy, ProxyType, SS_DEFAULT_GROUP, SSR_DEFAULT_GROUP, V2RAY_DEFAULT_GROUP, SOCKS_DEFAULT_GROUP, HTTP_DEFAULT_GROUP, TROJAN_DEFAULT_GROUP, XRAY_DEFAULT_GROUP, HYSTERIA_DEFAULT_GROUP, HYSTERIA2_DEFAULT_GROUP, TUIC_DEFAULT_GROUP, ANYTLS_DEFAULT_GROUP, MIERU_DEFAULT_GROUP } from "../proxy";
import {
  ss_ciphers, ssConstruct, ssrConstruct, socksConstruct, httpConstruct, trojanConstruct, snellConstruct,
  wireguardConstruct, vmessConstruct, vlessConstruct, hysteriaConstruct, hysteria2Construct, anyTlSConstruct,
  mieruConstruct, tuicConstruct, extractRemark, getUrlAlpn, getUrlAlpnList, getMember, readXHTTPExtraOptions,
  removeBrackets, jsonToString, xhttp_option_keys, isIPv4, isIPv6, isLink,
} from "./util";
import { tribool } from "../../lib/tribool";

export { isIPv4, isIPv6, isLink };

export function explodeVmess(vmess0: string, node: Proxy): void {
  let vmess = vmess0;
  let version = "", ps = "", add = "", port = "", type = "", id = "", aid = "", net = "", path = "", host = "", tls = "", sni = "";

  if (regMatch(vmess, "vmess://([A-Za-z0-9-_]+)\\?(.*)")) {
    explodeShadowrocket(vmess, node);
    return;
  } else if (regMatch(vmess, "vmess://(.*?)@(.*)")) {
    explodeStdVMess(vmess, node);
    return;
  } else if (regMatch(vmess, "vmess1://(.*?)\\?(.*)")) {
    explodeKitsunebi(vmess, node);
    return;
  }
  vmess = urlSafeBase64Decode(regReplace(vmess, "(vmess|vmess1)://", ""));
  if (regMatch(vmess, "(.*?) = (.*)")) {
    explodeQuan(vmess, node);
    return;
  }
  let jsondata: Record<string, unknown>;
  try {
    const parsed = JSON.parse(vmess);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
    jsondata = parsed;
  } catch {
    return;
  }

  version = "1"; // link without version treated as version 1
  {
    const v = getMember(jsondata, "v");
    if (v.length > 0) version = v;
  }
  ps = getMember(jsondata, "ps");
  add = getMember(jsondata, "add");
  port = getMember(jsondata, "port");
  if (port === "0") return;
  type = getMember(jsondata, "type");
  id = getMember(jsondata, "id");
  aid = getMember(jsondata, "aid");
  net = getMember(jsondata, "net");
  tls = getMember(jsondata, "tls");
  host = getMember(jsondata, "host");
  sni = getMember(jsondata, "sni");
  switch (toInt(version)) {
    case 1:
      if (host.length > 0) {
        const vArray = split(host, ";");
        if (vArray.length === 2) {
          host = vArray[0];
          path = vArray[1];
        }
      }
      break;
    case 2:
      path = getMember(jsondata, "path");
      break;
  }
  add = trim(add);
  vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, "auto", path, host, "", tls, sni, []);
}

export function explodeSS(ss0: string, node: Proxy): void {
  let ss = ss0;
  let ps = "", password = "", method = "", server = "", port = "", plugins = "", plugin = "", pluginopts = "", addition = "", group = SS_DEFAULT_GROUP, secret = "";

  ss = replaceAllDistinct(ss.substring(5), "/?", "?");
  if (strFind(ss, "#")) {
    const sspos = ss.indexOf("#");
    ps = urlDecode(ss.substring(sspos + 1));
    ss = ss.substring(0, sspos);
  }
  if (strFind(ss, "?")) {
    addition = ss.substring(ss.indexOf("?") + 1);
    plugins = urlDecode(getUrlArg(addition, "plugin"));
    const pluginpos = plugins.indexOf(";");
    plugin = pluginpos === -1 ? plugins : plugins.substring(0, pluginpos);
    // C++: plugins.substr(pluginpos+1) �?pluginpos==npos gives "" (pos+1 overflows to 0 �?whole string!)
    // std::string::npos + 1 == 0 �?substr(0) = whole string
    pluginopts = pluginpos === -1 ? plugins : plugins.substring(pluginpos + 1);
    group = getUrlArg(addition, "group");
    if (group.length > 0) group = urlSafeBase64Decode(group);
    ss = ss.substring(0, ss.indexOf("?"));
  }
  if (strFind(ss, "@")) {
    const m = regGetMatch(ss, "(\\S+?)@(\\S+):(\\d+)");
    if (!m) return;
    [, secret, server, port] = m;
    const m2 = regGetMatch(urlSafeBase64Decode(secret), "(\\S+?):(\\S+)");
    if (!m2) return;
    [, method, password] = m2;
  } else {
    const m = regGetMatch(urlSafeBase64Decode(ss), "(\\S+?):(\\S+)@(\\S+):(\\d+)");
    if (!m) return;
    [, method, password, server, port] = m;
  }
  if (port === "0") return;
  if (ps.length === 0) ps = server + ":" + port;
  ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
}

export function explodeSSR(ssr0: string, node: Proxy): void {
  let ssr = ssr0;
  let strobfs = "";
  let remarks = "", group = "", server = "", port = "", method = "", password = "", protocol = "", protoparam = "", obfs = "", obfsparam = "";
  ssr = replaceAllDistinct(ssr.substring(6), "\r", "");
  ssr = urlSafeBase64Decode(ssr);
  if (strFind(ssr, "/?")) {
    strobfs = ssr.substring(ssr.indexOf("/?") + 2);
    ssr = ssr.substring(0, ssr.indexOf("/?"));
    group = urlSafeBase64Decode(getUrlArg(strobfs, "group"));
    remarks = urlSafeBase64Decode(getUrlArg(strobfs, "remarks"));
    obfsparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "obfsparam")), "\\s", "");
    protoparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "protoparam")), "\\s", "");
  }
  const m = regGetMatch(ssr, "(\\S+):(\\d+?):(\\S+?):(\\S+?):(\\S+?):(\\S+)");
  if (!m) return;
  [, server, port, protocol, method, obfs, password] = m;
  password = urlSafeBase64Decode(password);
  if (port === "0") return;
  if (group.length === 0) group = SSR_DEFAULT_GROUP;
  if (remarks.length === 0) remarks = server + ":" + port;

  if (ss_ciphers.includes(method) && (obfs.length === 0 || obfs === "plain") && (protocol.length === 0 || protocol === "origin")) {
    ssConstruct(node, group, remarks, server, port, password, method, "", "");
  } else {
    ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
  }
}

export function explodeSocks(link0: string, node: Proxy): void {
  let link = link0;
  let group = "", remarks = "", server = "", port = "", username = "", password = "";
  if (strFind(link, "socks://")) {
    // v2rayn socks link
    if (strFind(link, "#")) {
      const pos = link.indexOf("#");
      remarks = urlDecode(link.substring(pos + 1));
      link = link.substring(0, pos);
    }
    link = urlSafeBase64Decode(link.substring(8));
    if (strFind(link, "@")) {
      let userinfo = split(link, "@");
      if (userinfo.length < 2) return;
      link = userinfo[1];
      userinfo = split(userinfo[0], ":");
      if (userinfo.length < 2) return;
      username = userinfo[0];
      password = userinfo[1];
    }
    const arguments_ = split(link, ":");
    if (arguments_.length < 2) return;
    server = arguments_[0];
    port = arguments_[1];
  } else if (strFind(link, "https://t.me/socks") || strFind(link, "tg://socks")) {
    server = getUrlArg(link, "server");
    port = getUrlArg(link, "port");
    username = urlDecode(getUrlArg(link, "user"));
    password = urlDecode(getUrlArg(link, "pass"));
    remarks = urlDecode(getUrlArg(link, "remarks"));
    group = urlDecode(getUrlArg(link, "group"));
  }
  if (group.length === 0) group = SOCKS_DEFAULT_GROUP;
  if (remarks.length === 0) remarks = server + ":" + port;
  if (port === "0") return;
  socksConstruct(node, group, remarks, server, port, username, password);
}

export function explodeHTTP(link: string, node: Proxy): void {
  let group = "", remarks = "", server = "", port = "", username = "", password = "";
  server = getUrlArg(link, "server");
  port = getUrlArg(link, "port");
  username = urlDecode(getUrlArg(link, "user"));
  password = urlDecode(getUrlArg(link, "pass"));
  remarks = urlDecode(getUrlArg(link, "remarks"));
  group = urlDecode(getUrlArg(link, "group"));
  if (group.length === 0) group = HTTP_DEFAULT_GROUP;
  if (remarks.length === 0) remarks = server + ":" + port;
  if (port === "0") return;
  httpConstruct(node, group, remarks, server, port, username, password, strFind(link, "/https"));
}

export function explodeHTTPSub(link0: string, node: Proxy): void {
  let link = link0;
  let group = "", remarks = "", server = "", port = "", username = "", password = "";
  let addition = "";
  const tls = strFind(link, "https://");
  const pos = link.indexOf("?");
  if (pos !== -1) {
    addition = link.substring(pos + 1);
    link = link.substring(0, pos);
    remarks = urlDecode(getUrlArg(addition, "remarks"));
    group = urlDecode(getUrlArg(addition, "group"));
  }
  link = link.substring(link.indexOf("://") + 3);
  link = urlSafeBase64Decode(link);
  if (strFind(link, "@")) {
    const m = regGetMatch(link, "(.*?):(.*?)@(.*):(.*)");
    if (!m) return;
    [, username, password, server, port] = m;
  } else {
    const m = regGetMatch(link, "(.*):(.*)");
    if (!m) return;
    [, server, port] = m;
  }
  if (group.length === 0) group = HTTP_DEFAULT_GROUP;
  if (remarks.length === 0) remarks = server + ":" + port;
  if (port === "0") return;
  httpConstruct(node, group, remarks, server, port, username, password, tls);
}

export function explodeTrojan(trojan0: string, node: Proxy): void {
  let trojan = trojan0;
  let server = "", port = "", psk = "", addition = "", group = "", remark = "", host = "", path = "", network = "", fp = "", sni = "";
  const tfo = new tribool(), scv = new tribool();
  if (startsWith(trojan, "trojan://")) trojan = trojan.substring(9);
  if (startsWith(trojan, "trojan-go://")) trojan = trojan.substring(12);
  const remarkRef = { v: remark }, trojanRef = { v: trojan };
  extractRemark(trojanRef, remarkRef);
  trojan = trojanRef.v;
  remark = remarkRef.v;
  let pos = trojan.indexOf("?");
  if (pos !== -1) {
    addition = trojan.substring(pos + 1);
    trojan = trojan.substring(0, pos);
  }
  const m = regGetMatch(trojan, "(.*?)@(.*):(.*)");
  if (!m) return;
  [, psk, server, port] = m;
  if (port === "0") return;

  host = getUrlArg(addition, "sni");
  sni = getUrlArg(addition, "sni");
  host = getUrlArg(addition, "host");
  if (host.length === 0) host = sni;
  if (host.length === 0) host = getUrlArg(addition, "peer");
  tfo.setString(getUrlArg(addition, "tfo"));
  fp = getUrlArg(addition, "fp");
  scv.setString(getUrlArg(addition, "allowInsecure"));
  group = urlDecode(getUrlArg(addition, "group"));

  if (getUrlArg(addition, "ws") === "1") {
    path = getUrlArg(addition, "wspath");
    network = "ws";
  } else if (getUrlArg(addition, "type") === "ws") {
    // v2rayN / X-ui style: trojan://{password}@{server}:{port}?type=ws&security=tls&path=...
    path = getUrlArg(addition, "path");
    if (path.substring(0, 3) === "%2F") path = urlDecode(path);
    network = "ws";
  } else if (getUrlArg(addition, "type") === "grpc") {
    path = getUrlArg(addition, "serviceName");
    network = "grpc";
  }

  if (remark.length === 0) remark = server + ":" + port;
  if (group.length === 0) group = TROJAN_DEFAULT_GROUP;
  const alpnList = getUrlAlpnList(addition);
  trojanConstruct(node, group, remark, server, port, psk, network, host, path, fp, sni, alpnList, true, new tribool(), tfo, scv);
}

export function explodeVless(vless: string, node: Proxy): void {
  if (regMatch(vless, "vless://(.*?)@(.*)")) {
    explodeStdVless(vless, node);
    return;
  }
}

export function explodeMierus(mierus: string, node: Proxy): void {
  if (strFind(mierus, "mierus://")) {
    if (regMatch(mierus, "mierus://(.*?)@(.*)")) {
      explodeStdMieru(mierus.substring(9), node);
    } else {
      mierus = urlSafeBase64Decode(mierus.substring(9));
      explodeStdMieru("mierus://" + mierus, node);
    }
  } else if (strFind(mierus, "mieru://")) {
    if (regMatch(mierus, "mierus://(.*?)@(.*)")) {
      explodeStdMieru(mierus.substring(8), node);
    } else {
      mierus = urlSafeBase64Decode(mierus.substring(8));
      explodeStdMieru("mierus://" + mierus, node);
    }
  }
}

export function explodeHysteria(hysteria0: string, node: Proxy): void {
  let hysteria = regReplace(hysteria0, "(hysteria|hy)://", "hysteria://");
  if (regMatch(hysteria, "hysteria://(.*?)[:](.*)")) {
    explodeStdHysteria(hysteria, node);
    return;
  }
}

export function explodeHysteria2(hysteria20: string, node: Proxy): void {
  let hysteria2 = regReplace(hysteria20, "(hysteria2|hy2)://", "hysteria2://");
  hysteria2 = regReplace(hysteria2, "/\\?", "?", true, false);
  if (regMatch(hysteria2, "hysteria2://(.*?)[:](.*)")) {
    explodeStdHysteria2(hysteria2, node);
    return;
  }
}

export function explodeQuan(quan: string, node: Proxy): void {
  let group = V2RAY_DEFAULT_GROUP, ps = "", add = "", port = "", cipher = "", type = "none", id = "", aid = "0", net = "tcp", path = "", host = "", edge = "", tls = "";
  const strTemp = regReplace(quan, "(.*?) = (.*)", "$1,$2");
  const configs = split(strTemp, ",");
  if (configs[1] !== "vmess") return;
  if (configs.length < 6) return;
  ps = trim(configs[0]);
  add = trim(configs[2]);
  port = trim(configs[3]);
  if (port === "0") return;
  cipher = trim(configs[4]);
  id = trim(replaceAllDistinct(configs[5], '"', ""));
  for (let i = 6; i < configs.length; i++) {
    const vArray = splitFirst(configs[i], "=");
    if (vArray.length < 2) continue;
    const itemName = trim(vArray[0]);
    const itemVal = trim(vArray[1]);
    switch (itemName) {
      case "group":
        group = itemVal;
        break;
      case "over-tls":
        tls = itemVal === "true" ? "tls" : "";
        break;
      case "tls-host":
        host = itemVal;
        break;
      case "obfs-path":
        path = replaceAllDistinct(itemVal, '"', "");
        break;
      case "obfs-header": {
        const headers = split(replaceAllDistinct(replaceAllDistinct(itemVal, '"', ""), "[Rr][Nn]", "|"), "|");
        for (const x of headers) {
          if (regFind(x, "(?i)Host: ")) host = x.substring(6);
          else if (regFind(x, "(?i)Edge: ")) edge = x.substring(6);
        }
        break;
      }
      case "obfs":
        if (itemVal === "ws") net = "ws";
        break;
      default:
        continue;
    }
  }
  if (path.length === 0) path = "/";
  vmessConstruct(node, group, ps, add, port, type, id, aid, net, cipher, path, host, edge, tls, "", []);
}

export function explodeNetch(netch0: string, node: Proxy): void {
  let netch = netch0;
  let type = "", group = "", remark = "", address = "", port = "", username = "", password = "", method = "", plugin = "", pluginopts = "";
  let protocol = "", protoparam = "", obfs = "", obfsparam = "", id = "", aid = "", transprot = "", faketype = "", host = "", edge = "", path = "", tls = "", sni = "", fp = "";
  const udp = new tribool(), tfo = new tribool(), scv = new tribool();
  netch = urlSafeBase64Decode(netch.substring(8));
  let json: Record<string, unknown>;
  try {
    const parsed = JSON.parse(netch);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
    json = parsed;
  } catch {
    return;
  }
  type = getMember(json, "Type");
  group = getMember(json, "Group");
  remark = getMember(json, "Remark");
  address = getMember(json, "Hostname");
  udp.setString(getMember(json, "EnableUDP"));
  tfo.setString(getMember(json, "EnableTFO"));
  scv.setString(getMember(json, "AllowInsecure"));
  port = getMember(json, "Port");
  fp = getMember(json, "FingerPrint");
  if (port === "0") return;
  method = getMember(json, "EncryptMethod");
  password = getMember(json, "Password");
  if (remark.length === 0) remark = address + ":" + port;
  switch (type) {
    case "SS":
      plugin = getMember(json, "Plugin");
      pluginopts = getMember(json, "PluginOption");
      if (group.length === 0) group = SS_DEFAULT_GROUP;
      ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
      break;
    case "SSR":
      protocol = getMember(json, "Protocol");
      obfs = getMember(json, "OBFS");
      if (ss_ciphers.includes(method) && (obfs.length === 0 || obfs === "plain") && (protocol.length === 0 || protocol === "origin")) {
        plugin = getMember(json, "Plugin");
        pluginopts = getMember(json, "PluginOption");
        if (group.length === 0) group = SS_DEFAULT_GROUP;
        ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
      } else {
        protoparam = getMember(json, "ProtocolParam");
        obfsparam = getMember(json, "OBFSParam");
        if (group.length === 0) group = SSR_DEFAULT_GROUP;
        ssrConstruct(node, group, remark, address, port, protocol, method, obfs, password, obfsparam, protoparam, udp, tfo, scv);
      }
      break;
    case "VMess":
      id = getMember(json, "UserID");
      aid = getMember(json, "AlterID");
      transprot = getMember(json, "TransferProtocol");
      faketype = getMember(json, "FakeType");
      host = getMember(json, "Host");
      path = getMember(json, "Path");
      edge = getMember(json, "Edge");
      tls = getMember(json, "TLSSecure");
      sni = getMember(json, "ServerName");
      if (group.length === 0) group = V2RAY_DEFAULT_GROUP;
      vmessConstruct(node, group, remark, address, port, faketype, id, aid, transprot, method, path, host, edge, tls, sni, [], udp, tfo, scv);
      break;
    case "Socks5":
      username = getMember(json, "Username");
      if (group.length === 0) group = SOCKS_DEFAULT_GROUP;
      socksConstruct(node, group, remark, address, port, username, password, udp, tfo, scv);
      break;
    case "HTTP":
    case "HTTPS":
      if (group.length === 0) group = HTTP_DEFAULT_GROUP;
      httpConstruct(node, group, remark, address, port, username, password, type === "HTTPS", tfo, scv);
      break;
    case "Trojan":
      host = getMember(json, "Host");
      path = getMember(json, "Path");
      transprot = getMember(json, "TransferProtocol");
      tls = getMember(json, "TLSSecure");
      sni = host;
      if (group.length === 0) group = TROJAN_DEFAULT_GROUP;
      trojanConstruct(node, group, remark, address, port, password, transprot, host, path, fp, sni, [], tls === "true", udp, tfo, scv);
      break;
    case "Snell":
      obfs = getMember(json, "OBFS");
      host = getMember(json, "Host");
      aid = getMember(json, "SnellVersion");
      if (group.length === 0) group = "SnellProvider";
      snellConstruct(node, group, remark, address, port, password, obfs, host, toInt(aid, 0), udp, tfo, scv);
      break;
    default:
      return;
  }
}

export function explodeStdVMess(vmess0: string, node: Proxy): void {
  let vmess = vmess0;
  let add = "", port = "", type = "", id = "", aid = "", net = "", path = "", host = "", tls = "", remarks = "";
  let addition = "";
  vmess = vmess.substring(8);
  const remarksRef = { v: remarks }, vmessRef = { v: vmess };
  extractRemark(vmessRef, remarksRef);
  vmess = vmessRef.v;
  remarks = remarksRef.v;
  const stdvmess_matcher = "^([a-z]+)(?:\\+([a-z]+))?:([\\da-f]{4}(?:[\\da-f]{4}-){4}[\\da-f]{12})-(\\d+)@(.+):(\\d+)(?:\\/?\\?(.*))?$";
  const m = regGetMatch(vmess, stdvmess_matcher);
  if (!m) return;
  [, net, tls, id, aid, add, port, addition] = m;
  switch (net) {
    case "tcp":
    case "kcp":
      type = getUrlArg(addition, "type");
      break;
    case "http":
    case "ws":
      host = getUrlArg(addition, "host");
      path = getUrlArg(addition, "path");
      break;
    case "quic":
      type = getUrlArg(addition, "security");
      host = getUrlArg(addition, "type");
      path = getUrlArg(addition, "key");
      break;
    default:
      return;
  }
  if (remarks.length === 0) remarks = add + ":" + port;
  const alpnList = getUrlAlpnList(addition);
  vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", path, host, "", tls, "", alpnList);
}

export function explodeStdHysteria(hysteria0: string, node: Proxy): void {
  let hysteria = hysteria0;
  let add = "", port = "", type = "", auth = "", host = "", insecure = "", up = "", down = "", alpn = "", obfsParam = "", remarks = "", auth_str = "", sni = "";
  let addition = "";
  hysteria = hysteria.substring(11);
  const remarksRef = { v: remarks }, hysteriaRef = { v: hysteria };
  extractRemark(hysteriaRef, remarksRef);
  hysteria = hysteriaRef.v;
  remarks = remarksRef.v;
  const m = regGetMatch(hysteria, "^(.*)[:](\\d+)[?](.*)$");
  if (!m) return;
  [, add, port, addition] = m;
  type = getUrlArg(addition, "protocol");
  auth = getUrlArg(addition, "auth");
  auth_str = getUrlArg(addition, "auth_str");
  host = getUrlArg(addition, "peer");
  insecure = getUrlArg(addition, "insecure");
  up = getUrlArg(addition, "upmbps");
  down = getUrlArg(addition, "downmbps");
  alpn = getUrlAlpn(addition);
  obfsParam = getUrlArg(addition, "obfsParam");
  sni = getUrlArg(addition, "peer");
  if (remarks.length === 0) remarks = add + ":" + port;
  hysteriaConstruct(node, HYSTERIA_DEFAULT_GROUP, remarks, add, port, type, auth, auth_str, host, up, down, alpn, obfsParam, insecure, "", sni);
}

export function explodeStdMieru(mieru0: string, node: Proxy): void {
  let mieru = mieru0;
  let username = "", password = "", host = "", port = "", ports = "", protocol = "", multiplexing = "", mtu = "", remarks = "";
  let addition = "";
  const udp = new tribool(), tfo = new tribool(), scv = new tribool(), tls13 = new tribool();

  const remarksRef = { v: remarks }, mieruRef = { v: mieru };
  extractRemark(mieruRef, remarksRef);
  mieru = mieruRef.v;
  remarks = remarksRef.v;

  const pos = mieru.lastIndexOf("?");
  if (pos !== -1) {
    addition = mieru.substring(pos + 1);
    mieru = mieru.substring(0, pos);
  }

  const m = regGetMatch(mieru, "^(.*?):(.*?)@(.*)$");
  if (!m) return;
  [, username, password, host] = m;

  port = getUrlArg(addition, "port");
  if (port.includes("-")) ports = port;
  protocol = getUrlArg(addition, "protocol");
  multiplexing = getUrlArg(addition, "multiplexing");
  mtu = getUrlArg(addition, "mtu");

  if (remarks.length === 0) remarks = host;

  mieruConstruct(node, "MieruGroup", remarks, port, password, host, ports, username, multiplexing, protocol, udp, tfo, scv, tls13, "");
  void mtu;
}

export function explodeStdHysteria2(hysteria20: string, node: Proxy): void {
  let hysteria2 = hysteria20;
  let add = "", port = "", password = "", host = "", insecure = "", up = "", down = "", alpn = "", obfsParam = "", obfsPassword = "", remarks = "", sni = "", ports = "";
  let fingerprint = "";
  let addition = "";
  const scv = new tribool();
  hysteria2 = hysteria2.substring(12);

  const remarksRef = { v: remarks }, h2Ref = { v: hysteria2 };
  extractRemark(h2Ref, remarksRef);
  hysteria2 = h2Ref.v;
  remarks = remarksRef.v;

  const pos = hysteria2.lastIndexOf("?");
  if (pos !== -1) {
    addition = hysteria2.substring(pos + 1);
    hysteria2 = hysteria2.substring(0, pos);
  }

  if (strFind(hysteria2, "@")) {
    const m = regGetMatch(hysteria2, "^(.*?)@(.*)[:](\\d+)$");
    if (!m) return;
    [, password, add, port] = m;
  } else {
    password = getUrlArg(addition, "password");
    if (password.length === 0) return;
    if (!strFind(hysteria2, ":")) return;
    const m = regGetMatch(hysteria2, "^(.*)[:](\\d+)$");
    if (!m) return;
    [, add, port] = m;
  }

  scv.setString(getUrlArg(addition, "insecure"));
  up = getUrlArg(addition, "up");
  down = getUrlArg(addition, "down");
  alpn = getUrlAlpn(addition);
  obfsParam = getUrlArg(addition, "obfs");
  obfsPassword = getUrlArg(addition, "obfs-password");
  host = getUrlArg(addition, "sni");
  sni = getUrlArg(addition, "sni");
  ports = getUrlArg(addition, "ports");
  fingerprint = getUrlArg(addition, "pinSHA256");
  if (remarks.length === 0) remarks = add + ":" + port;

  hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, remarks, add, port, password, host, up, down, alpn, obfsParam, obfsPassword, host, "", fingerprint, ports, new tribool(), new tribool(), scv);
}

export function explodeStdVless(vless0: string, node: Proxy): void {
  let vless = vless0;
  let add = "", port = "", type = "", id = "", aid = "", net = "", flow = "", pbk = "", sid = "", fp = "", mode = "", path = "", host = "", tls = "", remarks = "", sni = "", encryption = "";
  let addition = "";
  vless = vless.substring(8);

  const remarksRef = { v: remarks }, vlessRef = { v: vless };
  extractRemark(vlessRef, remarksRef);
  vless = vlessRef.v;
  remarks = remarksRef.v;

  const stdvless_matcher = "^([\\da-fA-F]{8}-[\\da-fA-F]{4}-[\\da-fA-F]{4}-[\\da-fA-F]{4}-[\\da-fA-F]{12})@\\[?([\\d\\-a-zA-Z:.]+)\\]?:(\\d+)(?:\\/?\\?(.*))?$";
  const m = regGetMatch(vless, stdvless_matcher);
  if (!m) return;
  [, id, add, port, addition] = m;

  tls = getUrlArg(addition, "security");
  net = getUrlArg(addition, "type");
  if (net.length === 0) net = "tcp";
  flow = getUrlArg(addition, "flow");
  pbk = getUrlArg(addition, "pbk");
  sid = getUrlArg(addition, "sid");
  encryption = getUrlArg(addition, "encryption");
  fp = getUrlArg(addition, "fp");
  const packet_encoding = getUrlArg(addition, "packet-encoding");
  const alpnList = getUrlAlpnList(addition);
  switch (net) {
    case "tcp":
    case "ws":
    case "h2":
      type = getUrlArg(addition, "headerType");
      host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "host");
      path = getUrlArg(addition, "path");
      break;
    case "grpc":
      host = getUrlArg(addition, "sni");
      path = getUrlArg(addition, "serviceName");
      mode = getUrlArg(addition, "mode");
      break;
    case "quic":
      type = getUrlArg(addition, "headerType");
      host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "quicSecurity");
      path = getUrlArg(addition, "key");
      break;
    case "xhttp":
      type = getUrlArg(addition, "headerType");
      host = getUrlArg(addition, strFind(addition, "sni") ? "sni" : "host");
      path = getUrlArg(addition, "path");
      readXHTTPExtraOptions(addition, node);
      for (const key of xhttp_option_keys) {
        let value = getUrlArg(addition, key);
        if (value.length === 0) value = getUrlArg(addition, replaceAllDistinct(key, "-", "_"));
        if (value.length > 0) {
          node.XHTTPOptions[key] = value;
        }
      }
      break;
    default:
      return;
  }
  if (remarks.length === 0) remarks = add + ":" + port;
  sni = getUrlArg(addition, "sni");
  vlessConstruct(node, XRAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", flow, mode, path, host, "", tls, pbk, sid, fp, sni, alpnList, packet_encoding, encryption);
}

export function explodeShadowrocket(rocket0: string, node: Proxy): void {
  let rocket = rocket0;
  let add = "", port = "", type = "", id = "", aid = "", net = "tcp", path = "", host = "", tls = "", cipher = "", remarks = "";
  let obfs = "";
  let addition = "";
  rocket = rocket.substring(8);

  const pos = rocket.indexOf("?");
  addition = pos === -1 ? "" : rocket.substring(pos + 1);
  rocket = pos === -1 ? rocket : rocket.substring(0, pos);

  const m = regGetMatch(urlSafeBase64Decode(rocket), "(.*?):(.*)@(.*):(.*)");
  if (!m) return;
  [, cipher, id, add, port] = m;
  if (port === "0") return;
  remarks = urlDecode(getUrlArg(addition, "remarks"));
  obfs = getUrlArg(addition, "obfs");
  if (obfs.length > 0) {
    if (obfs === "websocket") {
      net = "ws";
      host = getUrlArg(addition, "obfsParam");
      path = getUrlArg(addition, "path");
    }
  } else {
    net = getUrlArg(addition, "network");
    host = getUrlArg(addition, "wsHost");
    path = getUrlArg(addition, "wspath");
  }
  tls = getUrlArg(addition, "tls") === "1" ? "tls" : "";
  aid = getUrlArg(addition, "aid");
  if (aid.length === 0) aid = "0";
  if (remarks.length === 0) remarks = add + ":" + port;
  const alpnList = getUrlAlpnList(addition);
  vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "", alpnList);
}

export function explodeKitsunebi(kit0: string, node: Proxy): void {
  let kit = kit0;
  let add = "", port = "", type = "", id = "", aid = "0", net = "tcp", path = "", host = "", tls = "", cipher = "auto", remarks = "";
  let addition = "";
  kit = kit.substring(9);

  let pos = kit.indexOf("#");
  if (pos !== -1) {
    remarks = kit.substring(pos + 1);
    kit = kit.substring(0, pos);
  }
  pos = kit.indexOf("?");
  addition = pos === -1 ? "" : kit.substring(pos + 1);
  kit = pos === -1 ? kit : kit.substring(0, pos);

  const m = regGetMatch(kit, "(.*?)@(.*):(.*)");
  if (!m) return;
  [, id, add, port] = m;
  pos = port.indexOf("/");
  if (pos !== -1) {
    path = port.substring(pos);
    port = port.substring(0, pos);
  }
  if (port === "0") return;
  net = getUrlArg(addition, "network");
  tls = getUrlArg(addition, "tls") === "true" ? "tls" : "";
  host = getUrlArg(addition, "ws.host");
  if (remarks.length === 0) remarks = add + ":" + port;
  const alpnList = getUrlAlpnList(addition);
  vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "", alpnList);
}

export function explodeTuic(tuic0: string, node: Proxy): void {
  let link = tuic0.substring(7);
  let add = "", port = "", password = "", alpn = "", remarks = "", sni = "", congestion_control = "";
  let addition = "";
  const scv = new tribool();

  const remarksRef = { v: remarks }, linkRef = { v: link };
  extractRemark(linkRef, remarksRef);
  link = linkRef.v;
  remarks = remarksRef.v;

  let pos = link.lastIndexOf("?");
  if (pos !== -1) {
    addition = link.substring(pos + 1);
    link = link.substring(0, pos);
  }

  let uuid = "";
  pos = link.indexOf(":");
  if (pos !== -1) {
    uuid = link.substring(0, pos);
    link = link.substring(pos + 1);
    if (strFind(link, "@")) {
      pos = link.indexOf("@");
      if (pos !== -1) {
        password = link.substring(0, pos);
        link = link.substring(pos + 1);
      }
    }
  }

  pos = link.lastIndexOf(":");
  if (pos !== -1) {
    add = link.substring(0, pos);
    link = link.substring(pos + 1);
    pos = link.indexOf("?");
    if (pos !== -1) {
      port = link.substring(0, pos);
      addition = link.substring(pos + 1);
    } else {
      port = link;
    }
  }

  if (add.length > 2 && add.startsWith("[") && add.endsWith("]")) add = add.substring(1, add.length - 1);

  scv.setString(getUrlArg(addition, "insecure"));
  alpn = getUrlAlpn(addition);
  sni = getUrlArg(addition, "sni");
  congestion_control = getUrlArg(addition, "congestion_control");
  if (remarks.length === 0) remarks = add + ":" + port;
  tuicConstruct(node, TUIC_DEFAULT_GROUP, remarks, add, port, password, congestion_control, alpn, sni, uuid, "native", "", new tribool(), new tribool(), scv);
}

export function explodeAnyTLS(anytls0: string, node: Proxy): void {
  let anytls = anytls0.substring(9);
  let add = "", port = "", password = "", remarks = "", addition = "", sni = "", fp = "";
  let alpnList: string[] = [];
  const udp = new tribool(), tfo = new tribool(), scv = new tribool();

  const remarksRef = { v: remarks }, anytlsRef = { v: anytls };
  extractRemark(anytlsRef, remarksRef);
  anytls = anytlsRef.v;
  remarks = remarksRef.v;

  let pos = anytls.lastIndexOf("?");
  if (pos !== -1) {
    addition = anytls.substring(pos + 1);
    anytls = anytls.substring(0, pos);
  }

  pos = anytls.indexOf("@");
  if (pos !== -1) {
    password = anytls.substring(0, pos);
    anytls = anytls.substring(pos + 1);
  }

  pos = anytls.lastIndexOf(":");
  if (pos !== -1) {
    add = anytls.substring(0, pos);
    port = anytls.substring(pos + 1);
  }

  if (add.length > 2 && add.startsWith("[") && add.endsWith("]")) add = add.substring(1, add.length - 1);

  if (remarks.length === 0) remarks = add + ":" + port;

  alpnList = getUrlAlpnList(addition);

  fp = getUrlArg(addition, "fp");
  if (fp.length === 0) fp = getUrlArg(addition, "fingerprint");
  if (fp.length === 0) fp = urlDecode(getUrlArg(addition, "hpkp"));
  sni = getUrlArg(addition, "sni");
  if (sni.length === 0) sni = getUrlArg(addition, "peer");
  udp.setString(getUrlArg(addition, "udp"));
  tfo.setString(getUrlArg(addition, "tfo"));
  scv.setString(getUrlArg(addition, "insecure"));

  anyTlSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, port, password, add, alpnList, fp, sni, udp, tfo, scv, new tribool(), "", 30, 30, 0);
}
