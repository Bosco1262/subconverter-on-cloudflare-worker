// Port of src/parser/subparser.cpp — JSON/SSD/SS config-file parsers (explodeSSD, explodeSSAndroid,
// explodeSSConf, explodeSSRConf, explodeVmessConf, explodeSSTap, explodeNetchConf, explodeConfContent)

import { urlSafeBase64Decode } from "../../lib/base64";
import { replaceAllDistinct, toInt } from "../../lib/string";
import { regGetMatch } from "../../lib/regex";
import { Proxy, ProxyType, SS_DEFAULT_GROUP, SSR_DEFAULT_GROUP, V2RAY_DEFAULT_GROUP, SOCKS_DEFAULT_GROUP, newProxy } from "../proxy";
import { getMember, jsonToString, ss_ciphers, ssConstruct, ssrConstruct, socksConstruct, vmessConstruct } from "./util";
import { explodeNetch } from "./link";
import { base64Encode } from "../../lib/base64";
import { explodeSub } from "./index";

function asObject(parsed: unknown): Record<string, unknown> | null {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

function parseJson(content: string): Record<string, unknown> | null {
  try {
    return asObject(JSON.parse(content));
  } catch {
    return null;
  }
}

export function explodeSSD(link0: string, nodes: Proxy[]): void {
  let link = link0;
  let group = "", port = "", method = "", password = "", server = "", remarks = "";
  let plugin = "", pluginopts = "";
  let index = nodes.length;

  link = urlSafeBase64Decode(link.substring(6));
  const jsondata = parseJson(link);
  if (!jsondata) return;
  if (!("servers" in jsondata)) return;
  const airport = getMember(jsondata, "airport");
  if (airport) group = airport;

  let listType = 0;
  let serverNodes: unknown[];
  const serversVal = jsondata["servers"];
  if (Array.isArray(serversVal)) {
    listType = 0;
    serverNodes = serversVal;
  } else if (serversVal && typeof serversVal === "object") {
    listType = 1;
    serverNodes = Object.entries(serversVal as Record<string, unknown>).map(([k, v]) => ({ __key: k, __value: v }));
  } else return;

  for (let i = 0; i < serverNodes.length; i++) {
    port = getMember(jsondata, "port");
    method = getMember(jsondata, "encryption");
    password = getMember(jsondata, "password");
    plugin = getMember(jsondata, "plugin");
    pluginopts = getMember(jsondata, "plugin_options");

    let singlenode: unknown;
    if (listType === 0) singlenode = serverNodes[i];
    else singlenode = (serverNodes[i] as Record<string, unknown>)["__value"];
    const sn = asObject(singlenode);
    if (!sn) continue;
    {
      // upstream is `singlenode["server"] >> server;` (yamlcpp_extra.h:8-12): assign only when the
      // member is defined and non-null, so an entry WITHOUT "server" keeps the previous entry's
      // value. Every sibling field below already emulates that "keep previous" rule.
      const s = getMember(sn, "server");
      if (s) server = s;
    }
    {
      const r = getMember(sn, "remarks");
      if (r) remarks = r;
    }
    {
      const p = getMember(sn, "port");
      if (p) port = p;
    }
    {
      const p = getMember(sn, "encryption");
      if (p) method = p;
    }
    {
      const p = getMember(sn, "password");
      if (p) password = p;
    }
    {
      const p = getMember(sn, "plugin");
      if (p) plugin = p;
    }
    {
      const p = getMember(sn, "plugin_options");
      if (p) pluginopts = p;
    }

    if (port === "0") continue;

    const node = newProxy();
    ssConstruct(node, group, remarks, server, port, password, method, plugin, pluginopts);
    node.Id = index;
    nodes.push(node);
    index++;
  }
}

export function explodeSSAndroid(ss0: string, nodes: Proxy[]): void {
  let ss = ss0;
  let ps = "", password = "", method = "", server = "", port = "", group = SS_DEFAULT_GROUP;
  let plugin = "", pluginopts = "";
  let index = nodes.length;

  ss = '{"nodes":' + ss + "}";
  const json = parseJson(ss);
  if (!json) return;
  const nodesArr = json["nodes"];
  if (!Array.isArray(nodesArr)) return;

  for (const itemUnknown of nodesArr) {
    const item = asObject(itemUnknown);
    if (!item) continue;
    const node = newProxy();
    server = getMember(item, "server");
    if (server.length === 0) continue;
    ps = getMember(item, "remarks");
    port = getMember(item, "server_port");
    if (port === "0") continue;
    if (ps.length === 0) ps = server + ":" + port;
    password = getMember(item, "password");
    method = getMember(item, "method");
    plugin = getMember(item, "plugin");
    pluginopts = getMember(item, "plugin_opts");
    ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
    node.Id = index;
    nodes.push(node);
    index++;
  }
}

export function explodeSSConf(content: string, nodes: Proxy[]): void {
  let ps = "", password = "", method = "", server = "", port = "", plugin = "", pluginopts = "", group = SS_DEFAULT_GROUP;
  let index = nodes.length;

  const json = parseJson(content);
  if (!json) return;
  const section = "version" in json && "servers" in json ? "servers" : "configs";
  if (!(section in json)) return;
  const remarks0 = getMember(json, "remarks");
  if (remarks0) group = remarks0;
  const arr = json[section];
  if (!Array.isArray(arr)) return;

  for (const itemUnknown of arr) {
    const item = asObject(itemUnknown);
    if (!item) continue;
    const node = newProxy();
    ps = getMember(item, "remarks");
    port = getMember(item, "server_port");
    if (port === "0") continue;
    if (ps.length === 0) ps = server + ":" + port;
    password = getMember(item, "password");
    method = getMember(item, "method");
    server = getMember(item, "server");
    plugin = getMember(item, "plugin");
    pluginopts = getMember(item, "plugin_opts");
    node.Id = index;
    ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
    nodes.push(node);
    index++;
  }
}

export function explodeSSRConf(content: string, nodes: Proxy[]): void {
  let remarks = "", group = "", server = "", port = "", method = "", password = "", protocol = "", protoparam = "", obfs = "", obfsparam = "", plugin = "", pluginopts = "";
  let index = nodes.length;

  const json = parseJson(content);
  if (!json) return;

  if ("local_port" in json && "local_address" in json) {
    // single libev config
    const node = newProxy();
    server = getMember(json, "server");
    port = getMember(json, "server_port");
    remarks = server + ":" + port;
    method = getMember(json, "method");
    obfs = getMember(json, "obfs");
    protocol = getMember(json, "protocol");
    if (ss_ciphers.includes(method) && (obfs.length === 0 || obfs === "plain") && (protocol.length === 0 || protocol === "origin")) {
      plugin = getMember(json, "plugin");
      pluginopts = getMember(json, "plugin_opts");
      ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts);
    } else {
      protoparam = getMember(json, "protocol_param");
      obfsparam = getMember(json, "obfs_param");
      ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
    }
    nodes.push(node);
    return;
  }

  const arr = json["configs"];
  if (!Array.isArray(arr)) return;
  for (const itemUnknown of arr) {
    const item = asObject(itemUnknown);
    if (!item) continue;
    const node = newProxy();
    group = getMember(item, "group");
    if (group.length === 0) group = SSR_DEFAULT_GROUP;
    remarks = getMember(item, "remarks");
    server = getMember(item, "server");
    port = getMember(item, "server_port");
    if (port === "0") continue;
    if (remarks.length === 0) remarks = server + ":" + port;
    password = getMember(item, "password");
    method = getMember(item, "method");
    protocol = getMember(item, "protocol");
    protoparam = getMember(item, "protocolparam");
    obfs = getMember(item, "obfs");
    obfsparam = getMember(item, "obfsparam");
    ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
    node.Id = index;
    nodes.push(node);
    index++;
  }
}

export function explodeVmessConf(content: string, nodes: Proxy[]): void {
  let group = "", ps = "", add = "", port = "", type = "", id = "", aid = "", net = "", path = "", host = "", edge = "", tls = "", cipher = "", subid = "", sni = "";
  let index = nodes.length;
  const subdata = new Map<string, string>();

  const json = parseJson(content);
  if (!json) return;

  if ("outbounds" in json) {
    // single config
    const outbounds = json["outbounds"];
    if (Array.isArray(outbounds) && outbounds.length > 0) {
      const ob = asObject(outbounds[0]);
      const settings = ob ? asObject(ob["settings"]) : null;
      const vnext = settings && Array.isArray(settings["vnext"]) ? (settings["vnext"] as unknown[]) : null;
      if (ob && vnext && vnext.length > 0) {
        const node = newProxy();
        const v0 = asObject(vnext[0]);
        if (!v0) return;
        add = getMember(v0, "address");
        port = getMember(v0, "port");
        if (port === "0") return;
        const users = Array.isArray(v0["users"]) ? (v0["users"] as unknown[]) : [];
        const u0 = users.length > 0 ? asObject(users[0]) : null;
        if (u0) {
          id = getMember(u0, "id");
          aid = getMember(u0, "alterId");
          cipher = getMember(u0, "security");
        }
        const streamset = "streamSettings" in ob ? asObject(ob["streamSettings"]) : null;
        if (streamset) {
          net = getMember(streamset, "network");
          tls = getMember(streamset, "security");
          if (net === "ws") {
            const wsset = "wsSettings" in streamset ? asObject(streamset["wsSettings"]) : null;
            if (wsset) {
              path = getMember(wsset, "path");
              const headers = asObject(wsset["headers"]);
              if (headers) {
                host = getMember(headers, "Host");
                edge = getMember(headers, "Edge");
              }
            }
          }
          const tcpset = "tcpSettings" in streamset ? asObject(streamset["tcpSettings"]) : null;
          if (tcpset) {
            const header = asObject(tcpset["header"]);
            if (header) {
              type = getMember(header, "type");
              if (type === "http") {
                const request = asObject(header["request"]);
                if (request) {
                  const reqPath = request["path"];
                  if (Array.isArray(reqPath) && reqPath.length > 0) path = jsonToString(reqPath[0]);
                  const reqHeaders = asObject(request["headers"]);
                  if (reqHeaders) {
                    host = getMember(reqHeaders, "Host");
                    edge = getMember(reqHeaders, "Edge");
                  }
                }
              }
            }
          }
        }
        vmessConstruct(node, V2RAY_DEFAULT_GROUP, add + ":" + port, add, port, type, id, aid, net, cipher, path, host, edge, tls, "", []);
        nodes.push(node);
      }
    }
    return;
  }

  // read all subscribe remark as group name
  const subItem = json["subItem"];
  if (Array.isArray(subItem)) {
    for (const itemUnknown of subItem) {
      const item = asObject(itemUnknown);
      if (!item) continue;
      const sid = jsonToString(item["id"]);
      const sremarks = jsonToString(item["remarks"]);
      subdata.set(sid, sremarks);
    }
  }

  const vmessArr = json["vmess"];
  if (!Array.isArray(vmessArr)) return;
  for (const itemUnknown of vmessArr) {
    const item = asObject(itemUnknown);
    if (!item) continue;
    const node = newProxy();
    // Upstream skips an entry whose address/port/id is null (subparser.cpp:596-598: `IsNull()`).
    // In JS a MISSING key is `undefined`, so `=== null` never fired and the entry produced a node
    // with an empty hostname and port 0. `== null` covers both null and undefined.
    if (item["address"] == null || item["port"] == null || item["id"] == null) continue;

    ps = jsonToString(item["remarks"]);
    add = jsonToString(item["address"]);
    port = getMember(item, "port");
    if (port === "0") continue;
    subid = jsonToString(item["subid"]);
    if (subid.length > 0) {
      const g = subdata.get(subid);
      if (g !== undefined) group = g;
    }
    if (ps.length === 0) ps = add + ":" + port;

    {
      const scv = getMember(item, "allowInsecure");
      if (scv) node.AllowInsecure.setString(scv);
    }
    const configType = jsonToString(item["configType"]);
    switch (toInt(configType, 0)) {
      case 1: {
        // vmess config
        type = jsonToString(item["headerType"]);
        id = jsonToString(item["id"]);
        aid = jsonToString(item["alterId"]);
        net = jsonToString(item["network"]);
        path = jsonToString(item["path"]);
        host = jsonToString(item["requestHost"]);
        tls = jsonToString(item["streamSecurity"]);
        cipher = jsonToString(item["security"]);
        sni = jsonToString(item["sni"]);
        vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, cipher, path, host, "", tls, sni, []);
        break;
      }
      case 3: {
        // ss config
        id = jsonToString(item["id"]);
        cipher = jsonToString(item["security"]);
        ssConstruct(node, SS_DEFAULT_GROUP, ps, add, port, id, cipher, "", "");
        break;
      }
      case 4: {
        // socks config
        socksConstruct(node, SOCKS_DEFAULT_GROUP, ps, add, port, "", "");
        break;
      }
      default:
        continue;
    }
    node.Id = index;
    nodes.push(node);
    index++;
  }
}

export function explodeSSTap(sstap: string, nodes: Proxy[]): void {
  let group = "", remarks = "", server = "", port = "", cipher = "", user = "", pass = "", protocol = "", protoparam = "", obfs = "", obfsparam = "";
  let index = nodes.length;
  const json = parseJson(sstap);
  if (!json) return;
  const arr = json["configs"];
  if (!Array.isArray(arr)) return;

  for (const itemUnknown of arr) {
    const item = asObject(itemUnknown);
    if (!item) continue;
    const node = newProxy();
    group = jsonToString(item["group"]);
    remarks = jsonToString(item["remarks"]);
    server = jsonToString(item["server"]);
    port = getMember(item, "server_port");
    if (port === "0") continue;
    if (remarks.length === 0) remarks = server + ":" + port;
    pass = jsonToString(item["password"]);
    const configType = jsonToString(item["type"]);
    switch (toInt(configType, 0)) {
      case 5: {
        // socks 5
        user = jsonToString(item["username"]);
        socksConstruct(node, group, remarks, server, port, user, pass);
        break;
      }
      case 6: {
        // ss/ssr
        protocol = jsonToString(item["protocol"]);
        obfs = jsonToString(item["obfs"]);
        cipher = jsonToString(item["method"]);
        if (ss_ciphers.includes(cipher) && protocol === "origin" && obfs === "plain") {
          ssConstruct(node, group, remarks, server, port, pass, cipher, "", "");
        } else {
          obfsparam = jsonToString(item["obfsparam"]);
          protoparam = jsonToString(item["protocolparam"]);
          ssrConstruct(node, group, remarks, server, port, protocol, cipher, obfs, pass, obfsparam, protoparam);
        }
        break;
      }
      default:
        continue;
    }
    node.Id = index;
    nodes.push(node);
    index++;
  }
}

export function explodeNetchConf(netch: string, nodes: Proxy[]): void {
  let index = nodes.length;
  const json = parseJson(netch);
  if (!json) return;
  if (!("Server" in json)) return;
  const arr = json["Server"];
  if (!Array.isArray(arr)) return;

  for (const item of arr) {
    const node = newProxy();
    explodeNetch("Netch://" + base64Encode(JSON.stringify(item)), node);
    node.Id = index;
    nodes.push(node);
    index++;
  }
}

export function explodeConfContent(content: string, nodes: Proxy[]): number {
  let filetype = "Unknow";

  if (content.includes('"version"')) filetype = "SS";
  else if (content.includes('"serverSubscribes"')) filetype = "SSR";
  else if (content.includes('"uiItem"') || content.includes("vnext")) filetype = "V2Ray";
  else if (content.includes('"proxy_apps"')) filetype = "SSConf";
  else if (content.includes('"idInUse"')) filetype = "SSTap";
  else if (content.includes('"local_address"') && content.includes('"local_port"')) filetype = "SSR";
  else if (content.includes('"ModeFileNameType"')) filetype = "Netch";

  switch (filetype) {
    case "SS":
      explodeSSConf(content, nodes);
      break;
    case "SSR":
      explodeSSRConf(content, nodes);
      break;
    case "V2Ray":
      explodeVmessConf(content, nodes);
      break;
    case "SSConf":
      explodeSSAndroid(content, nodes);
      break;
    case "SSTap":
      explodeSSTap(content, nodes);
      break;
    case "Netch":
      explodeNetchConf(content, nodes);
      break;
    default:
      // try to parse as a local subscription
      explodeSub(content, nodes);
  }

  return nodes.length > 0 ? 1 : 0;
}
