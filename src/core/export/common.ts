// Port of src/generator/config/subexport.cpp — shared helpers (lines 1-251, 851-951)

import { Proxy, ProxyType } from "../proxy";
import { split, startsWith, toInt, randomStr } from "../../lib/string";
import { regFind, regGetMatch, regMatch, regReplace } from "../../lib/regex";
import { tribool } from "../../lib/tribool";
import type { extra_settings } from "../extra";

export const clashr_protocols = [
  "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a",
  "auth_chain_b",
];
export const clashr_obfs = [
  "plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth",
  "tls1.2_ticket_fastauth",
];
export const clash_ssr_ciphers = [
  "rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
  "aes-192-cfb", "aes-256-cfb", "chacha20-ietf", "xchacha20", "none",
];

export function isNumeric(str: string): boolean {
  if (str.length === 0) return false;
  for (const c of str) {
    if (c < "0" || c > "9") return false;
  }
  return true;
}

export function isIntegerString(str: string): boolean {
  if (str.length === 0) return false;
  const start = str[0] === "-" ? 1 : 0;
  if (start === str.length) return false;
  for (let i = start; i < str.length; i++) {
    if (str[i] < "0" || str[i] > "9") return false;
  }
  return true;
}

// YAML scalar value with yaml-cpp SetTag("str") semantics for digit-only strings
export function yamlScalarFromString(value: string): string | number | boolean | ScalarStr {
  if (value === "true") return true;
  if (value === "false") return false;
  if (isIntegerString(value)) return toInt(value);
  return value;
}

// marker class: string that must be emitted with an explicit string tag (quoted) in YAML
export class ScalarStr {
  constructor(public value: string) {}
}

export function vmessLinkConstruct(
  remarks: string, add: string, port: string, type: string, id: string, aid: string, net: string,
  path: string, host: string, tls: string,
): string {
  return JSON.stringify({
    v: "2",
    ps: remarks,
    add: add,
    port: port,
    type: type.length === 0 ? "none" : type,
    id: id,
    aid: aid,
    net: net.length === 0 ? "tcp" : net,
    path: path,
    host: host,
    tls: tls,
  });
}

export function matchRange(range: string, target: number): boolean {
  const vArray = split(range, ",");
  let match = false;
  const reg_num = "-?\\d+", reg_range = "(\\d+)-(\\d+)", reg_not = "\\!-?(\\d+)";
  const reg_not_range = "\\!(\\d+)-(\\d+)", reg_less = "(\\d+)-", reg_more = "(\\d+)\\+";
  for (const x of vArray) {
    if (regMatch(x, reg_num)) {
      if (toInt(x, 2147483647) === target) match = true;
    } else if (regMatch(x, reg_range)) {
      const m = regGetMatch(x, reg_range);
      const range_begin = m && m.length > 1 ? toInt(m[1], 2147483647) : 2147483647;
      const range_end = m && m.length > 2 ? toInt(m[2], -2147483648) : -2147483648;
      if (target >= range_begin && target <= range_end) match = true;
    } else if (regMatch(x, reg_not)) {
      match = true;
      if (toInt(regReplace(x, reg_not, "$1"), 2147483647) === target) match = false;
    } else if (regMatch(x, reg_not_range)) {
      match = true;
      const m = regGetMatch(x, reg_range);
      const range_begin = m && m.length > 1 ? toInt(m[1], 2147483647) : 2147483647;
      const range_end = m && m.length > 2 ? toInt(m[2], -2147483648) : -2147483648;
      if (target >= range_begin && target <= range_end) match = false;
    } else if (regMatch(x, reg_less)) {
      if (toInt(regReplace(x, reg_less, "$1"), 2147483647) >= target) match = true;
    } else if (regMatch(x, reg_more)) {
      if (toInt(regReplace(x, reg_more, "$1"), -2147483648) <= target) match = true;
    }
  }
  return match;
}

const PROXY_TYPE_NAMES: Partial<Record<ProxyType, string>> = {
  [ProxyType.Shadowsocks]: "SS",
  [ProxyType.ShadowsocksR]: "SSR",
  [ProxyType.VMess]: "VMESS",
  [ProxyType.Trojan]: "TROJAN",
  [ProxyType.Snell]: "SNELL",
  [ProxyType.HTTP]: "HTTP",
  [ProxyType.HTTPS]: "HTTPS",
  [ProxyType.SOCKS5]: "SOCKS5",
  [ProxyType.WireGuard]: "WIREGUARD",
  [ProxyType.VLESS]: "VLESS",
  [ProxyType.Hysteria]: "HYSTERIA",
  [ProxyType.Hysteria2]: "HYSTERIA2",
};

export function applyMatcher(rule: string, realRule: { v: string }, node: Proxy): boolean {
  let target = "";
  const groupid_regex = "^!!(?:GROUPID|INSERT)=([\\d\\-+!,]+)(?:!!(.*))?$";
  const group_regex = "^!!(?:GROUP)=(.+?)(?:!!(.*))?$";
  const type_regex = "^!!(?:TYPE)=(.+?)(?:!!(.*))?$";
  const port_regex = "^!!(?:PORT)=(.+?)(?:!!(.*))?$";
  const server_regex = "^!!(?:SERVER)=(.+?)(?:!!(.*))?$";
  if (startsWith(rule, "!!GROUP=")) {
    const m = regGetMatch(rule, group_regex);
    if (m) {
      target = m.length > 1 ? m[1] : "";
      realRule.v = m.length > 2 && m[2] !== undefined ? m[2] : "";
    }
    return regFind(node.Group, target);
  } else if (startsWith(rule, "!!GROUPID=") || startsWith(rule, "!!INSERT=")) {
    const dir = startsWith(rule, "!!INSERT=") ? -1 : 1;
    const m = regGetMatch(rule, groupid_regex);
    if (m) {
      target = m.length > 1 ? m[1] : "";
      realRule.v = m.length > 2 && m[2] !== undefined ? m[2] : "";
    }
    return matchRange(target, dir * node.GroupId);
  } else if (startsWith(rule, "!!TYPE=")) {
    const m = regGetMatch(rule, type_regex);
    if (m) {
      target = m.length > 1 ? m[1] : "";
      realRule.v = m.length > 2 && m[2] !== undefined ? m[2] : "";
    }
    if (node.Type === ProxyType.Unknown) return false;
    const tname = PROXY_TYPE_NAMES[node.Type];
    return tname !== undefined && regMatch(tname, target);
  } else if (startsWith(rule, "!!PORT=")) {
    const m = regGetMatch(rule, port_regex);
    if (m) {
      target = m.length > 1 ? m[1] : "";
      realRule.v = m.length > 2 && m[2] !== undefined ? m[2] : "";
    }
    return matchRange(target, node.Port);
  } else if (startsWith(rule, "!!SERVER=")) {
    const m = regGetMatch(rule, server_regex);
    if (m) {
      target = m.length > 1 ? m[1] : "";
      realRule.v = m.length > 2 && m[2] !== undefined ? m[2] : "";
    }
    return regFind(node.Hostname, target);
  } else realRule.v = rule;
  return true;
}

export function processRemark(remarkRef: { v: string }, remarksList: string[], procComma = true): void {
  // Replace '=' with '-' to avoid client parse errors
  let remark = remarkRef.v.split("=").join("-");
  if (procComma) {
    if (remark.includes(",")) {
      remark = '"' + remark + '"';
    }
  }
  const tempRemark = remark;
  let cnt = 2;
  let candidate = remark;
  while (remarksList.includes(candidate)) {
    candidate = tempRemark + " " + cnt;
    cnt++;
  }
  remarkRef.v = candidate;
}

export function groupGenerate(
  rule: string, nodelist: Proxy[], filteredNodelist: string[], addDirect: boolean, ext: extra_settings,
): void {
  const realRuleRef = { v: "" };
  if (startsWith(rule, "[]") && addDirect) {
    filteredNodelist.push(rule.substring(2));
  } else {
    // script: rules dropped (NO_JS_RUNTIME)
    for (const x of nodelist) {
      if (
        applyMatcher(rule, realRuleRef, x) &&
        (realRuleRef.v.length === 0 || regFind(x.Remark, realRuleRef.v)) &&
        !filteredNodelist.includes(x.Remark)
      )
        filteredNodelist.push(x.Remark);
    }
  }
}

export function generatePeer(node: Proxy, clientIdAsReserved = false): string {
  let result = "";
  result += "public-key = " + node.PublicKey;
  result += ", endpoint = " + node.Hostname + ":" + node.Port;
  if (node.AllowedIPs.length > 0) result += ', allowed-ips = "' + node.AllowedIPs + '"';
  if (node.ClientId.length > 0) {
    if (clientIdAsReserved) result += ", reserved = [" + node.ClientId + "]";
    else result += ", client-id = " + node.ClientId;
  }
  return result;
}

export function replaceAll(input: string, search: string, replace: string): string {
  return input.split(search).join(replace);
}

export function formatterShortId(input: string): string {
  let output = input;
  const target = "short-id:";
  let startPos = output.indexOf(target);
  while (startPos !== -1) {
    const endPos = output.indexOf("}", startPos);
    if (endPos !== -1) {
      let originalId = output.substring(startPos + target.length, endPos);
      originalId = originalId.replace(/\s/g, "");
      const modifiedId = ' "' + originalId + '" ';
      output = output.substring(0, startPos + target.length) + modifiedId + output.substring(endPos);
    }
    startPos = output.indexOf(target, startPos + 1);
  }
  return output;
}

export function makeWGSectionName(): string {
  return randomStr(5);
}
