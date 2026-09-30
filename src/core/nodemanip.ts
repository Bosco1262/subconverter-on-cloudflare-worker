// Port of src/generator/config/nodemanip.cpp

import { Proxy, ProxyType, newProxy } from "./proxy";
import { split, replaceAllDistinct, startsWith, trim } from "../lib/string";
import { regFind, regReplace, regTrim, regValid } from "../lib/regex";
import { urlDecode } from "../lib/urlencode";
import { getUrlArg } from "../lib/string";
import { webGet } from "../lib/fetch";
import { fileExist, fileGet } from "../lib/vfs";
import { global } from "./settings";
import type { extra_settings } from "./extra";
import { explode, explodeSub } from "./parser";
import { explodeConfContent } from "./parser/conf";
import { getSubInfoFromHeader, getSubInfoFromNodes, getSubInfoFromSSD, type RegexMatchConfigs } from "./info";
import { applyMatcher } from "./export/common";
import { isLink } from "./parser/util";

export interface parse_settings {
  proxy: string;
  exclude_remarks: string[];
  include_remarks: string[];
  stream_rules: RegexMatchConfigs;
  time_rules: RegexMatchConfigs;
  sub_info: string;
  authorized: boolean;
  request_header: Record<string, string> | Map<string, string>;
}

export function explodeConf(filepath: string, nodes: Proxy[]): number {
  return explodeConfContent(fileGet(filepath), nodes);
}

export async function addNodes(
  link0: string, allNodes: Proxy[], groupID: number, parseSet: parse_settings,
): Promise<number> {
  let link = replaceAllDistinct(link0, '"', "");
  const customGroupRef = { v: "" };
  let nodes: Proxy[] = [];
  const node = newProxy();
  let strSub = "";

  // tag:group_name,link
  if (startsWith(link, "tag:")) {
    const pos = link.indexOf(",");
    if (pos !== -1) {
      customGroupRef.v = link.substring(4, pos);
      link = link.substring(pos + 1);
    }
  }

  if (link === "nullnode") {
    const placeholder = newProxy();
    placeholder.GroupId = 0;
    allNodes.push(placeholder);
    return 0;
  }

  let linkType = "Unknow";
  if (startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks")) linkType = "SOCKS";
  else if (startsWith(link, "https://t.me/http") || startsWith(link, "tg://http")) linkType = "HTTP";
  else if (isLink(link) || startsWith(link, "surge:///install-config")) linkType = "SUB";
  else if (startsWith(link, "Netch://")) linkType = "Netch";
  else if (fileExist(link)) linkType = "Local";

  switch (linkType) {
    case "SUB": {
      if (startsWith(link, "surge:///install-config")) link = urlDecode(getUrlArg(link, "url"));
      const respHeaders: { v: [string, string][] } = { v: [] };
      strSub = await webGet(link, {
        proxy: parseSet.proxy,
        cacheTTL: global.enableCache ? global.cacheSubscription : 0,
        requestHeaders: parseSet.request_header,
        maxResponseSize: global.maxAllowedDownloadSize > 0 ? global.maxAllowedDownloadSize : undefined,
        respHeadersOut: respHeaders,
      });
      if (strSub.length > 0) {
        if (explodeConfContent(strSub, nodes) === 0) {
          console.error("Invalid subscription: '" + link + "'!");
          return -1;
        }
        if (startsWith(strSub, "ssd://")) {
          const info = getSubInfoFromSSD(strSub);
          if (info) parseSet.sub_info = info;
        } else {
          let info = getSubInfoFromHeader(headersToString(respHeaders.v));
          if (!info) info = getSubInfoFromNodes(nodes, parseSet.stream_rules, parseSet.time_rules);
          if (info) parseSet.sub_info = info;
        }
        filterNodes(nodes, parseSet.exclude_remarks, parseSet.include_remarks, groupID);
        for (const x of nodes) {
          x.GroupId = groupID;
          if (customGroupRef.v.length > 0) x.Group = customGroupRef.v;
        }
        allNodes.push(...nodes);
      } else {
        console.error("Cannot download subscription data.");
        return -1;
      }
      break;
    }
    case "Local": {
      if (!parseSet.authorized) return -1;
      if (explodeConf(link, nodes) === 0) {
        console.error("Invalid configuration file!");
        return -1;
      }
      if (startsWith(strSub, "ssd://")) {
        const info = getSubInfoFromSSD(strSub);
        if (info) parseSet.sub_info = info;
      } else {
        const info = getSubInfoFromNodes(nodes, parseSet.stream_rules, parseSet.time_rules);
        if (info) parseSet.sub_info = info;
      }
      filterNodes(nodes, parseSet.exclude_remarks, parseSet.include_remarks, groupID);
      for (const x of nodes) {
        x.GroupId = groupID;
        if (customGroupRef.v.length > 0) x.Group = customGroupRef.v;
      }
      allNodes.push(...nodes);
      break;
    }
    default: {
      explode(link, node);
      if (node.Type === ProxyType.Unknown) {
        console.error("No valid link found.");
        return -1;
      }
      node.GroupId = groupID;
      if (customGroupRef.v.length > 0) node.Group = customGroupRef.v;
      allNodes.push(node);
    }
  }
  return 0;
}

function headersToString(headers: [string, string][]): string {
  return headers.map(([k, v]) => k + ": " + v).join("\r\n");
}

function chkIgnore(node: Proxy, excludeRemarks: string[], includeRemarks: string[]): boolean {
  const realRule = { v: "" };
  const excluded = excludeRemarks.some((x) => {
    if (applyMatcher(x, realRule, node)) {
      if (realRule.v.length === 0) return true;
      return regFind(node.Remark, realRule.v);
    }
    return false;
  });
  let included: boolean;
  if (includeRemarks.length > 0) {
    included = includeRemarks.some((x) => {
      if (applyMatcher(x, realRule, node)) {
        if (realRule.v.length === 0) return true;
        return regFind(node.Remark, realRule.v);
      }
      return false;
    });
  } else included = true;
  return excluded || !included;
}

export function filterNodes(nodes: Proxy[], excludeRemarks: string[], includeRemarks: string[], groupID: number): void {
  let nodeIndex = 0;
  for (let i = 0; i < nodes.length; ) {
    if (chkIgnore(nodes[i], excludeRemarks, includeRemarks)) {
      nodes.splice(i, 1);
    } else {
      nodes[i].Id = nodeIndex;
      nodes[i].GroupId = groupID;
      nodeIndex++;
      i++;
    }
  }
}

export function nodeRename(node: Proxy, renameArray: RegexMatchConfigs, ext: extra_settings): void {
  const originalRemark = node.Remark;
  const realRule = { v: "" };
  for (const x of renameArray) {
    if (x.Script.length > 0) continue; // scripts unsupported (NO_JS_RUNTIME)
    if (applyMatcher(x.Match, realRule, node) && realRule.v.length > 0)
      node.Remark = regReplace(node.Remark, realRule.v, x.Replace);
  }
  if (node.Remark.length === 0) node.Remark = originalRemark;
}

export function removeEmoji(origRemark: string): string {
  // C++ checks UTF-8 bytes F0 9F — an emoji in U+1F000..U+1FFFF — and strips 4 bytes (2 UTF-16 units)
  let remark = origRemark;
  for (;;) {
    const cp = remark.codePointAt(0) ?? 0;
    if (cp >= 0x1f000 && cp <= 0x1ffff) remark = remark.substring(2);
    else break;
  }
  if (remark.length === 0) return origRemark;
  return remark;
}

export function addEmoji(node: Proxy, emojiArray: RegexMatchConfigs, ext: extra_settings): string {
  void ext;
  const realRule = { v: "" };
  for (const x of emojiArray) {
    if (x.Script.length > 0) continue;
    if (x.Replace.length === 0) continue;
    if (applyMatcher(x.Match, realRule, node) && realRule.v.length > 0 && regFind(node.Remark, realRule.v))
      return x.Replace + " " + node.Remark;
  }
  return node.Remark;
}

export function preprocessNodes(nodes: Proxy[], ext: extra_settings): void {
  for (const x of nodes) {
    if (ext.remove_emoji) {
      const r = { v: x.Remark };
      x.Remark = trim(removeEmoji(r.v));
    }
    nodeRename(x, ext.rename_array, ext);
    if (ext.add_emoji) x.Remark = addEmoji(x, ext.emoji_array, ext);
  }

  if (ext.sort_flag) {
    // sort scripts unsupported — stable sort by remark
    stableSort(nodes, (a, b) => (a.Remark < b.Remark ? -1 : a.Remark > b.Remark ? 1 : 0));
  }
}

export function stableSort<T>(arr: T[], cmp: (a: T, b: T) => number): void {
  const indexed = arr.map((v, i) => ({ v, i }));
  indexed.sort((a, b) => cmp(a.v, b.v) || a.i - b.i);
  for (let i = 0; i < arr.length; i++) arr[i] = indexed[i].v;
}

export { regTrim, regValid, split };
