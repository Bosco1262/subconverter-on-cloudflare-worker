// Port of src/parser/subparser.cpp explode + explodeSub dispatch (lines 3414-3523)

import { urlSafeBase64Decode } from "../../lib/base64";
import { startsWith, strFind, countLeast } from "../../lib/string";
import { regFind, regGetMatch } from "../../lib/regex";
import { loadYaml } from "../../lib/yaml";
import { Proxy, ProxyType, newProxy } from "../proxy";
import { isLink } from "./util";
import {
  explodeVmess, explodeSS, explodeSSR, explodeSocks, explodeHTTP, explodeHTTPSub, explodeTrojan,
  explodeVless, explodeHysteria, explodeHysteria2, explodeTuic, explodeAnyTLS, explodeMierus, explodeNetch,
} from "./link";
import { explodeSSD, explodeConfContent } from "./conf";
export { explodeSSD, explodeConfContent };
import { explodeClash } from "./clash";
import { explodeSurge } from "./surge";
import { explodeSingbox } from "./singbox";

/// Parse a link
export function explode(link: string, node: Proxy): void {
  if (startsWith(link, "ssr://")) explodeSSR(link, node);
  else if (startsWith(link, "vmess://") || startsWith(link, "vmess1://")) explodeVmess(link, node);
  else if (startsWith(link, "ss://")) explodeSS(link, node);
  else if (startsWith(link, "socks://") || startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks")) explodeSocks(link, node);
  else if (startsWith(link, "https://t.me/http") || startsWith(link, "tg://http")) explodeHTTP(link, node);
  else if (startsWith(link, "Netch://")) explodeNetch(link, node);
  else if (startsWith(link, "trojan://") || startsWith(link, "trojan-go://")) explodeTrojan(link, node);
  else if (strFind(link, "vless://") || strFind(link, "vless1://")) explodeVless(link, node);
  else if (strFind(link, "hysteria://") || strFind(link, "hy://")) explodeHysteria(link, node);
  else if (strFind(link, "tuic://")) explodeTuic(link, node);
  else if (strFind(link, "anytls://")) explodeAnyTLS(link, node);
  else if (strFind(link, "hysteria2://") || strFind(link, "hy2://")) explodeHysteria2(link, node);
  else if (strFind(link, "mierus://") || strFind(link, "mieru://")) explodeMierus(link, node);
  else if (isLink(link)) explodeHTTPSub(link, node);
}

export function explodeSub(sub0: string, nodes: Proxy[]): void {
  let sub = sub0;
  let processed = false;

  // try to parse as SSD configuration
  if (startsWith(sub, "ssd://")) {
    explodeSSD(sub, nodes);
    processed = true;
  }

  // try to parse as clash configuration
  if (!processed && regFind(sub, "\"?(Proxy|proxies)\"?:")) {
    const m = regGetMatch(sub, "^(?:Proxy|proxies):$\\s(?:(?:^ +?.*$| *?-.*$|)\\s?)+");
    if (m && m.length > 0) sub = m[0]; // C++ fills out-param with result[0] (full match)
    const yamlnode = loadYaml(sub);
    if (yamlnode && Object.keys(yamlnode).length > 0 && ("Proxy" in yamlnode || "proxies" in yamlnode)) {
      explodeClash(yamlnode, nodes);
      processed = true;
    }
  }

  // try to parse as sing-box configuration
  if (!processed && regFind(sub, "\"?(inbounds)\"?:")) {
    if (regFind(sub, "\"?(outbounds)\"?:")) {
      if (regFind(sub, "\"?(route)\"?:")) {
        try {
          const document = JSON.parse(sub) as Record<string, unknown>;
          const outbounds = document ? document["outbounds"] : null;
          if (Array.isArray(outbounds) && outbounds.length > 0) {
            explodeSingbox(outbounds, nodes);
            processed = true;
          }
        } catch {
          // JSON parse error — ignore
        }
      }
    }
  }

  // try to parse as surge configuration
  if (!processed && explodeSurge(sub, nodes) > 0) {
    processed = true;
  }

  // try to parse as normal subscription
  if (!processed) {
    sub = urlSafeBase64Decode(sub);
    if (regFind(sub, "(vmess|shadowsocks|http|trojan)\\s*?=")) {
      if (explodeSurge(sub, nodes) > 0) return;
    }
    const delimiter = countLeast(sub, "\n", 1) ? "\n" : countLeast(sub, "\r", 1) ? "\r" : " ";
    // C++ uses getline with single-char delimiter
    const lines = delimiter === "\n" ? sub.split("\n") : delimiter === "\r" ? sub.split("\r") : sub.split(" ");
    for (let strLink of lines) {
      const node = newProxy();
      // C++: if any '\r' present, erase last char (quirk kept for fidelity)
      if (strLink.includes("\r")) strLink = strLink.substring(0, strLink.length - 1);
      explode(strLink, node);
      if (strLink.length === 0 || node.Type === ProxyType.Unknown) {
        continue;
      }
      nodes.push(node);
    }
  }
}
