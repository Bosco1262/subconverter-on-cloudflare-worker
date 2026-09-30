// Port of src/generator/config/ruleconvert.cpp + renderClashScript from templates.cpp

import { global } from "./settings";
import { endsWith, getLineBreak, startsWith, strFind, toLower, replaceAllDistinct, trim, countLeast } from "../lib/string";
import { regFind, regGetMatch, regReplace } from "../lib/regex";
import { split, splitChar } from "../lib/string";
import { urlSafeBase64Encode } from "../lib/base64";
import { urlDecode } from "../lib/urlencode";
import { trimWhitespace } from "../lib/string";
import type { INIReader } from "../lib/ini";
import { isIPv4, isIPv6, isLink } from "./parser/util";
import type { RulesetContent } from "./extra";
import { RULESET_SURGE, RULESET_QUANX, RULESET_CLASH_DOMAIN, RULESET_CLASH_IPCIDR, RULESET_CLASH_CLASSICAL } from "./extra";

/// rule type lists
const BASIC_TYPES = ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR", "GEOIP", "MATCH", "FINAL"];
export const ClashRuleTypes = [...BASIC_TYPES, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "DOMAIN-REGEX", "GEOSITE", "IP-SUFFIX", "IP-ASN", "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-SUFFIX", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME", "PROCESS-PATH-REGEX", "PROCESS-PATH", "PROCESS-NAME-REGEX", "UID", "NETWORK", "DSCP", "SUB-RULE", "RULE-SET", "AND", "OR", "NOT"];
export const Surge2RuleTypes = [...BASIC_TYPES, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"];
export const SurgeRuleTypes = [...BASIC_TYPES, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"];
export const QuanXRuleTypes = [...BASIC_TYPES, "USER-AGENT", "HOST", "HOST-SUFFIX", "HOST-KEYWORD"];
export const SurfRuleTypes = [...BASIC_TYPES, "IP-CIDR6", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"];
export const SingBoxRuleTypes = [...BASIC_TYPES, "IP-VERSION", "INBOUND", "PROTOCOL", "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT", "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID"];

export function convertRuleset(content: string, type: number): string {
  /// Target: Surge type,pattern[,flag]
  /// Source: QuanX type,pattern[,group] | Clash payload:\n  - 'ipcidr/domain/classic(Surge-like)'

  if (type === RULESET_SURGE) return content;

  if (regFind(content, "^payload:\\r?\\n")) {
    // Clash
    let output = regReplace(regReplace(content, "payload:\\r?\\n", "", true), "\\s?^\\s*-\\s+('|\"?)(.*)\\1$", "\n$2", true);
    if (type === RULESET_CLASH_CLASSICAL) return output;
    const delimiter = getLineBreak(output);
    const lines = delimiter === "\n" ? output.split("\n") : output.split("\r");
    let result = "";
    for (let strLine of lines) {
      strLine = trim(strLine);
      let lineSize = strLine.length;
      if (lineSize > 0 && strLine[lineSize - 1] === "\r") {
        strLine = strLine.substring(0, strLine.length - 1);
        lineSize--;
      }
      if (strFind(strLine, "//")) {
        strLine = strLine.substring(0, strLine.indexOf("//"));
        strLine = trimWhitespace(strLine);
      }
      if (strLine.length > 0 && (strLine[0] !== ";" && strLine[0] !== "#" && !(lineSize >= 2 && strLine[0] === "/" && strLine[1] === "/"))) {
        const pos = strLine.indexOf("/");
        if (pos !== -1) {
          // ipcidr
          if (isIPv4(strLine.substring(0, pos))) result += "IP-CIDR,";
          else result += "IP-CIDR6,";
        } else {
          if (strLine[0] === "." || (lineSize >= 2 && strLine[0] === "+" && strLine[1] === ".")) {
            // suffix
            let keywordFlag = false;
            while (endsWith(strLine, ".*")) {
              keywordFlag = true;
              strLine = strLine.substring(0, strLine.length - 2);
            }
            result += "DOMAIN-";
            if (keywordFlag) result += "KEYWORD,";
            else result += "SUFFIX,";
            // strLine.erase(0, 2 - (strLine[0] == '.'))
            strLine = strLine.substring(2 - (strLine[0] === "." ? 1 : 0));
          } else result += "DOMAIN,";
        }
      }
      result += strLine;
      result += "\n";
    }
    return result;
  } else {
    // QuanX
    let output = regReplace(regReplace(content, "^(?i:host)", "DOMAIN", true), "^(?i:ip6-cidr)", "IP-CIDR6", true);
    output = regReplace(output, "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$", "\\U$1\\E$2${3:-}", true);
    return output;
  }
}

function transformRuleToCommon(input: string, group: string, noResolveOnly = false): string {
  const temp = split(input, ",");
  let strLine: string;
  if (temp.length < 2) {
    strLine = temp[0] + "," + group;
  } else {
    strLine = temp[0] + "," + temp[1] + "," + group;
    if (temp.length > 2 && (!noResolveOnly || temp[2] === "no-resolve")) {
      strLine += "," + temp[2];
    }
  }
  return strLine;
}

export function rulesetToClash(
  baseRule: Record<string, unknown>, rulesetContentArray: RulesetContent[], overwriteOriginalRules: boolean, newFieldName: boolean,
): void {
  const allRules: string[] = [];
  const fieldName = newFieldName ? "rules" : "Rule";
  let rules: unknown[] = [];
  let totalRules = 0;

  if (!overwriteOriginalRules && Array.isArray(baseRule[fieldName])) {
    rules = baseRule[fieldName] as unknown[];
  }

  for (const x of rulesetContentArray) {
    if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
    const ruleGroup = x.rule_group;
    const retrievedRules0 = x.rule_content;
    if (retrievedRules0.length === 0) {
      console.warn("Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!");
      continue;
    }
    if (startsWith(retrievedRules0, "[]")) {
      let strLine = retrievedRules0.substring(2);
      if (startsWith(strLine, "FINAL")) strLine = "MATCH" + strLine.substring(5);
      strLine = transformRuleToCommon(strLine, ruleGroup);
      allRules.push(strLine);
      totalRules++;
      continue;
    }
    const retrievedRules = convertRuleset(retrievedRules0, x.rule_type);
    const delimiter = getLineBreak(retrievedRules);
    const lines = delimiter === "\n" ? retrievedRules.split("\n") : retrievedRules.split("\r");
    for (let strLine of lines) {
      if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
      strLine = trimWhitespace(strLine, true, true);
      const lineSize = strLine.length;
      if (lineSize === 0 || strLine[0] === ";" || strLine[0] === "#" || (lineSize >= 2 && strLine[0] === "/" && strLine[1] === "/")) continue;
      if (!ClashRuleTypes.some((type) => startsWith(strLine, type))) continue;
      if (strFind(strLine, "//")) {
        strLine = strLine.substring(0, strLine.indexOf("//"));
        strLine = trimWhitespace(strLine);
      }
      strLine = transformRuleToCommon(strLine, ruleGroup);
      allRules.push(strLine);
    }
  }

  for (const x of allRules) rules.push(x);
  baseRule[fieldName] = rules;
}

export function rulesetToClashStr(
  baseRule: Record<string, unknown>, rulesetContentArray: RulesetContent[], overwriteOriginalRules: boolean, newFieldName: boolean,
): string {
  const fieldName = newFieldName ? "rules" : "Rule";
  let outputContent = "\n" + fieldName + ":\n";
  let totalRules = 0;

  if (!overwriteOriginalRules && Array.isArray(baseRule[fieldName])) {
    for (const item of baseRule[fieldName] as unknown[]) {
      outputContent += "  - " + String(item) + "\n";
    }
  }
  delete baseRule[fieldName];

  for (const x of rulesetContentArray) {
    if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
    const ruleGroup = x.rule_group;
    const retrievedRules0 = x.rule_content;
    if (retrievedRules0.length === 0) {
      console.warn("Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!");
      continue;
    }
    if (startsWith(retrievedRules0, "[]")) {
      let strLine = retrievedRules0.substring(2);
      if (startsWith(strLine, "FINAL")) strLine = "MATCH" + strLine.substring(5);
      strLine = transformRuleToCommon(strLine, ruleGroup);
      outputContent += "  - " + strLine + "\n";
      totalRules++;
      continue;
    }
    const retrievedRules = convertRuleset(retrievedRules0, x.rule_type);
    const delimiter = getLineBreak(retrievedRules);
    const lines = delimiter === "\n" ? retrievedRules.split("\n") : retrievedRules.split("\r");
    for (let strLine of lines) {
      if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
      strLine = trimWhitespace(strLine, true, true);
      const lineSize = strLine.length;
      if (lineSize === 0 || strLine[0] === ";" || strLine[0] === "#" || (lineSize >= 2 && strLine[0] === "/" && strLine[1] === "/")) continue;
      if (!ClashRuleTypes.some((type) => startsWith(strLine, type))) continue;
      if (strFind(strLine, "//")) {
        strLine = strLine.substring(0, strLine.indexOf("//"));
        strLine = trimWhitespace(strLine);
      }
      // AND & OR & NOT
      if (startsWith(strLine, "AND") || startsWith(strLine, "OR") || startsWith(strLine, "NOT")) {
        outputContent += "  - " + strLine + "," + ruleGroup + "\n";
      } else if (startsWith(strLine, "SUB-RULE") || startsWith(strLine, "RULE-SET")) {
        outputContent += "  - " + strLine + "\n";
      } else {
        strLine = transformRuleToCommon(strLine, ruleGroup);
        outputContent += "  - " + strLine + "\n";
      }
      totalRules++;
    }
  }
  return outputContent;
}

export function rulesetToSurge(
  baseRule: INIReader, rulesetContentArray: RulesetContent[], surgeVer: number, overwriteOriginalRules: boolean, remotePathPrefix: string,
): void {
  const allRules: string[] = [];
  let totalRules = 0;

  let targetSection: string;
  switch (surgeVer) {
    case 0:
      targetSection = "RoutingRule";
      break;
    case -1:
      targetSection = "filter_local";
      break;
    case -2:
      targetSection = "TCP";
      break;
    default:
      targetSection = "Rule";
  }
  baseRule.setCurrentSection(targetSection);

  if (overwriteOriginalRules) {
    baseRule.eraseSection(targetSection);
    switch (surgeVer) {
      case -1:
        baseRule.eraseSection("filter_remote");
        break;
      case -4:
        baseRule.eraseSection("Remote Rule");
        break;
      default:
        break;
    }
  }

  for (const x of rulesetContentArray) {
    if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
    const ruleGroup = x.rule_group;
    const rulePath = x.rule_path;
    const rulePathTyped = x.rule_path_typed;
    if (rulePath.length === 0) {
      let strLine = x.rule_content.substring(2);
      if (strLine === "MATCH") strLine = "FINAL";
      if (surgeVer === -1 || surgeVer === -2) {
        strLine = transformRuleToCommon(strLine, ruleGroup, true);
      } else {
        if (!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
          strLine = transformRuleToCommon(strLine, ruleGroup);
      }
      strLine = replaceAllDistinct(strLine, ",,", ",");
      allRules.push(strLine);
      totalRules++;
      continue;
    } else {
      if (surgeVer === -1 && x.rule_type === RULESET_QUANX && isLink(rulePath)) {
        const strLine = rulePath + ", tag=" + ruleGroup + ", force-policy=" + ruleGroup + ", enabled=true";
        baseRule.set("filter_remote", "{NONAME}", strLine);
        continue;
      }
      // fileExist(rule_path) — local paths only exist in embedded VFS for base configs; rulesets are remote
      const pathExists = rulePathExists(rulePath);
      if (pathExists) {
        if (surgeVer > 2 && remotePathPrefix.length > 0) {
          let strLine = "RULE-SET," + remotePathPrefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rulePathTyped) + "," + ruleGroup;
          if (x.update_interval) strLine += ",update-interval=" + x.update_interval;
          allRules.push(strLine);
          continue;
        } else if (surgeVer === -1 && remotePathPrefix.length > 0) {
          let strLine = remotePathPrefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rulePathTyped) + "&group=" + urlSafeBase64Encode(ruleGroup);
          strLine += ", tag=" + ruleGroup + ", enabled=true";
          baseRule.set("filter_remote", "{NONAME}", strLine);
          continue;
        } else if (surgeVer === -4 && remotePathPrefix.length > 0) {
          const strLine = remotePathPrefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rulePathTyped) + "," + ruleGroup;
          baseRule.set("Remote Rule", "{NONAME}", strLine);
          continue;
        }
      } else if (isLink(rulePath)) {
        if (surgeVer > 2) {
          let strLine: string;
          if (x.rule_type !== RULESET_SURGE) {
            if (remotePathPrefix.length === 0) continue;
            strLine = "RULE-SET," + remotePathPrefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rulePathTyped) + "," + ruleGroup;
          } else strLine = "RULE-SET," + rulePath + "," + ruleGroup;
          if (x.update_interval) strLine += ",update-interval=" + x.update_interval;
          allRules.push(strLine);
          continue;
        } else if (surgeVer === -1 && remotePathPrefix.length > 0) {
          let strLine = remotePathPrefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rulePathTyped) + "&group=" + urlSafeBase64Encode(ruleGroup);
          strLine += ", tag=" + ruleGroup + ", enabled=true";
          baseRule.set("filter_remote", "{NONAME}", strLine);
          continue;
        } else if (surgeVer === -4) {
          const strLine = rulePath + "," + ruleGroup;
          baseRule.set("Remote Rule", "{NONAME}", strLine);
          continue;
        }
      } else continue;
      const retrievedRules0 = x.rule_content;
      if (retrievedRules0.length === 0) {
        console.warn("Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!");
        continue;
      }

      const retrievedRules = convertRuleset(retrievedRules0, x.rule_type);
      const delimiter = getLineBreak(retrievedRules);
      const lines = delimiter === "\n" ? retrievedRules.split("\n") : retrievedRules.split("\r");
      for (let strLine of lines) {
        if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
        strLine = trimWhitespace(strLine, true, true);
        const lineSize = strLine.length;
        if (lineSize === 0 || strLine[0] === ";" || strLine[0] === "#" || (lineSize >= 2 && strLine[0] === "/" && strLine[1] === "/")) continue;

        // remove unsupported types
        switch (surgeVer) {
          case -2:
            if (startsWith(strLine, "IP-CIDR6")) continue;
            if (!QuanXRuleTypes.some((type) => startsWith(strLine, type))) continue;
            break;
          case -1:
            if (!QuanXRuleTypes.some((type) => startsWith(strLine, type))) continue;
            break;
          case -3:
            if (!SurfRuleTypes.some((type) => startsWith(strLine, type))) continue;
            break;
          default:
            if (surgeVer > 2) {
              if (!SurgeRuleTypes.some((type) => startsWith(strLine, type))) continue;
            } else {
              if (!Surge2RuleTypes.some((type) => startsWith(strLine, type))) continue;
            }
        }

        if (strFind(strLine, "//")) {
          strLine = strLine.substring(0, strLine.indexOf("//"));
          strLine = trimWhitespace(strLine);
        }

        if (surgeVer === -1 || surgeVer === -2) {
          if (startsWith(strLine, "IP-CIDR6")) strLine = "IP6-CIDR" + strLine.substring(8);
          strLine = transformRuleToCommon(strLine, ruleGroup, true);
        } else {
          if (!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
            strLine = transformRuleToCommon(strLine, ruleGroup);
        }
        allRules.push(strLine);
        totalRules++;
      }
    }
  }

  for (const x of allRules) {
    baseRule.set(targetSection, "{NONAME}", x);
  }
}

// VFS hook — set by vfs module; local ruleset files exist only in embedded assets
let rulePathChecker: (path: string) => boolean = () => false;
export function setRulePathChecker(fn: (path: string) => boolean): void {
  rulePathChecker = fn;
}
function rulePathExists(path: string): boolean {
  return rulePathChecker(path);
}

function transformRuleToSingBox(rule: string, group: string): Record<string, unknown> {
  const args = split(rule, ",");
  if (args.length < 2) return {};
  let type = toLower(args[0]);
  const value = toLower(args[1]);
  const ruleObj: Record<string, unknown> = {};
  type = replaceAllDistinct(type, "-", "_");
  type = replaceAllDistinct(type, "ip_cidr6", "ip_cidr");
  type = replaceAllDistinct(type, "src_", "source_");
  if (type === "match" || type === "final") {
    ruleObj["outbound"] = value;
  } else {
    ruleObj[type] = value;
    ruleObj["outbound"] = group;
  }
  return ruleObj;
}

function appendSingBoxRule(rules: Record<string, string[]>, rule: string): void {
  const args = split(rule, ",");
  if (args.length < 2) return;
  const type = args[0];
  if (!SingBoxRuleTypes.includes(type)) return;

  let realType = toLower(type);
  const value = toLower(args[1]);
  realType = replaceAllDistinct(realType, "-", "_");
  realType = replaceAllDistinct(realType, "ip_cidr6", "ip_cidr");

  if (!rules[realType]) rules[realType] = [];
  rules[realType].push(value);
}

export function rulesetToSingBox(baseRule: Record<string, unknown>, rulesetContentArray: RulesetContent[], overwriteOriginalRules: boolean): void {
  let totalRules = 0;
  let final = "";

  let rules: Record<string, unknown>[] = [];
  let mergeRules: Record<string, string[]> | null = null;
  if (!overwriteOriginalRules) {
    const route = baseRule["route"] as Record<string, unknown> | undefined;
    if (route && Array.isArray(route["rules"])) {
      rules = route["rules"] as Record<string, unknown>[];
    }
  }

  if (global.singBoxAddClashModes) {
    rules.push({ clash_mode: "Global", outbound: "GLOBAL" });
    rules.push({ clash_mode: "Direct", outbound: "DIRECT" });
  }

  for (const x of rulesetContentArray) {
    if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
    const ruleGroup = x.rule_group;
    const retrievedRules0 = x.rule_content;
    if (retrievedRules0.length === 0) {
      console.warn("Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!");
      continue;
    }
    if (startsWith(retrievedRules0, "[]")) {
      const strLine = retrievedRules0.substring(2);
      if (startsWith(strLine, "FINAL") || startsWith(strLine, "MATCH")) {
        final = ruleGroup;
        continue;
      }
      rules.push(transformRuleToSingBox(strLine, ruleGroup));
      totalRules++;
      continue;
    }
    const retrievedRules = convertRuleset(retrievedRules0, x.rule_type);
    const delimiter = getLineBreak(retrievedRules);
    const lines = delimiter === "\n" ? retrievedRules.split("\n") : retrievedRules.split("\r");

    const rule: Record<string, string[]> = {};
    for (let strLine of lines) {
      if (global.maxAllowedRules > 0 && totalRules > global.maxAllowedRules) break;
      strLine = trimWhitespace(strLine, true, true);
      const lineSize = strLine.length;
      if (lineSize === 0 || strLine[0] === ";" || strLine[0] === "#" || (lineSize >= 2 && strLine[0] === "/" && strLine[1] === "/")) continue;
      if (strFind(strLine, "//")) {
        strLine = strLine.substring(0, strLine.indexOf("//"));
        strLine = trimWhitespace(strLine);
      }
      appendSingBoxRule(rule, strLine);
    }
    if (Object.keys(rule).length === 0) continue;
    rule["outbound"] = [ruleGroup];
    // sing-box rules use scalar values, not arrays — flatten single-element arrays
    const flattened: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rule)) {
      flattened[k] = v.length === 1 ? v[0] : v;
    }
    rules.push(flattened);
  }

  if (!baseRule["route"]) baseRule["route"] = {};
  const route = baseRule["route"] as Record<string, unknown>;
  route["rules"] = rules;
  route["final"] = final;
  void mergeRules;
}

// ---- renderClashScript (templates.cpp 310-581) ----

function findFileName(path: string): string {
  let pos = path.lastIndexOf("/");
  if (pos === -1) {
    pos = path.lastIndexOf("\\");
    if (pos === -1) pos = 0;
  }
  let pos2 = path.lastIndexOf(".");
  if (pos2 < pos || pos2 === -1) pos2 = path.length;
  return path.substring(pos + 1, pos2 - pos === 0 ? path.length : pos === path.length - 1 ? path.length : pos2);
}

export function renderClashScript(
  baseRule: Record<string, unknown>, rulesetContentArray: RulesetContent[], remotePathPrefix: string,
  script: boolean, overwriteOriginalRules: boolean, clashClassicalRuleset: boolean,
): void {
  let matchGroup = "", geoips = "";
  const keywords = new Map<string, string>();
  const urls = new Map<string, string>();
  const names = new Map<string, string>();
  const hasDomain = new Map<string, boolean>();
  const hasIpcidr = new Map<string, boolean>();
  const rulesetInterval = new Map<string, number>();
  const ruleType = new Map<string, number>();
  const rulesetFormat = new Map<string, string>();
  const rules: string[] = [];
  const groups: string[] = [];
  let index = 0;

  if (!overwriteOriginalRules && Array.isArray(baseRule["rules"])) {
    rules.push(...(baseRule["rules"] as string[]).map(String));
  }

  for (const x of rulesetContentArray) {
    const ruleGroup = x.rule_group;
    const rulePath = x.rule_path;
    const rulePathTyped = x.rule_path_typed;
    if (rulePath.length === 0) {
      let strLine = x.rule_content.substring(2);
      if (script) {
        if (startsWith(strLine, "MATCH") || startsWith(strLine, "FINAL")) matchGroup = ruleGroup;
        else if (startsWith(strLine, "GEOIP")) {
          const vArray = split(strLine, ",");
          if (vArray.length < 2) continue;
          geoips += '"' + vArray[1] + '": "' + ruleGroup + '",';
        }
        continue;
      }
      if (startsWith(strLine, "FINAL")) strLine = "MATCH" + strLine.substring(5);
      strLine += "," + ruleGroup;
      if (countLeast(strLine, ",", 3)) strLine = regReplace(strLine, "^(.*?,.*?)(,.*)(,.*)$", "$1$3$2");
      rules.push(strLine);
      continue;
    } else {
      if (x.rule_type === RULESET_CLASH_IPCIDR || x.rule_type === RULESET_CLASH_DOMAIN || x.rule_type === RULESET_CLASH_CLASSICAL) {
        let ruleName = urlDecode(findFileNameRule(rulePath));
        const oldRuleName = ruleName;
        let idx = 2;
        while (groups.includes(ruleName)) ruleName = oldRuleName + " " + idx++;
        names.set(ruleName, ruleGroup);
        urls.set(ruleName, "*" + rulePath);
        ruleType.set(ruleName, x.rule_type);
        rulesetInterval.set(ruleName, x.update_interval);
        rulesetFormat.set(ruleName, x.rule_format);
        switch (x.rule_type) {
          case RULESET_CLASH_IPCIDR:
            hasIpcidr.set(ruleName, true);
            break;
          case RULESET_CLASH_DOMAIN:
            hasDomain.set(ruleName, true);
            break;
          case RULESET_CLASH_CLASSICAL:
            break;
        }
        if (!script) rules.push("RULE-SET," + ruleName + "," + ruleGroup);
        groups.push(ruleName);
        continue;
      }
      if (remotePathPrefix.length > 0) {
        if (rulePathExists(rulePath) || isLink(rulePath)) {
          let ruleName = urlDecode(findFileNameRule(rulePath));
          const oldRuleName = ruleName;
          let idx = 2;
          while (groups.includes(ruleName)) ruleName = oldRuleName + " " + idx++;
          names.set(ruleName, ruleGroup);
          urls.set(ruleName, rulePathTyped);
          ruleType.set(ruleName, x.rule_type);
          rulesetInterval.set(ruleName, x.update_interval);
          rulesetFormat.set(ruleName, x.rule_format);
          if (clashClassicalRuleset) {
            if (!script) rules.push("RULE-SET," + ruleName + "," + ruleGroup);
            groups.push(ruleName);
            continue;
          }
        } else continue;
      }

      const retrievedRules0 = x.rule_content;
      if (retrievedRules0.length === 0) {
        console.warn("Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!");
        continue;
      }

      const retrievedRules = convertRuleset(retrievedRules0, x.rule_type);
      const delimiter = getLineBreak(retrievedRules);
      const lines = delimiter === "\n" ? retrievedRules.split("\n") : retrievedRules.split("\r");
      let hasNoResolve = false;
      const ruleName = [...names.entries()].reverse().find(([, g]) => g === ruleGroup)?.[0] ?? "";
      for (let strLine of lines) {
        const lineSize = strLine.length;
        if (lineSize > 0 && strLine[lineSize - 1] === "\r") strLine = strLine.substring(0, strLine.length - 1);
        if (strLine.length === 0 || strLine[0] === ";" || strLine[0] === "#" || (strLine.length >= 2 && strLine[0] === "/" && strLine[1] === "/")) continue;

        if (startsWith(strLine, "DOMAIN-KEYWORD,")) {
          if (script) {
            const vArray = split(strLine, ",");
            if (vArray.length < 2) continue;
            if (!keywords.has(ruleName)) keywords.set(ruleName, '"' + trim(vArray[1]) + '"');
            else keywords.set(ruleName, keywords.get(ruleName) + ',"' + trim(vArray[1]) + '"');
          } else {
            const vArray = split(strLine, ",");
            if (vArray.length < 2) {
              strLine = vArray[0] + "," + ruleGroup;
            } else {
              strLine = vArray[0] + "," + trim(vArray[1]) + "," + ruleGroup;
              if (vArray.length > 2) strLine += "," + vArray[2];
            }
            rules.push(strLine);
          }
        } else if (!hasDomain.get(ruleName) && (startsWith(strLine, "DOMAIN,") || startsWith(strLine, "DOMAIN-SUFFIX,")))
          hasDomain.set(ruleName, true);
        else if (!hasIpcidr.get(ruleName) && (startsWith(strLine, "IP-CIDR,") || startsWith(strLine, "IP-CIDR6,"))) {
          hasIpcidr.set(ruleName, true);
          if (strLine.includes(",no-resolve")) hasNoResolve = true;
        }
      }
      if (hasDomain.get(ruleName) && !script) rules.push("RULE-SET," + ruleName + " (Domain)," + ruleGroup);
      if (hasIpcidr.get(ruleName) && !script) {
        if (hasNoResolve) rules.push("RULE-SET," + ruleName + " (IP-CIDR)," + ruleGroup + ",no-resolve");
        else rules.push("RULE-SET," + ruleName + " (IP-CIDR)," + ruleGroup);
      }
      if (!hasDomain.get(ruleName) && !hasIpcidr.get(ruleName) && !script)
        rules.push("RULE-SET," + ruleName + "," + ruleGroup);
      if (!groups.includes(ruleName)) groups.push(ruleName);
    }
  }

  for (const x of groups) {
    const url = urls.get(x) ?? "", keyword = keywords.get(x) ?? "", name = names.get(x) ?? "";
    const groupHasDomain = hasDomain.get(x) ?? false;
    const groupHasIpcidr = hasIpcidr.get(x) ?? false;
    const interval = rulesetInterval.get(x) ?? 0;
    const format = rulesetFormat.get(x) ?? "";

    if (groupHasDomain) {
      let yamlKey = x;
      if (ruleType.get(x) !== RULESET_CLASH_DOMAIN) yamlKey += " (Domain)";
      ensureProvider(baseRule, yamlKey, "domain", url, remotePathPrefix, interval, format, "_domain.yaml");
    }
    if (groupHasIpcidr) {
      let yamlKey = x;
      if (ruleType.get(x) !== RULESET_CLASH_IPCIDR) yamlKey += " (IP-CIDR)";
      ensureProvider(baseRule, yamlKey, "ipcidr", url, remotePathPrefix, interval, format, "_ipcidr.yaml");
    }
    if (!groupHasDomain && !groupHasIpcidr) {
      ensureProvider(baseRule, x, "classical", url, remotePathPrefix, interval, format, ".yaml");
    }
    if (script) {
      // script data collected for template render below
      scriptData.push({ has_domain: groupHasDomain ? "true" : "false", has_ipcidr: groupHasIpcidr ? "true" : "false", name: x, group: name, keyword, original: (ruleType.get(x) === RULESET_CLASH_DOMAIN || ruleType.get(x) === RULESET_CLASH_IPCIDR) ? "true" : "false" });
    }
    index++;
  }
  void index;

  if (script) {
    baseRule["script"] = { code: renderClashScriptPython(scriptData, geoips, matchGroup) };
    scriptData.length = 0;
  } else baseRule["rules"] = rules;
}

const scriptData: Record<string, string>[] = [];

function ensureProvider(
  baseRule: Record<string, unknown>, yamlKey: string, behavior: string, url: string,
  remotePathPrefix: string, interval: number, format: string, suffix: string,
): void {
  if (!baseRule["rule-providers"]) baseRule["rule-providers"] = {};
  const providers = baseRule["rule-providers"] as Record<string, unknown>;
  const provider: Record<string, unknown> = {};
  provider["type"] = "http";
  provider["behavior"] = behavior;
  if (url[0] === "*") provider["url"] = url.substring(1);
  else provider["url"] = remotePathPrefix + "/getruleset?type=" + (behavior === "domain" ? 3 : behavior === "ipcidr" ? 4 : 6) + "&url=" + urlSafeBase64Encode(url);
  provider["path"] = "./providers/" + strHash(url) + suffix;
  if (format.length > 0) provider["format"] = format;
  if (interval) provider["interval"] = interval;
  providers[yamlKey] = provider;
}

// std::hash-like stable id (upstream uses std::hash; value differs on each platform anyway — use a stable FNV)
function strHash(url: string): string {
  let h = 1469598103934665603n;
  for (let i = 0; i < url.length; i++) {
    h ^= BigInt(url.charCodeAt(i));
    h = (h * 1099511628211n) & 0xFFFFFFFFFFFFFFFFn;
  }
  return h.toString();
}

function findFileNameRule(path: string): string {
  // port of findFileName — returns filename without extension
  let pos = path.lastIndexOf("/");
  if (pos === -1) {
    pos = path.lastIndexOf("\\");
    if (pos === -1) pos = 0;
  }
  let pos2 = path.lastIndexOf(".");
  if (pos2 < pos || pos2 === -1) pos2 = path.length;
  return path.substring(pos + 1, pos2);
}

function renderClashScriptPython(rules: Record<string, string>[], geoipsRaw: string, matchGroup: string): string {
  // renders clash_script_template + group/keyword templates with inja semantics
  const indent = (s: string) => s;
  let out = "def main(ctx, md):\n";
  out += '  host = md["host"]\n';
  for (const rule of rules) {
    if (rule.set !== "true") continue;
    if ((rule.has_domain === "false" && rule.has_ipcidr === "false") || rule.original === "true") {
      out += `  if ctx.rule_providers["${rule.name}"].match(md):\n`;
      out += `    ctx.log('[Script] matched ${rule.group} rule')\n`;
      out += `    return "${rule.group}"`;
    } else {
      if (rule.has_domain === "true") {
        out += `  if ctx.rule_providers["${rule.name}_domain"].match(md):\n`;
        out += `    ctx.log('[Script] matched ${rule.group} DOMAIN rule')\n`;
        out += `    return "${rule.group}"`;
      }
      if (rule.keyword !== "") {
        out += `\n  keywords = [${rule.keyword}]\n`;
        out += `  for keyword in keywords:\n`;
        out += `    if keyword in host:\n`;
        out += `      ctx.log('[Script] matched ${rule.group} DOMAIN-KEYWORD rule')\n`;
        out += `      return "${rule.group}"`;
      }
      if (rule.has_ipcidr === "true") {
        out += `\n  if ctx.rule_providers["${rule.name}_ipcidr"].match(md):\n`;
        out += `    ctx.log('[Script] matched ${rule.group} IP rule')\n`;
        out += `    return "${rule.group}"`;
      }
    }
    out += "\n";
  }
  out = indent(out);
  out += "\n";
  if (geoipsRaw.length > 0) {
    const geoips = geoipsRaw.substring(0, geoipsRaw.length - 1);
    out += `  geoips = { ${geoips} }\n`;
    out += `  ip = md["dst_ip"]\n`;
    out += `  if ip == "":\n`;
    out += `    ip = ctx.resolve_ip(host)\n`;
    out += `    if ip == "":\n`;
    out += `      ctx.log('[Script] dns lookup error use ${matchGroup}')\n`;
    out += `      return "${matchGroup}"\n`;
    out += `  for key in geoips:\n`;
    out += `    if ctx.geoip(ip) == key:\n`;
    out += `      return geoips[key]`;
  }
  out += `\n  return "${matchGroup}"`;
  return out;
}

void splitChar;
