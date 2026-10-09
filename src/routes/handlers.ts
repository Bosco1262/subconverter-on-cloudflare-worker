// Port of interfaces.cpp: getRuleset (134-285), surgeConfToClash (930-1141), getProfile (1143-1232), renderTemplate (1387-1420)

import { global, fetchFile, fromIniRulesetConfs } from "../core/settings";
import { subconverter, type SubRequest, type SubResult } from "../core/orchestrator";
import type { extra_settings, RulesetContent, ProxyGroupConfig, ProxyGroupType } from "../core/extra";
import { newExtraSettings, RULESET_SURGE, RULESET_QUANX } from "../core/extra";
import { newProxy, Proxy } from "../core/proxy";
import { addNodes } from "../core/nodemanip";
import { proxyToClashCore } from "../core/export/clash";
import { ClashRuleTypes, QuanXRuleTypes, SurgeRuleTypes, convertRuleset } from "../core/ruleconvert";
import { render_template } from "../core/template";
import { INIReader } from "../lib/ini";
import { webGet } from "../lib/fetch";
import { fileExist, fileGet } from "../lib/vfs";
import { loadYaml } from "../lib/yaml";
import { stringify as yamlDump } from "../lib/yaml-dump";
import { base64Encode, base64Decode, urlSafeBase64Decode } from "../lib/base64";
import { split, startsWith, toInt, trim, trimWhitespace, countLeast, getLineBreak, join, strFind, getUrlArg } from "../lib/string";
import { urlEncode, urlDecode } from "../lib/urlencode";
import { regFind, regReplace } from "../lib/regex";
import { tribool } from "../lib/tribool";
import { fetchFile as fetchFileDyn } from "../core/settings";
void fetchFileDyn;

function argGet(argument: [string, string][], key: string): string {
  for (const [k, v] of argument) if (k === key) return v;
  return "";
}

function joinArguments(args: [string, string][]): string {
  let out = "";
  for (const [k, v] of args) out += k + "=" + urlEncode(v) + "&";
  if (out.length > 0) out = out.substring(0, out.length - 1);
  return out;
}

function parseProxy(source: string): string {
  if (source === "SYSTEM" || source === "NONE") return "";
  return source;
}

// ---------------- /getruleset (interfaces.cpp:134-285) ----------------

export async function getRulesetHandler(req: SubRequest): Promise<SubResult> {
  const argument = req.argument;
  const url = urlSafeBase64Decode(argGet(argument, "url"));
  const type = argGet(argument, "type");
  const group = urlSafeBase64Decode(argGet(argument, "group"));
  let typeInt = toInt(type, 0);

  if (url.length === 0 || type.length === 0 || (typeInt === 2 && group.length === 0) || typeInt < 1 || typeInt > 6) {
    return { status: 400, body: "Invalid request!", headers: [] };
  }

  const vArray = split(url, "|").map((x) => "ruleset," + x);
  // INIBinding::from<RulesetConfig>::from_ini + refreshRulesets: "[]" anywhere in the url marks
  // literal inline rule content, and the content is the url from "[]" onwards.
  const confs = fromIniRulesetConfs(vArray);
  const rca: RulesetContent[] = [];
  for (const [, path] of confs) {
    const pos = path.indexOf("[]");
    if (pos !== -1) {
      rca.push({
        rule_group: "",
        rule_path: "",
        rule_path_typed: "",
        rule_format: "surge-ruleset",
        rule_type: RULESET_SURGE,
        rule_content: path.substring(pos),
        update_interval: 0,
      });
      continue;
    }
    const content = await fetchFile(path, parseProxy(global.proxyRuleset), global.enableCache ? global.cacheRuleset : 0);
    rca.push({
      rule_group: "",
      rule_path: path,
      rule_path_typed: path,
      rule_format: "",
      rule_type: type === "2" ? RULESET_QUANX : RULESET_SURGE,
      rule_content: content,
      update_interval: 0,
    });
  }
  void typeInt;
  typeInt = toInt(type, 0);

  let outputContent = "";
  for (const x of rca) {
    outputContent += convertRuleset(x.rule_content, x.rule_type);
  }

  if (outputContent.length === 0) {
    return { status: 400, body: "Invalid request!", headers: [] };
  }

  const strLine = { v: "" };
  const ruleMatchRegex = "^(.*?,.*?)(,.*)(,.*)$";
  const delimiter = getLineBreak(outputContent);
  const lines = delimiter === "\n" ? outputContent.split("\n") : outputContent.split("\r");
  let finalOutput = "";
  if (typeInt === 3 || typeInt === 4 || typeInt === 6) finalOutput = "payload:\n";

  const filterLine = (): number => {
    filterPosb = 0;
    let pose = strLine.v.indexOf(",");
    if (pose === -1) return 1;
    filterPosb = pose + 1;
    pose = strLine.v.indexOf(",", filterPosb);
    if (pose === -1) {
      pose = strLine.v.length;
      if (strLine.v[pose - 1] === "\r") pose--;
    }
    filterPose = pose - filterPosb;
    return 0;
  };

  for (let line of lines) {
    strLine.v = line;
    if (strFind(strLine.v, "//")) {
      strLine.v = strLine.v.substring(0, strLine.v.indexOf("//"));
      strLine.v = trimWhitespace(strLine.v);
    }
    let handled = false;
    switch (typeInt) {
      case 2:
        if (!QuanXRuleTypes.some((t: string) => startsWith(strLine.v, t))) continue;
        break;
      case 1:
        if (!SurgeRuleTypes.some((t: string) => startsWith(strLine.v, t))) continue;
        break;
      case 3: {
        if (!startsWith(strLine.v, "DOMAIN-SUFFIX,") && !startsWith(strLine.v, "DOMAIN,")) continue;
        if (filterLine()) continue;
        finalOutput += "  - '";
        if (strLine.v[filterPosb - 2] === "X") finalOutput += "+.";
        finalOutput += strLine.v.substring(filterPosb, filterPosb + filterPose);
        finalOutput += "'\n";
        handled = true;
        break;
      }
      case 4: {
        if (!startsWith(strLine.v, "IP-CIDR,") && !startsWith(strLine.v, "IP-CIDR6,")) continue;
        if (filterLine()) continue;
        finalOutput += "  - '";
        finalOutput += strLine.v.substring(filterPosb, filterPosb + filterPose);
        finalOutput += "'\n";
        handled = true;
        break;
      }
      case 5: {
        if (!startsWith(strLine.v, "DOMAIN-SUFFIX,") && !startsWith(strLine.v, "DOMAIN,")) continue;
        if (filterLine()) continue;
        if (strLine.v[filterPosb - 2] === "X") finalOutput += ".";
        finalOutput += strLine.v.substring(filterPosb, filterPosb + filterPose);
        finalOutput += "\n";
        handled = true;
        break;
      }
      case 6:
        if (!ClashRuleTypes.some((t) => startsWith(strLine.v, t))) continue;
        finalOutput += "  - ";
        break;
      default:
        break;
    }
    if (handled) continue;

    let s = strLine.v;
    const lineSize = s.length;
    if (lineSize > 0 && s[lineSize - 1] === "\r") s = s.substring(0, s.length - 1);

    if (s.length > 0 && (s[0] !== ";" && s[0] !== "#" && !(s.length >= 2 && s[0] === "/" && s[1] === "/"))) {
      if (typeInt === 2) {
        if (startsWith(s, "IP-CIDR6")) s = "IP6-CIDR" + s.substring(8);
        s += "," + group;
        if (countLeast(s, ",", 3) && regReplace(s, ruleMatchRegex, "$2") === ",no-resolve")
          s = regReplace(s, ruleMatchRegex, "$1$3$2");
        else s = regReplace(s, ruleMatchRegex, "$1$3");
      }
    }
    finalOutput += s;
    finalOutput += "\n";
  }

  if (finalOutput === "payload:\n") {
    switch (typeInt) {
      case 3:
        finalOutput += "  - '--placeholder--'";
        break;
      case 4:
        finalOutput += "  - '0.0.0.0/32'";
        break;
      case 6:
        finalOutput += "  - 'DOMAIN,--placeholder--'";
        break;
    }
  }
  return { status: 200, body: finalOutput, headers: [] };
}

// filterLine shared state
let filterPosb = 0;
let filterPose = 0;

// ---------------- /surge2clash (interfaces.cpp:930-1141) ----------------

export async function surgeConfToClashHandler(req: SubRequest): Promise<SubResult> {
  const argument = req.argument;
  const joined = joinArguments(argument);
  const ini = new INIReader();
  const nodes: Proxy[] = [];
  let url = joined.length <= 5 ? "" : joined.substring(5);
  // Upstream gets request.params already percent-decoded from httplib, then joinArguments()
  // re-encodes them, so the "link=" value must be decoded again here.
  url = urlDecode(url);
  const proxygroupName = global.clashUseNewFieldName ? "proxy-groups" : "Proxy Group";
  const ruleName = global.clashUseNewFieldName ? "rules" : "Rule";

  ini.store_any_line = true;

  if (url.length === 0) url = global.defaultUrls.join("|");
  if (url.length === 0 || joined.substring(0, 5) !== "link=") {
    return { status: 400, body: "Invalid request!", headers: [] };
  }
  if (url === "link") {
    return { status: 400, body: "Please insert your subscription link instead of clicking the default link.", headers: [] };
  }

  let proxy = parseProxy(global.proxyConfig);
  const tplArgs = {
    global_vars: { ...global.templateVars },
    local_vars: { "clash.new_field_name": global.clashUseNewFieldName ? "true" : "false" },
    request_params: { target: "clash", url } as Record<string, string>,
  };

  const baseContent0 = await fetchFile(global.clashBase, proxy, global.enableCache ? global.cacheConfig : 0);
  const rendered = render_template(baseContent0, tplArgs, global.templatePath);
  if (rendered.ret !== 0) return { status: 400, body: rendered.output, headers: [] };
  const clash = loadYaml(rendered.output);
  if (!clash) return { status: 400, body: "base load failed", headers: [] };

  const baseContent = await fetchFile(url, proxy, global.enableCache ? global.cacheConfig : 0);

  if (ini.parse(baseContent) !== 0) {
    const errmsg = "Parsing Surge config failed! Reason: parse error";
    return { status: 400, body: errmsg, headers: [] };
  }
  if (!ini.sectionExist("Proxy") || !ini.sectionExist("Proxy Group") || !ini.sectionExist("Rule")) {
    return { status: 400, body: "Incomplete surge config! Missing critical sections!", headers: [] };
  }

  // scan groups first, get potential policy-path
  // The clash base template emits `proxy-groups:` with nothing under it, which YAML parses as null —
  // `null ?? []` keeps null and push() would throw, so coerce to a real array first.
  if (!Array.isArray(clash[proxygroupName])) clash[proxygroupName] = [];
  const section = ini.getItems("Proxy Group");
  const links: string[] = [url];
  for (const [name, content] of section) {
    const parts = split(content, ",");
    if (parts.length === 0) continue;
    const type = parts[0];
    if (!(type === "select" || type === "url-test" || type === "fallback" || type === "load-balance")) continue;
    const singlegroup: Record<string, unknown> = {};
    singlegroup["name"] = name;
    singlegroup["type"] = type;
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i];
      if (startsWith(p, "url")) singlegroup["url"] = trim(p.substring(p.indexOf("=") + 1));
      else if (startsWith(p, "interval")) singlegroup["interval"] = trim(p.substring(p.indexOf("=") + 1));
      else if (startsWith(p, "policy-path")) links.push(trim(p.substring(p.indexOf("=") + 1)));
      else {
        const proxies = (singlegroup["proxies"] as string[]) ?? [];
        proxies.push(trim(p));
        singlegroup["proxies"] = proxies;
      }
    }
    // Assignment is needed because the base template provides no array (YAML null); upstream's
    // clash[proxygroup_name] is a real YAML node, so this merely mirrors that shape. Note these
    // entries are replaced again by proxyToClashCore() below — upstream does the same, since it
    // passes an empty extra_proxy_group and proxyToClash always re-assigns proxy-groups.
    (clash[proxygroupName] as unknown[]).push(singlegroup);
  }

  proxy = parseProxy(global.proxySubscription);

  const subInfo = { v: "" };
  const parseSet = {
    proxy,
    exclude_remarks: [] as string[],
    include_remarks: [] as string[],
    stream_rules: [] as never[],
    time_rules: [] as never[],
    sub_info: subInfo.v,
    authorized: !global.apiMode,
    request_header: req.headers,
  };
  for (const x of links) {
    const r = await addNodes(x, nodes, 0, parseSet);
    if (r === -1) {
      if (global.skipFailedLinks) console.warn("The following link doesn't contain any valid node info: " + x);
      else return { status: 400, body: "The following link doesn't contain any valid node info: " + x, headers: [] };
    }
  }

  if (nodes.length === 0) return { status: 400, body: "No nodes were found!", headers: [] };

  const ext: extra_settings = newExtraSettings();
  ext.sort_flag = global.sortFlag;
  ext.filter_deprecated = global.filterDeprecated;
  ext.clash_new_field_name = global.clashUseNewFieldName;
  ext.udp = new tribool(global.UDPFlagSet);
  ext.tfo = new tribool(global.TFOFlag);
  ext.skip_cert_verify = new tribool(global.skipCertVerify);
  ext.tls13 = new tribool(global.TLS13Flag);
  ext.clash_proxies_style = global.clashProxiesStyle;

  proxyToClashCore(nodes, clash, [], false, ext);

  for (const [name, content] of ini.getItems("Proxy")) {
    const parts = split(content, ",");
    if (parts.length === 0) continue;
    const type = trim(parts[0]);
    let singlegroup: Record<string, unknown> | null = null;
    switch (type) {
      case "direct":
        singlegroup = { name, type: "select", proxies: ["DIRECT"] };
        break;
      case "reject":
      case "reject-tinygif":
        singlegroup = { name, type: "select", proxies: ["REJECT"] };
        break;
      default:
        continue;
    }
    // The base template leaves `proxy-groups:` empty (YAML null), so coerce once before pushing.
    (clash[proxygroupName] as unknown[]).push(singlegroup);
  }

  const ruleItems = ini.getAll("Rule", "{NONAME}");
  const rule: string[] = [];
  for (const x of ruleItems) {
    if (startsWith(x, "RULE-SET")) {
      const strArray = split(x, ",");
      if (strArray.length !== 3) continue;
      const content = await webGet(strArray[1], { cacheTTL: global.enableCache ? global.cacheRuleset : 0 });
      if (content.length === 0) continue;
      const delimiter = getLineBreak(content);
      for (let strLine of delimiter === "\n" ? content.split("\n") : content.split("\r")) {
        const lineSize = strLine.length;
        if (lineSize > 0 && strLine[lineSize - 1] === "\r") strLine = strLine.substring(0, lineSize - 1);
        if (strLine.length === 0 || strLine[0] === ";" || strLine[0] === "#" || (strLine.length >= 2 && strLine[0] === "/" && strLine[1] === "/")) continue;
        else if (!ClashRuleTypes.some((t) => startsWith(strLine, t))) continue;
        strLine += strArray[2];
        if (countLeast(strLine, ",", 3)) strLine = regReplace(strLine, "^(.*?,.*?)(,.*)(,.*)$", "$1$3$2");
        rule.push(strLine);
      }
      continue;
    } else if (!ClashRuleTypes.some((t) => startsWith(x, t))) continue;
    rule.push(x);
  }
  clash[ruleName] = rule;

  const headers: [string, string][] = [["profile-update-interval", String(Math.floor(global.configUpdateInterval / 3600))]];
  return { status: 200, body: yamlDump(clash), headers };
}

// ---------------- /getprofile (interfaces.cpp:1143-1232) ----------------

export async function getProfileHandler(req: SubRequest): Promise<SubResult> {
  const argument = [...req.argument];
  const name = argGet(argument, "name");
  let token = argGet(argument, "token");
  const profiles = split(name, "|");
  if (token.length === 0 || profiles.length === 0) {
    return { status: 403, body: "Forbidden", headers: [] };
  }
  let profileName = profiles[0];
  let profileContent: string;
  if (fileExist(profileName)) {
    profileContent = fileGet(profileName, true);
  } else {
    return { status: 404, body: "Profile not found", headers: [] };
  }
  const ini = new INIReader();
  if (ini.parse(profileContent) !== 0 && !ini.sectionExist("Profile")) {
    return { status: 500, body: "Broken profile!", headers: [] };
  }
  const contents = ini.getItems("Profile");
  if (contents.length === 0) {
    return { status: 500, body: "Broken profile!", headers: [] };
  }
  const profileToken = contents.find(([k]) => k === "profile_token");
  if (profiles.length === 1 && profileToken) {
    if (token !== profileToken[1]) {
      return { status: 403, body: "Forbidden", headers: [] };
    }
    token = global.accessToken;
  } else {
    if (token !== global.accessToken) {
      return { status: 403, body: "Forbidden", headers: [] };
    }
  }
  if (profiles.length > 1) {
    let allUrls = contents.find(([k]) => k === "url")?.[1] ?? "";
    for (let i = 1; i < profiles.length; i++) {
      profileName = profiles[i];
      if (!fileExist(profileName)) continue;
      const ini2 = new INIReader();
      if (ini2.parse(fileGet(profileName)) !== 0 && !ini2.sectionExist("Profile")) continue;
      const url = ini2.get("Profile", "url");
      if (url.length > 0) allUrls += "|" + url;
    }
    const urlIdx = contents.findIndex(([k]) => k === "url");
    if (urlIdx !== -1) contents[urlIdx] = ["url", allUrls];
    else contents.push(["url", allUrls]);
  }

  const newArgument: [string, string][] = [...contents.filter(([k]) => k !== "{NONAME}"), ["token", token], ["profile_data", base64Encode(global.managedConfigPrefix + "/getprofile?" + joinArguments(argument))], ...argument];
  req.argument = newArgument;
  return subconverter(req);
}

// ---------------- /render (interfaces.cpp:1387-1420) ----------------

export async function renderTemplateHandler(req: SubRequest): Promise<SubResult> {
  const argument = req.argument;
  const path = argGet(argument, "path");

  if (!startsWith(path, global.templatePath) || !fileExist(path)) {
    return { status: 404, body: "Not found", headers: [] };
  }
  const templateContent = await fetchFile(path, parseProxy(global.proxyConfig), global.enableCache ? global.cacheConfig : 0);
  if (templateContent.length === 0) {
    return { status: 400, body: "File empty or out of scope", headers: [] };
  }
  const tplArgs = {
    global_vars: { ...global.templateVars },
    request_params: Object.fromEntries(argument) as Record<string, string>,
    local_vars: {} as Record<string, string>,
  };
  const rendered = render_template(templateContent, tplArgs, global.templatePath);
  if (rendered.ret !== 0) {
    return { status: 400, body: rendered.output, headers: [] };
  }
  return { status: 200, body: rendered.output, headers: [] };
}
