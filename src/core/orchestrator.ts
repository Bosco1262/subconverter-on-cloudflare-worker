// Port of src/handler/interfaces.cpp subconverter() (lines 292-910) + matchUserAgent + parseProxy + importItems

import { Proxy, ProxyType } from "./proxy";
import { newExtraSettings, type extra_settings, type ProxyGroupConfig, type RulesetContent, RULESET_SURGE } from "./extra";
import { global, fetchFile, refreshRulesets, loadExternalConfig, newExternalConfig, fromIniRulesetConfs, type ExternalConfig } from "./settings";
import { addNodes, filterNodes, preprocessNodes } from "./nodemanip";
import { getSubInfoFromNodes, type RegexMatchConfigs } from "./info";
import { split, startsWith, toInt, join, strFind, getUrlArg } from "../lib/string";
import { urlEncode } from "../lib/urlencode";
import { base64Decode, urlSafeBase64Decode } from "../lib/base64";
import { regTrim, regValid } from "../lib/regex";
import { tribool } from "../lib/tribool";
import { proxyToClash, proxyToClashCore } from "./export/clash";
import { proxyToSurge } from "./export/surge";
import { proxyToSingle, proxyToSSSub, proxyToSSD } from "./export/single";
import { proxyToQuan, proxyToQuanX, proxyToMellow, proxyToLoon } from "./export/others";
import { proxyToSingBox } from "./export/singbox";
import { formatterShortId, generatePeer } from "./export/common";
import { render_template } from "./template";
import { loadYaml } from "../lib/yaml";
import { uploadGist } from "../lib/gist";
import { stringify as yamlDump } from "../lib/yaml-dump";
import { fileExist } from "../lib/vfs";
import type { RequestLike, ResponseLike } from "./http-bridge";
import { toProxyGroupConfigs } from "./settings";

export { generatePeer };

const gRegexBlacklist = ["(.*)*"];

function parseProxy(source: string): string {
  if (source === "SYSTEM") return ""; // system proxy unsupported on Workers
  if (source === "NONE") return "";
  return source;
}

// importItems (settings.cpp:24) — handle !!import: prefixed entries in url lists
async function importItems(items: string[], allowLocal: boolean): Promise<void> {
  for (let i = 0; i < items.length; i++) {
    if (!startsWith(items[i], "!!import:")) continue;
    const arg = items[i].substring(9);
    const content = await fetchFile(arg, global.proxySubscription, global.cacheConfig);
    if (content.length === 0) continue;
    const newItems = content
      .split(/\r?\n/)
      .map((x) => regTrim(x))
      .filter((x) => x.length > 0 && (allowLocal || isLocalPath(x) === false));
    items.splice(i, 1, ...newItems);
    i--;
  }
}

function isLocalPath(x: string): boolean {
  return !(x.startsWith("http://") || x.startsWith("https://") || x.startsWith("data:"));
}

interface UAProfile {
  head: string;
  versionMatch: string;
  versionTarget: string;
  target: string;
  clashNewName: tribool;
  surgeVer: number;
}

const UAMatchList: UAProfile[] = [
  { head: "ClashForAndroid", versionMatch: "\\/([0-9.]+)", versionTarget: "2.0", target: "clash", clashNewName: new tribool(true), surgeVer: -1 },
  { head: "ClashForAndroid", versionMatch: "\\/([0-9.]+)R", versionTarget: "", target: "clashr", clashNewName: new tribool(false), surgeVer: -1 },
  { head: "ClashForAndroid", versionMatch: "", versionTarget: "", target: "clash", clashNewName: new tribool(false), surgeVer: -1 },
  { head: "ClashforWindows", versionMatch: "\\/([0-9.]+)", versionTarget: "0.11", target: "clash", clashNewName: new tribool(true), surgeVer: -1 },
  { head: "ClashforWindows", versionMatch: "", versionTarget: "", target: "clash", clashNewName: new tribool(false), surgeVer: -1 },
  { head: "clash-verge", versionMatch: "", versionTarget: "", target: "clash", clashNewName: new tribool(true), surgeVer: -1 },
  { head: "ClashX Pro", versionMatch: "", versionTarget: "", target: "clash", clashNewName: new tribool(true), surgeVer: -1 },
  { head: "ClashX", versionMatch: "\\/([0-9.]+)", versionTarget: "0.13", target: "clash", clashNewName: new tribool(true), surgeVer: -1 },
  { head: "Clash", versionMatch: "", versionTarget: "", target: "clash", clashNewName: new tribool(true), surgeVer: -1 },
  { head: "Kitsunebi", versionMatch: "", versionTarget: "", target: "v2ray", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Loon", versionMatch: "", versionTarget: "", target: "loon", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Pharos", versionMatch: "", versionTarget: "", target: "mixed", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Potatso", versionMatch: "", versionTarget: "", target: "mixed", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Quantumult%20X", versionMatch: "", versionTarget: "", target: "quanx", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Quantumult", versionMatch: "", versionTarget: "", target: "quan", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Qv2ray", versionMatch: "", versionTarget: "", target: "v2ray", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Shadowrocket", versionMatch: "", versionTarget: "", target: "mixed", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Surfboard", versionMatch: "", versionTarget: "", target: "surfboard", clashNewName: new tribool(), surgeVer: -1 },
  { head: "Surge", versionMatch: "\\/([0-9.]+).*x86", versionTarget: "906", target: "surge", clashNewName: new tribool(false), surgeVer: 4 },
  { head: "Surge", versionMatch: "\\/([0-9.]+).*x86", versionTarget: "368", target: "surge", clashNewName: new tribool(false), surgeVer: 3 },
  { head: "Surge", versionMatch: "\\/([0-9.]+)", versionTarget: "1419", target: "surge", clashNewName: new tribool(false), surgeVer: 4 },
  { head: "Surge", versionMatch: "\\/([0-9.]+)", versionTarget: "900", target: "surge", clashNewName: new tribool(false), surgeVer: 3 },
  { head: "Surge", versionMatch: "", versionTarget: "", target: "surge", clashNewName: new tribool(false), surgeVer: 2 },
  { head: "Trojan-Qt5", versionMatch: "", versionTarget: "", target: "trojan", clashNewName: new tribool(), surgeVer: -1 },
  { head: "V2rayU", versionMatch: "", versionTarget: "", target: "v2ray", clashNewName: new tribool(), surgeVer: -1 },
  { head: "V2RayX", versionMatch: "", versionTarget: "", target: "v2ray", clashNewName: new tribool(), surgeVer: -1 },
];

function verGreaterEqual(srcVer: string, targetVer: string): boolean {
  const srcParts = srcVer.split(".").map((x) => toInt(x, 0));
  const tgtParts = targetVer.split(".").map((x) => toInt(x, 0));
  for (let i = 0; i < srcParts.length; i++) {
    if (i >= tgtParts.length) return true;
    if (srcParts[i] < tgtParts[i]) return false;
    if (srcParts[i] > tgtParts[i]) return true;
  }
  return srcParts.length >= tgtParts.length;
}

export function matchUserAgent(userAgent: string, refs: { target: { v: string }; clashNewName: tribool; surgeVer: { v: number } }): void {
  if (userAgent.length === 0) return;
  for (const x of UAMatchList) {
    if (startsWith(userAgent, x.head)) {
      if (x.versionMatch.length > 0) {
        const m = new RegExp(x.versionMatch).exec(userAgent);
        if (!m) continue;
        const version = m[1] ?? "";
        if (x.versionTarget.length > 0 && !verGreaterEqual(version, x.versionTarget)) continue;
      }
      refs.target.v = x.target;
      refs.clashNewName = x.clashNewName;
      if (x.surgeVer !== -1) refs.surgeVer.v = x.surgeVer;
      return;
    }
  }
}

export interface SubRequest {
  method: string;
  argument: [string, string][];
  headers: Map<string, string>;
  userAgent: string;
}

export interface SubResult {
  status: number;
  body: string;
  headers: [string, string][];
}

// multimap access helpers (std::multimap find = first value)
function argGet(argument: [string, string][], key: string): string {
  for (const [k, v] of argument) if (k === key) return v;
  return "";
}

export async function subconverter(req: SubRequest): Promise<SubResult> {
  const response: ResponseLike = { status: 200, headers: [] };
  const argument = req.argument;

  const argTarget = argGet(argument, "target");
  const argSurgeVer = argGet(argument, "ver");
  const argClashNewField = new tribool(argGet(argument, "new_name"));
  let intSurgeVer = argSurgeVer.length > 0 ? toInt(argSurgeVer, 3) : 3;
  const targetRef = { v: argTarget };
  const surgeVerRef = { v: intSurgeVer };
  if (argTarget === "auto") matchUserAgent(req.userAgent, { target: targetRef, clashNewName: argClashNewField, surgeVer: surgeVerRef });
  const target = targetRef.v;
  intSurgeVer = surgeVerRef.v;

  /// don't load groups/rulesets for simple subscription targets
  let lSimpleSubscription = false;
  switch (target) {
    case "ss":
    case "ssd":
    case "ssr":
    case "sssub":
    case "v2ray":
    case "trojan":
    case "mixed":
      lSimpleSubscription = true;
      break;
    case "clash":
    case "clashr":
    case "surge":
    case "quan":
    case "quanx":
    case "loon":
    case "surfboard":
    case "mellow":
    case "singbox":
    case "vless":
    case "hysteria2":
      break;
    default:
      return { status: 400, body: "Invalid target!", headers: [] };
  }

  /// string values
  let argUrl = argGet(argument, "url");
  const argGroupName = argGet(argument, "group");
  const argUploadPath = argGet(argument, "upload_path");
  const argIncludeRemark = argGet(argument, "include");
  const argExcludeRemark = argGet(argument, "exclude");
  const argCustomGroups = urlSafeBase64Decode(argGet(argument, "groups"));
  const argCustomRulesets = urlSafeBase64Decode(argGet(argument, "ruleset"));
  let argExternalConfig = argGet(argument, "config");
  const argDeviceID = argGet(argument, "dev_id");
  const argFilename = argGet(argument, "filename");
  const argUpdateInterval = argGet(argument, "interval");
  const argUpdateStrict = argGet(argument, "strict");
  const argRenames = argGet(argument, "rename");
  const argFilterScript = argGet(argument, "filter_script");

  /// switches with defaults
  const argUpload = new tribool(argGet(argument, "upload"));
  const argEmoji = new tribool(argGet(argument, "emoji"));
  const argAddEmoji = new tribool(argGet(argument, "add_emoji"));
  const argRemoveEmoji = new tribool(argGet(argument, "remove_emoji"));
  const argAppendType = new tribool(argGet(argument, "append_type"));
  const argTFO = new tribool(argGet(argument, "tfo"));
  const argUDP = new tribool(argGet(argument, "udp"));
  const argGenNodeList = new tribool(argGet(argument, "list"));
  const argSort = new tribool(argGet(argument, "sort"));
  const argUseSortScript = new tribool(argGet(argument, "sort_script"));
  const argGenClashScript = new tribool(argGet(argument, "script"));
  const argEnableInsert = new tribool(argGet(argument, "insert"));
  const argSkipCertVerify = new tribool(argGet(argument, "scv"));
  const argFilterDeprecated = new tribool(argGet(argument, "fdn"));
  const argExpandRulesets = new tribool(argGet(argument, "expand"));
  const argAppendUserinfo = new tribool(argGet(argument, "append_info"));
  const argPrependInsert = new tribool(argGet(argument, "prepend"));
  const argGenClassicalRuleProvider = new tribool(argGet(argument, "classic"));
  const argTLS13 = new tribool(argGet(argument, "tls13"));

  const lCustomProxyGroups: ProxyGroupConfig[] = [...global.customProxyGroups];
  const lCustomRulesets: [string, string, string, number][] = [...global.currentRulesets];
  let lIncludeRemarks = [...global.includeRemarks];
  let lExcludeRemarks = [...global.excludeRemarks];
  const lRulesetContent: RulesetContent[] = [];
  const ext: extra_settings = newExtraSettings();
  let subInfo = "";
  const interval = argUpdateInterval.length > 0 ? toInt(argUpdateInterval, global.configUpdateInterval) : global.configUpdateInterval;
  const authorized = !global.apiMode || argGet(argument, "token") === global.accessToken;
  const strict = argUpdateStrict.length > 0 ? argUpdateStrict === "true" : global.configUpdateStrict;

  if (gRegexBlacklist.includes(argIncludeRemark) || gRegexBlacklist.includes(argExcludeRemark)) {
    return { status: 200, body: "Invalid request!", headers: [] };
  }

  /// base configs
  let lClashBase = global.clashBase, lSurgeBase = global.surgeBase, lMellowBase = global.mellowBase;
  let lSurfboardBase = global.surfboardBase;
  let lQuanBase = global.quanBase, lQuanXBase = global.quanXBase, lLoonBase = global.loonBase;
  let lSSSubBase = global.SSSubBase;
  let lSingBoxBase = global.singBoxBase;

  /// validate urls
  argEnableInsert.define(global.enableInsert);
  if (argUrl.length === 0 && (!global.apiMode || authorized)) argUrl = global.defaultUrls.join("|");
  if ((argUrl.length === 0 && !(global.insertUrls.length > 0 && global.insertUrls[0] !== "" && argEnableInsert.get())) || target.length === 0) {
    return { status: 400, body: "Invalid request!", headers: [] };
  }

  /// request args as template variables
  const reqArgMap: Record<string, string> = {};
  for (const [k, v] of argument) {
    if (k === "token") continue;
    if (!(k in reqArgMap)) reqArgMap[k] = v;
  }
  reqArgMap["target"] = target;
  reqArgMap["ver"] = String(intSurgeVer);

  const tplArgs = {
    global_vars: { ...global.templateVars },
    request_params: reqArgMap,
    local_vars: {} as Record<string, string>,
  };

  let proxy = parseProxy(global.proxySubscription);

  /// flags
  ext.authorized = authorized;
  ext.append_proxy_type = argAppendType.get(global.appendProxyType);
  if ((target === "clash" || target === "clashr") && argGenClashScript.isUndef()) argExpandRulesets.define(true);

  ext.clash_proxies_style = global.clashProxiesStyle;
  ext.clash_proxy_groups_style = global.clashProxyGroupsStyle;

  ext.tfo.define(argTFO).define(global.TFOFlag);
  ext.udp.define(argUDP).define(global.UDPFlagSet);
  ext.skip_cert_verify.define(argSkipCertVerify).define(global.skipCertVerify);
  ext.tls13.define(argTLS13).define(global.TLS13Flag);

  ext.sort_flag = argSort.get(global.sortFlag);
  argUseSortScript.define(global.sortScript.length > 0);
  if (ext.sort_flag && argUseSortScript.get()) ext.sort_script = global.sortScript;
  ext.filter_deprecated = argFilterDeprecated.get(global.filterDeprecated);
  ext.clash_new_field_name = argClashNewField.get(global.clashUseNewFieldName);
  ext.clash_script = argGenClashScript.get();
  ext.clash_classical_ruleset = argGenClassicalRuleProvider.get();
  if (!argExpandRulesets.get() && !argExpandRulesets.isUndef()) ext.clash_new_field_name = true;
  else ext.clash_script = false;

  ext.nodelist = argGenNodeList.get();
  ext.surge_ssr_path = global.surgeSSRPath;
  ext.quanx_dev_id = argDeviceID.length > 0 ? argDeviceID : global.quanxDeviceId;
  ext.enable_rule_generator = global.enableRuleGen;
  ext.overwrite_original_rules = global.overwriteOriginalRules;
  if (!argExpandRulesets.get() && !argExpandRulesets.isUndef()) ext.managed_config_prefix = global.managedConfigPrefix;

  /// load external configuration
  if (argExternalConfig.length === 0) argExternalConfig = global.defaultExternalConfig;
  if (argExternalConfig.length > 0) {
    const extconf = newExternalConfig();
    if (await loadExternalConfig(argExternalConfig, extconf)) {
      if (!ext.nodelist) {
        checkExternalBase(extconf.ssSubBase, (v) => (lSSSubBase = v));
        if (!lSimpleSubscription) {
          checkExternalBase(extconf.clashRuleBase, (v) => (lClashBase = v));
          checkExternalBase(extconf.surgeRuleBase, (v) => (lSurgeBase = v));
          checkExternalBase(extconf.surfboardRuleBase, (v) => (lSurfboardBase = v));
          checkExternalBase(extconf.mellowRuleBase, (v) => (lMellowBase = v));
          checkExternalBase(extconf.quanRuleBase, (v) => (lQuanBase = v));
          checkExternalBase(extconf.quanXRuleBase, (v) => (lQuanXBase = v));
          checkExternalBase(extconf.loonRuleBase, (v) => (lLoonBase = v));
          checkExternalBase(extconf.singBoxBase, (v) => (lSingBoxBase = v));
          if (extconf.customRulesets.length > 0) {
            lCustomRulesets.length = 0;
            lCustomRulesets.push(...extconf.customRulesets);
          }
          if (extconf.customProxyGroups.length > 0) {
            lCustomProxyGroups.length = 0;
            lCustomProxyGroups.push(...extconf.customProxyGroups);
          }
          ext.enable_rule_generator = extconf.enableRuleGen;
          ext.overwrite_original_rules = extconf.overwriteOriginalRules;
        }
      }
      if (extconf.rename.length > 0) ext.rename_array = extconf.rename;
      if (extconf.emoji.length > 0) ext.emoji_array = extconf.emoji;
      if (extconf.include.length > 0) lIncludeRemarks = extconf.include;
      if (extconf.exclude.length > 0) lExcludeRemarks = extconf.exclude;
      argAddEmoji.define(extconf.addEmoji ?? new tribool());
      argRemoveEmoji.define(extconf.removeEmoji ?? new tribool());
    }
  } else {
    if (!lSimpleSubscription) {
      // loading custom groups/rulesets from base64 INI args
      if (argCustomGroups.length > 0 && !ext.nodelist) {
        const vArray = split(argCustomGroups, "@");
        lCustomProxyGroups.push(...fromIniProxyGroups(vArray));
      }
      if (argCustomRulesets.length > 0 && !ext.nodelist) {
        const vArray = split(argCustomRulesets, "@");
        lCustomRulesets.push(...fromIniRulesets(vArray));
      }
    }
  }
  if (ext.enable_rule_generator && !ext.nodelist && !lSimpleSubscription) {
    await refreshRulesets(lCustomRulesets.length > 0 ? lCustomRulesets : global.currentRulesets, lRulesetContent);
  }

  if (!argEmoji.isUndef()) {
    argAddEmoji.set(argEmoji.get());
    argRemoveEmoji.set(true);
  }
  ext.add_emoji = argAddEmoji.get(global.addEmoji);
  ext.remove_emoji = argRemoveEmoji.get(global.removeEmoji);
  if (ext.add_emoji && ext.emoji_array.length === 0) ext.emoji_array = global.emojis;
  if (argRenames.length > 0) {
    ext.rename_array = fromIniRename(split(argRenames, "`"));
  } else if (ext.rename_array.length === 0) ext.rename_array = global.renames;

  /// custom include/exclude
  if (argIncludeRemark.length > 0 && regValid(argIncludeRemark)) lIncludeRemarks = [argIncludeRemark];
  if (argExcludeRemark.length > 0 && regValid(argExcludeRemark)) lExcludeRemarks = [argExcludeRemark];

  /// start parsing urls
  const streamTemp: RegexMatchConfigs = global.streamNodeRules;
  const timeTemp: RegexMatchConfigs = global.timeNodeRules;

  const urls: string[] = [];
  const nodes: Proxy[] = [];
  const insertNodes: Proxy[] = [];
  let groupID = 0;

  const parseSet = {
    proxy,
    exclude_remarks: lExcludeRemarks,
    include_remarks: lIncludeRemarks,
    stream_rules: streamTemp,
    time_rules: timeTemp,
    sub_info: "",
    authorized,
    request_header: req.headers,
  };

  // MAX_NODES is this port's own fuse (upstream has no max_allowed_nodes at all — it exists to
  // protect the free-plan CPU budget). Checking only BEFORE addNodes meant a single subscription
  // could contribute unlimited nodes, so the limit is now enforced after every fetch as well.
  const overNodeLimit = (list: Proxy[]): boolean => {
    if (global.maxAllowedNodes > 0 && list.length > global.maxAllowedNodes) {
      console.warn("Node limit reached (" + global.maxAllowedNodes + "); truncating node list.");
      list.length = global.maxAllowedNodes;
      return true;
    }
    return false;
  };

  if (global.insertUrls.length > 0 && global.insertUrls[0] !== "" && argEnableInsert.get()) {
    groupID = -1;
    urls.push(...split(global.insertUrls.join("|"), "|"));
    await importItems(urls, true);
    for (const x0 of urls) {
      const x = regTrim(x0);
      if (x.length === 0) continue;
      if (overNodeLimit(insertNodes)) break;
      const r = await addNodes(x, insertNodes, groupID, parseSet);
      if (r === -1) {
        if (global.skipFailedLinks) console.warn("The following link doesn't contain any valid node info: " + x);
        else return { status: 400, body: "The following link doesn't contain any valid node info: " + x, headers: [] };
      }
      groupID--;
    }
    overNodeLimit(insertNodes);
  }
  urls.length = 0;
  urls.push(...split(argUrl, "|"));
  await importItems(urls, true);
  groupID = 0;
  for (const x0 of urls) {
    const x = regTrim(x0);
    if (x.length === 0) continue;
    if (overNodeLimit(nodes)) break;
    const r = await addNodes(x, nodes, groupID, parseSet);
    if (r === -1) {
      if (global.skipFailedLinks) console.warn("The following link doesn't contain any valid node info: " + x);
      else return { status: 400, body: "The following link doesn't contain any valid node info: " + x, headers: [] };
    }
    groupID++;
  }
  overNodeLimit(nodes);
  if (nodes.length === 0 && insertNodes.length === 0) {
    return { status: 400, body: "No nodes were found!", headers: [] };
  }
  subInfo = parseSet.sub_info;
  if (subInfo.length > 0 && argAppendUserinfo.get(global.appendSubUserinfo)) {
    response.headers.push(["Subscription-UserInfo", subInfo]);
  }

  if (req.method === "HEAD") {
    return { status: response.status, body: "", headers: response.headers };
  }

  argPrependInsert.define(global.prependInsert);
  if (argPrependInsert.get()) {
    insertNodes.push(...nodes);
    nodes.length = 0;
    nodes.push(...insertNodes);
  } else {
    nodes.push(...insertNodes);
  }

  // filter scripts skipped (NO_JS_RUNTIME)

  if (argGroupName.length > 0) for (const x of nodes) x.Group = argGroupName;

  preprocessNodes(nodes, ext);

  let managedUrl = base64Decode(argGet(argument, "profile_data"));
  if (managedUrl.length === 0) managedUrl = global.managedConfigPrefix + "/sub?" + joinArguments(argument);

  proxy = parseProxy(global.proxyConfig);
  let outputContent = "";

  const renderBase = async (base: string): Promise<string | null> => {
    const content = await fetchFile(base, proxy, global.enableCache ? global.cacheConfig : 0);
    const r = render_template(content, tplArgs, global.templatePath);
    if (r.ret !== 0) {
      return r.output; // error text
    }
    return r.output;
  };

  switch (target) {
    case "clash":
    case "clashr": {
      tplArgs.local_vars["clash.new_field_name"] = ext.clash_new_field_name ? "true" : "false";
      response.headers.push(["profile-update-interval", String(Math.floor(interval / 3600))]);
      if (ext.nodelist) {
        const yamlnode: Record<string, unknown> = {};
        proxyToClashCore(nodes, yamlnode, [], target === "clashr", ext);
        outputContent = formatterShortId(yamlDump(yamlnode));
      } else {
        const rendered = await renderBase(lClashBase);
        if (rendered === null) {
          return { status: 400, body: "", headers: response.headers };
        }
        if (renderBaseFailed(rendered)) {
          return { status: 400, body: rendered, headers: response.headers };
        }
        outputContent = proxyToClash(nodes, rendered, lRulesetContent, lCustomProxyGroups, target === "clashr", ext);
      }
      if (argUpload.get()) await uploadGist(target, argUploadPath, outputContent, false);
      break;
    }
    case "surge": {
      if (ext.nodelist) {
        outputContent = proxyToSurge(nodes, "", [], [], intSurgeVer, { ...ext, nodelist: true });
        if (argUpload.get()) await uploadGist("surge" + argSurgeVer + "list", argUploadPath, outputContent, true);
      } else {
        const rendered = await renderBase(lSurgeBase);
        if (rendered === null || renderBaseFailed(rendered)) {
          return { status: 400, body: rendered ?? "", headers: response.headers };
        }
        outputContent = proxyToSurge(nodes, rendered, lRulesetContent, lCustomProxyGroups, intSurgeVer, ext);
        if (argUpload.get()) await uploadGist("surge" + argSurgeVer, argUploadPath, outputContent, true);
        if (global.writeManagedConfig && global.managedConfigPrefix.length > 0) {
          outputContent = "#!MANAGED-CONFIG " + managedUrl + (interval ? " interval=" + interval : "") + " strict=" + (strict ? "true" : "false") + "\n\n" + outputContent;
        }
      }
      break;
    }
    case "surfboard": {
      const rendered = await renderBase(lSurfboardBase);
      if (rendered === null || renderBaseFailed(rendered)) {
        return { status: 400, body: rendered ?? "", headers: response.headers };
      }
      outputContent = proxyToSurge(nodes, rendered, lRulesetContent, lCustomProxyGroups, -3, ext);
      if (argUpload.get()) await uploadGist("surfboard", argUploadPath, outputContent, true);
      if (global.writeManagedConfig && global.managedConfigPrefix.length > 0) {
        outputContent = "#!MANAGED-CONFIG " + managedUrl + (interval ? " interval=" + interval : "") + " strict=" + (strict ? "true" : "false") + "\n\n" + outputContent;
      }
      break;
    }
    case "mellow": {
      const rendered = await renderBase(lMellowBase);
      if (rendered === null || renderBaseFailed(rendered)) {
        return { status: 400, body: rendered ?? "", headers: response.headers };
      }
      outputContent = proxyToMellow(nodes, rendered, lRulesetContent, lCustomProxyGroups, ext);
      if (argUpload.get()) await uploadGist("mellow", argUploadPath, outputContent, true);
      break;
    }
    case "sssub": {
      const rendered = await renderBase(lSSSubBase);
      if (rendered === null || renderBaseFailed(rendered)) {
        return { status: 400, body: rendered ?? "", headers: response.headers };
      }
      outputContent = proxyToSSSub(rendered, nodes, ext);
      if (argUpload.get()) await uploadGist("sssub", argUploadPath, outputContent, false);
      break;
    }
    case "ss":
      outputContent = proxyToSingle(nodes, 1, ext);
      // upstream uploads these single-format targets too (interfaces.cpp:795-831); the port only did
      // so for the config-style targets, so ?upload=true silently did nothing here.
      if (argUpload.get()) await uploadGist("ss", argUploadPath, outputContent, false);
      break;
    case "ssr":
      outputContent = proxyToSingle(nodes, 2, ext);
      if (argUpload.get()) await uploadGist("ssr", argUploadPath, outputContent, false);
      break;
    case "v2ray":
      outputContent = proxyToSingle(nodes, 4, ext);
      if (argUpload.get()) await uploadGist("v2ray", argUploadPath, outputContent, false);
      break;
    case "trojan":
      outputContent = proxyToSingle(nodes, 8, ext);
      if (argUpload.get()) await uploadGist("trojan", argUploadPath, outputContent, false);
      break;
    case "vless":
      // NOTE: upstream passes 16 here, which via GETBIT 1-based maps to hysteria2 flag — bug-compatible port
      outputContent = proxyToSingle(nodes, 16, ext);
      if (argUpload.get()) await uploadGist("vless", argUploadPath, outputContent, false);
      break;
    case "hysteria2":
      outputContent = proxyToSingle(nodes, 32, ext);
      if (argUpload.get()) await uploadGist("hysteria2", argUploadPath, outputContent, false);
      break;
    case "mixed":
      outputContent = proxyToSingle(nodes, 63, ext);
      if (argUpload.get()) await uploadGist("sub", argUploadPath, outputContent, false);
      break;
    case "quan": {
      let baseContent = "";
      if (!ext.nodelist) {
        const rendered = await renderBase(lQuanBase);
        if (rendered === null || renderBaseFailed(rendered)) {
          return { status: 400, body: rendered ?? "", headers: response.headers };
        }
        baseContent = rendered;
      }
      outputContent = proxyToQuan(nodes, baseContent, lRulesetContent, lCustomProxyGroups, ext);
      if (argUpload.get()) await uploadGist("quan", argUploadPath, outputContent, false);
      break;
    }
    case "quanx": {
      let baseContent = "";
      if (!ext.nodelist) {
        const rendered = await renderBase(lQuanXBase);
        if (rendered === null || renderBaseFailed(rendered)) {
          return { status: 400, body: rendered ?? "", headers: response.headers };
        }
        baseContent = rendered;
      }
      outputContent = proxyToQuanX(nodes, baseContent, lRulesetContent, lCustomProxyGroups, ext);
      if (argUpload.get()) await uploadGist("quanx", argUploadPath, outputContent, false);
      break;
    }
    case "loon": {
      let baseContent = "";
      if (!ext.nodelist) {
        const rendered = await renderBase(lLoonBase);
        if (rendered === null || renderBaseFailed(rendered)) {
          return { status: 400, body: rendered ?? "", headers: response.headers };
        }
        baseContent = rendered;
      }
      outputContent = proxyToLoon(nodes, baseContent, lRulesetContent, lCustomProxyGroups, ext);
      if (argUpload.get()) await uploadGist("loon", argUploadPath, outputContent, false);
      break;
    }
    case "ssd":
      outputContent = proxyToSSD(nodes, argGroupName, subInfo, ext);
      if (argUpload.get()) await uploadGist("ssd", argUploadPath, outputContent, false);
      break;
    case "singbox": {
      let baseContent = "";
      if (!ext.nodelist) {
        const rendered = await renderBase(lSingBoxBase);
        if (rendered === null || renderBaseFailed(rendered)) {
          return { status: 400, body: rendered ?? "", headers: response.headers };
        }
        baseContent = rendered;
      }
      outputContent = proxyToSingBox(nodes, baseContent, lRulesetContent, lCustomProxyGroups, ext);
      if (argUpload.get()) await uploadGist("singbox", argUploadPath, outputContent, false);
      break;
    }
    default:
      return { status: 500, body: "Unrecognized target", headers: response.headers };
  }

  if (argFilename.length > 0) {
    response.headers.push(["Content-Disposition", 'attachment; filename="' + argFilename + '"; filename*=utf-8\'\'' + urlEncode(argFilename)]);
  }
  return { status: response.status, body: outputContent, headers: response.headers };
}

function renderBaseFailed(output: string): boolean {
  return output.startsWith("Template render failed!");
}

function checkExternalBase(path: string, dest: (v: string) => void): void {
  if (isLinkPath(path) || (startsWith(path, global.basePath) && localFileExists(path))) dest(path);
}

function isLinkPath(path: string): boolean {
  return path.startsWith("http://") || path.startsWith("https://") || path.startsWith("data:");
}

function localFileExists(path: string): boolean {
  return fileExist(path);
}

function joinArguments(args: [string, string][]): string {
  let out = "";
  for (const [k, v] of args) {
    out += k + "=" + urlEncode(v) + "&";
  }
  if (out.length > 0) out = out.substring(0, out.length - 1);
  return out;
}

// INIBinding::from<ProxyGroupConfig>::from_ini equivalent
function fromIniProxyGroups(lines: string[]): ProxyGroupConfig[] {
  // format: name,type,rule1,rule2...  (with option k=v pairs at end)
  const groups: Record<string, unknown>[] = [];
  for (const line of lines) {
    if (line.length === 0) continue;
    if (startsWith(line, "import:")) continue;
    const parts = split(line, ",");
    if (parts.length < 2) continue;
    const name = parts[0].trim();
    const type = parts[1].trim();
    const rule: string[] = [];
    const extras: Record<string, string> = {};
    for (let i = 2; i < parts.length; i++) {
      const p = parts[i].trim();
      const eq = p.indexOf("=");
      if (eq > 0 && !p.startsWith("[]")) {
        const k = p.substring(0, eq).trim();
        const v = p.substring(eq + 1).trim();
        switch (k) {
          case "url": extras["url"] = v; continue;
          case "interval": extras["interval"] = v; continue;
          case "tolerance": extras["tolerance"] = v; continue;
          case "timeout": extras["timeout"] = v; continue;
          case "strategy": extras["strategy"] = v; continue;
          case "lazy": extras["lazy"] = v; continue;
          case "disable_udp": extras["disable_udp"] = v; continue;
        }
      }
      rule.push(p);
    }
    groups.push({ name, type, rule, ...extras });
  }
  return toProxyGroupConfigs(groups);
}

function fromIniRulesets(lines: string[]): [string, string, string, number][] {
  return fromIniRulesetConfs(lines).map(([group, ruleset, interval]) => [group, ruleset, "", interval]);
}

function fromIniRename(lines: string[]): RegexMatchConfigs {
  const out: RegexMatchConfigs = [];
  for (const line of lines) {
    const at = line.lastIndexOf("@");
    if (at === -1) continue;
    out.push({ Match: line.substring(0, at), Replace: line.substring(at + 1), Script: "" });
  }
  return out;
}

export { RULESET_SURGE, strFind, ProxyType, base64Decode };
