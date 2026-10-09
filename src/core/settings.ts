// Port of src/handler/settings.h — global settings struct (Workers: single global per isolate)

export interface Settings {
  listenAddress: string;
  listenPort: number;
  maxPendingConns: number;
  maxConcurThreads: number;
  serveFile: boolean;
  serveFileRoot: string;
  requireAuth: boolean;
  authUser: string;
  authPassword: string;
  skipFailedLinks: boolean;
  prependInsert: boolean;
  asyncFetchRuleset: boolean;
  maxAllowedRulesets: number;
  maxAllowedRulesetsSize: number;
  maxAllowedRules: number;
  apiMode: boolean;
  apiAccessToken: string;
  defaultUrls: string[];
  enableInsert: boolean;
  insertUrls: string[];
  excludeRemarks: string[];
  includeRemarks: string[];
  enableFilter: boolean;
  defaultExternalConfig: string;
  appendSubUserinfo: boolean;
  configUpdateInterval: number;
  configUpdateStrict: boolean;
  quanxDeviceId: string;
  templateVars: Record<string, string>;
  aliases: { uri: string; target: string }[];
  logLevel: number;
  currentRulesets: [string, string, string, number][]; // group, path, format?, interval
  // extra runtime flags set by readConf (tribool: undef = not set, like upstream)
  UDPFlagSet: tribool;
  TFOFlag: tribool;
  skipCertVerify: tribool;
  TLS13Flag: tribool;
  sortFlag: boolean;
  clashUseNewFieldName: boolean;
  clashProxiesStyle: string;
  clashProxyGroupsStyle: string;
  addEmoji: boolean;
  removeEmoji: boolean;
  surgeSSRPath: string;
  appendProxyType: boolean;
  enableCache: boolean;
  emojiCache?: unknown;
  maxAllowedDownloadSize: number;
  updateRulesetOnRequest: boolean;
  enableRuleGen: boolean;
  overwriteOriginalRules: boolean;
  reloadConfOnRequest: boolean;
  filterDeprecated: boolean;
  cacheSubscription: number;
  cacheConfig: number;
  cacheRuleset: number;
  surgeResolveHostname: boolean;
  singBoxAddClashModes: boolean;
  scriptCleanContext: boolean;
  basePath: string;
  templatePath: string;
  customRulesets: [string, string, string, number][];
  customProxyGroups: ProxyGroupConfig[];
  renames: { Match: string; Replace: string; Script: string }[];
  emojis: { Match: string; Replace: string; Script: string }[];
  streamNodeRules: { Match: string; Replace: string; Script: string }[];
  timeNodeRules: { Match: string; Replace: string; Script: string }[];
  proxyConfig: string;
  proxyRuleset: string;
  proxySubscription: string;
  managedConfigPrefix: string;
  managedConfigAppend: boolean;
  accessToken: string;
  filterScript: string;
  sortScript: string;
  clashBase: string;
  surgeBase: string;
  surfboardBase: string;
  mellowBase: string;
  quanBase: string;
  quanXBase: string;
  loonBase: string;
  SSSubBase: string;
  singBoxBase: string;
  defaultPreferredConfig: string;
  uploadGist: boolean;
  gistConfPath: string;
  prefPath: string;
  writeManagedConfig: boolean;
  maxAllowedNodes: number;
  enableCron: boolean;
}

export const global: Settings = {  listenAddress: "127.0.0.1",
  listenPort: 25500,
  maxPendingConns: 10,
  maxConcurThreads: 4,
  serveFile: false,
  serveFileRoot: "",
  requireAuth: false,
  authUser: "",
  authPassword: "",
  skipFailedLinks: false,
  prependInsert: false,
  asyncFetchRuleset: false,
  maxAllowedRulesets: 64,
  maxAllowedRulesetsSize: 0,
  maxAllowedRules: 0,
  maxAllowedNodes: 0,
  apiMode: false,
  apiAccessToken: "",
  defaultUrls: [],
  enableInsert: true,
  insertUrls: [""],
  excludeRemarks: [],
  includeRemarks: [],
  enableFilter: false,
  filterScript: "",
  defaultExternalConfig: "",
  appendSubUserinfo: true,
  configUpdateInterval: 86400,
  configUpdateStrict: false,
  quanxDeviceId: "",
  templateVars: {},
  aliases: [],
  logLevel: 2,
  currentRulesets: [],
  UDPFlagSet: new tribool(),
  TFOFlag: new tribool(),
  skipCertVerify: new tribool(),
  TLS13Flag: new tribool(),
  sortFlag: false,
  clashUseNewFieldName: true,
  clashProxiesStyle: "flow",
  clashProxyGroupsStyle: "block",
  addEmoji: false,
  removeEmoji: true,
  surgeSSRPath: "",
  appendProxyType: false,
  enableCache: true,
  writeManagedConfig: true,
  maxAllowedDownloadSize: 1048576,
  updateRulesetOnRequest: false,
  enableRuleGen: true,
  overwriteOriginalRules: true,
  reloadConfOnRequest: false,
  filterDeprecated: false,
  cacheSubscription: 60,
  cacheConfig: 300,
  cacheRuleset: 21600,
  surgeResolveHostname: false,
  singBoxAddClashModes: false,
  scriptCleanContext: true,
  basePath: "base",
  templatePath: "templates",
  customRulesets: [],
  customProxyGroups: [],
  renames: [],
  emojis: [],
  streamNodeRules: [],
  timeNodeRules: [],
  proxyConfig: "",
  proxyRuleset: "",
  proxySubscription: "",
  managedConfigPrefix: "",
  managedConfigAppend: false,
  accessToken: "",
  sortScript: "",
  clashBase: "base/all_base.tpl",
  surgeBase: "base/all_base.tpl",
  surfboardBase: "base/all_base.tpl",
  mellowBase: "base/all_base.tpl",
  quanBase: "base/all_base.tpl",
  quanXBase: "base/all_base.tpl",
  loonBase: "base/all_base.tpl",
  SSSubBase: "base/all_base.tpl",
  singBoxBase: "base/all_base.tpl",
  defaultPreferredConfig: "",
  uploadGist: false,
  gistConfPath: "",
  prefPath: "pref.toml",
  enableCron: false,
};

// ---- config loading (port of readConf / loadExternalConfig / refreshRulesets) ----

import { parse as tomlParse } from "smol-toml";
import { loadYaml } from "../lib/yaml";
import { INIReader } from "../lib/ini";
import { fileGet, fileExist } from "../lib/vfs";
import { webGet } from "../lib/fetch";
import type { RegexMatchConfigs } from "./info";
import type { ProxyGroupConfigs } from "./extra";
import { ProxyGroupType, BalanceStrategy, RULESET_SURGE } from "./extra";
import type { ProxyGroupConfig, RulesetContent } from "./extra";
import { tribool } from "../lib/tribool";
import { toInt } from "../lib/string";

export interface ExternalConfig {
  customRulesets: [string, string, string, number][];
  customProxyGroups: ProxyGroupConfig[];
  clashRuleBase: string;
  surgeRuleBase: string;
  surfboardRuleBase: string;
  mellowRuleBase: string;
  quanRuleBase: string;
  quanXRuleBase: string;
  loonRuleBase: string;
  ssSubBase: string;
  singBoxBase: string;
  rename: RegexMatchConfigs;
  emoji: RegexMatchConfigs;
  include: string[];
  exclude: string[];
  enableRuleGen: boolean;
  overwriteOriginalRules: boolean;
  managedConfigPrefix: string;
  addEmoji?: tribool;
  removeEmoji?: tribool;
  baseConf: string;
}

export function newExternalConfig(): ExternalConfig {
  return {
    customRulesets: [],
    customProxyGroups: [],
    clashRuleBase: "",
    surgeRuleBase: "",
    surfboardRuleBase: "",
    mellowRuleBase: "",
    quanRuleBase: "",
    quanXRuleBase: "",
    loonRuleBase: "",
    ssSubBase: "",
    singBoxBase: "",
    rename: [],
    emoji: [],
    include: [],
    exclude: [],
    enableRuleGen: true,
    overwriteOriginalRules: false,
    managedConfigPrefix: "",
    baseConf: "",
  };
}

function asStrArr(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x));
  if (v === undefined || v === null) return [];
  return [String(v)];
}

// fetchFile: local (VFS) or remote (webGet) — port of multithread.cpp fetchFile
export async function fetchFile(path: string, proxy: string, cacheTTL: number): Promise<string> {
  if (fileExist(path)) return fileGet(path);
  if (path.startsWith("http://") || path.startsWith("https://") || path.startsWith("data:")) {
    return webGet(path, { proxy: proxyNorm(proxy), cacheTTL });
  }
  return "";
}

function proxyNorm(p: string): string {
  // SYSTEM proxy unsupported on Workers; NONE/empty → no proxy
  if (p === "SYSTEM" || p === "NONE" || p.length === 0) return "";
  return p;
}

async function importArrayItems(list: { import?: string }[], proxy: string): Promise<{ import?: string }[]> {
  // handle `import = "path"` entries inside array-of-tables
  const result: { import?: string }[] = [];
  for (const item of list) {
    if (item && typeof item.import === "string") {
      const content = await fetchFile(item.import, proxy, global.cacheConfig);
      const imported = parseTomlLike(content);
      if (Array.isArray(imported)) result.push(...(imported as { import?: string }[]));
      else if (imported && typeof imported === "object") {
        // TOML snippets use [[emoji]]/[[custom_groups]] headers — take the first array value
        const firstArray = Object.values(imported).find((v) => Array.isArray(v));
        if (firstArray) result.push(...(firstArray as { import?: string }[]));
      }
      continue;
    }
    result.push(item);
  }
  return result;
}

function parseTomlLike(content: string): unknown {
  try {
    return tomlParse(content);
  } catch {
    try {
      const parsed = loadYaml(content);
      if (parsed) return parsed;
    } catch {
      /* ignore */
    }
    try {
      return JSON.parse(content);
    } catch {
      return null;
    }
  }
}

function toRegexMatchConfigs(v: unknown): RegexMatchConfigs {
  const out: RegexMatchConfigs = [];
  if (!Array.isArray(v)) return out;
  for (const item of v) {
    if (!item || typeof item !== "object") continue;
    const m = item as Record<string, unknown>;
    out.push({ Match: String(m.match ?? ""), Replace: String(m.replace ?? ""), Script: String(m.script ?? "") });
  }
  return out;
}

export async function readYAMLConf(content: string): Promise<boolean> {
  const conf = loadYaml(content);
  if (!conf) return false;
  return applyParsedConf(conf as Record<string, unknown>, "yaml");
}

export async function readTOMLConf(content: string): Promise<boolean> {
  let conf: Record<string, unknown>;
  try {
    conf = tomlParse(content) as Record<string, unknown>;
  } catch {
    return false;
  }
  return applyParsedConf(conf, "toml");
}

async function applyParsedConf(conf: Record<string, unknown>, _format: string): Promise<boolean> {
  void _format;
  const common = (conf.common ?? {}) as Record<string, unknown>;
  const nodePref = (conf.node_pref ?? {}) as Record<string, unknown>;
  const managed = (conf.managed_config ?? {}) as Record<string, unknown>;
  const surgeExt = (conf.surge_external_proxy ?? {}) as Record<string, unknown>;
  const emojis = (conf.emojis ?? {}) as Record<string, unknown>;
  const ruleset = (conf.ruleset ?? {}) as Record<string, unknown>;
  const template = (conf.template ?? {}) as Record<string, unknown>;
  const userinfo = (conf.userinfo ?? {}) as Record<string, unknown>;
  const aliases = conf.aliases;
  const server = (conf.server ?? {}) as Record<string, unknown>;
  const advanced = (conf.advanced ?? {}) as Record<string, unknown>;

  if ("api_mode" in common) global.apiMode = common.api_mode === true;
  if ("api_access_token" in common) global.accessToken = String(common.api_access_token ?? "");
  global.defaultUrls = asStrArr(common.default_url);
  if ("enable_insert" in common) global.enableInsert = common.enable_insert !== false;
  global.insertUrls = asStrArr(common.insert_url);
  if ("prepend_insert_url" in common) global.prependInsert = common.prepend_insert_url === true;
  global.excludeRemarks = asStrArr(common.exclude_remarks);
  global.includeRemarks = asStrArr(common.include_remarks);
  if ("enable_filter" in common) global.enableFilter = common.enable_filter === true;
  if ("filter_script" in common) global.filterScript = String(common.filter_script ?? "");
  if ("default_external_config" in common) global.defaultExternalConfig = String(common.default_external_config ?? "");
  if ("base_path" in common) global.basePath = String(common.base_path ?? "base");
  if ("clash_rule_base" in common) global.clashBase = String(common.clash_rule_base ?? "");
  if ("surge_rule_base" in common) global.surgeBase = String(common.surge_rule_base ?? "");
  if ("surfboard_rule_base" in common) global.surfboardBase = String(common.surfboard_rule_base ?? "");
  if ("mellow_rule_base" in common) global.mellowBase = String(common.mellow_rule_base ?? "");
  if ("quan_rule_base" in common) global.quanBase = String(common.quan_rule_base ?? "");
  if ("quanx_rule_base" in common) global.quanXBase = String(common.quanx_rule_base ?? "");
  if ("loon_rule_base" in common) global.loonBase = String(common.loon_rule_base ?? "");
  if ("sssub_rule_base" in common) global.SSSubBase = String(common.sssub_rule_base ?? "");
  if ("singbox_rule_base" in common) global.singBoxBase = String(common.singbox_rule_base ?? "");
  if ("proxy_config" in common) global.proxyConfig = String(common.proxy_config ?? "");
  if ("proxy_ruleset" in common) global.proxyRuleset = String(common.proxy_ruleset ?? "");
  if ("proxy_subscription" in common) global.proxySubscription = String(common.proxy_subscription ?? "");
  if ("append_proxy_type" in common) global.filterDeprecated = common.append_proxy_type === true;
  if ("reload_conf_on_request" in common) global.reloadConfOnRequest = common.reload_conf_on_request === true;

  if ("udp_flag" in nodePref) global.UDPFlagSet.set(nodePref.udp_flag === true);
  if ("tcp_fast_open_flag" in nodePref) global.TFOFlag.set(nodePref.tcp_fast_open_flag === true);
  if ("skip_cert_verify_flag" in nodePref) global.skipCertVerify.set(nodePref.skip_cert_verify_flag === true);
  if ("tls13_flag" in nodePref) global.TLS13Flag.set(nodePref.tls13_flag === true);
  if ("sort_flag" in nodePref) global.sortFlag = nodePref.sort_flag === true;
  if ("sort_script" in nodePref) global.sortScript = String(nodePref.sort_script ?? "");
  if ("filter_deprecated_nodes" in nodePref) global.filterDeprecated = nodePref.filter_deprecated_nodes === true;
  if ("append_sub_userinfo" in nodePref) global.appendSubUserinfo = nodePref.append_sub_userinfo === true;
  if ("clash_use_new_field_name" in nodePref) global.clashUseNewFieldName = nodePref.clash_use_new_field_name === true;
  if ("clash_proxies_style" in nodePref) global.clashProxiesStyle = String(nodePref.clash_proxies_style ?? "flow");
  if ("clash_proxy_groups_style" in nodePref) global.clashProxyGroupsStyle = String(nodePref.clash_proxy_groups_style ?? "flow");
  if ("singbox_add_clash_modes" in nodePref) global.singBoxAddClashModes = nodePref.singbox_add_clash_modes === true;

  if ("write_managed_config" in managed) global.writeManagedConfig = managed.write_managed_config === true;
  if ("managed_config_prefix" in managed) global.managedConfigPrefix = String(managed.managed_config_prefix ?? "");
  if ("config_update_interval" in managed) global.configUpdateInterval = toInt(String(managed.config_update_interval ?? "86400"), 86400);
  if ("config_update_strict" in managed) global.configUpdateStrict = managed.config_update_strict === true;
  if ("quanx_device_id" in managed) global.quanxDeviceId = String(managed.quanx_device_id ?? "");

  if ("resolve_hostname" in surgeExt) global.surgeResolveHostname = surgeExt.resolve_hostname === true;
  if ("surge_ssr_path" in surgeExt) global.surgeSSRPath = String(surgeExt.surge_ssr_path ?? "");

  if ("add_emoji" in emojis) global.addEmoji = emojis.add_emoji === true;
  if ("remove_old_emoji" in emojis) global.removeEmoji = emojis.remove_old_emoji === true;
  if (Array.isArray(emojis.emoji)) {
    const list = await importArrayItems(emojis.emoji as { import?: string }[], "");
    global.emojis = toRegexMatchConfigs(list);
  }
  if (Array.isArray(nodePref.rename_node)) {
    const list = await importArrayItems(nodePref.rename_node as { import?: string }[], "");
    global.renames = toRegexMatchConfigs(list);
  }
  if (Array.isArray(conf.custom_groups)) {
    const list = await importArrayItems(conf.custom_groups as { import?: string }[], "");
    global.customProxyGroups = toProxyGroupConfigs(list);
  }

  if ("enabled" in ruleset) global.enableRuleGen = ruleset.enabled !== false;
  if ("overwrite_original_rules" in ruleset) global.overwriteOriginalRules = ruleset.overwrite_original_rules === true;
  if ("update_ruleset_on_request" in ruleset) global.updateRulesetOnRequest = ruleset.update_ruleset_on_request === true;
  // [[rulesets]] is a top-level array-of-tables key
  if (Array.isArray(conf.rulesets)) {
    const list = await importArrayItems(conf.rulesets as { import?: string }[], "");
    global.currentRulesets = toRulesetConfigs(list);
  }

  if ("template_path" in template) global.templatePath = String(template.template_path ?? "");
  if (Array.isArray(template.globals)) {
    for (const g of template.globals) {
      if (g && typeof g === "object") {
        const gg = g as Record<string, unknown>;
        if ("key" in gg && "value" in gg) global.templateVars[String(gg.key)] = String(gg.value ?? "");
      }
    }
  }

  if (Array.isArray(aliases)) {
    global.aliases = aliases
      .filter((a) => a && typeof a === "object")
      .map((a) => ({ uri: String((a as Record<string, unknown>).uri ?? ""), target: String((a as Record<string, unknown>).target ?? "") }));
  }

  if (Array.isArray(userinfo.stream_rule)) global.streamNodeRules = toRegexMatchConfigs(userinfo.stream_rule);
  if (Array.isArray(userinfo.time_rule)) global.timeNodeRules = toRegexMatchConfigs(userinfo.time_rule);

  if ("max_allowed_rulesets" in advanced) global.maxAllowedRulesets = toInt(String(advanced.max_allowed_rulesets ?? "0"), 0);
  if ("max_allowed_rules" in advanced) global.maxAllowedRules = toInt(String(advanced.max_allowed_rules ?? "0"), 0);
  if ("max_allowed_download_size" in advanced) global.maxAllowedDownloadSize = toInt(String(advanced.max_allowed_download_size ?? "0"), 0);
  if ("enable_cache" in advanced) global.enableCache = advanced.enable_cache !== false;
  if ("cache_subscription" in advanced) global.cacheSubscription = toInt(String(advanced.cache_subscription ?? "60"), 60);
  if ("cache_config" in advanced) global.cacheConfig = toInt(String(advanced.cache_config ?? "300"), 300);
  if ("cache_ruleset" in advanced) global.cacheRuleset = toInt(String(advanced.cache_ruleset ?? "21600"), 21600);
  if ("script_clean_context" in advanced) global.scriptCleanContext = advanced.script_clean_context === true;
  if ("async_fetch_ruleset" in advanced) global.asyncFetchRuleset = advanced.async_fetch_ruleset === true;
  if ("skip_failed_links" in advanced) global.skipFailedLinks = advanced.skip_failed_links === true;

  return true;
}

function toRulesetConfigs(v: unknown): [string, string, string, number][] {
  const out: [string, string, string, number][] = [];
  if (!Array.isArray(v)) return out;
  for (const item of v) {
    if (!item || typeof item !== "object") continue;
    const m = item as Record<string, unknown>;
    out.push([String(m.group ?? ""), String(m.ruleset ?? ""), String(m.type ?? "surge-ruleset"), toInt(String(m.interval ?? "0"), 0)]);
  }
  return out;
}

export async function readConf(confContent?: string): Promise<boolean> {
  let content = confContent;
  if (content === undefined) {
    content = fileGet(global.prefPath);
    if (content.length === 0) {
      for (const p of ["pref.toml", "pref.yml", "pref.ini"]) {
        content = fileGet(p);
        if (content.length > 0) {
          global.prefPath = p;
          break;
        }
      }
    }
  }
  if (content === undefined || content.length === 0) return false;
  if (content.includes("common:")) return readYAMLConf(content);
  if (/^\s*version\s*=/.test(content) || content.includes("[common]")) return readTOMLConf(content);
  return readINIConf(content);
}

function readINIConf(content: string): boolean {
  const ini = new INIReader();
  ini.store_any_line = false;
  if (ini.parse(content) !== 0) return false;
  const get = (s: string, k: string): string => ini.get(s, k);
  const getBool = (s: string, k: string, def: boolean): boolean => {
    const v = get(s, k);
    return v.length === 0 ? def : v === "true";
  };
  const getInt = (s: string, k: string, def: number): number => toInt(get(s, k), def);
  global.apiMode = getBool("common", "api_mode", false);
  global.accessToken = get("common", "api_access_token");
  global.defaultUrls = get("common", "default_url").split("|").filter((s) => s.length > 0);
  global.enableInsert = getBool("common", "enable_insert", true);
  global.insertUrls = get("common", "insert_url").split("|").filter((s) => s.length > 0);
  global.prependInsert = getBool("common", "prepend_insert_url", true);
  global.excludeRemarks = get("common", "exclude_remarks").split("|").filter((s) => s.length > 0);
  global.includeRemarks = get("common", "include_remarks").split("|").filter((s) => s.length > 0);
  global.basePath = get("common", "base_path") || "base";
  global.clashBase = get("common", "clash_rule_base") || global.clashBase;
  global.surgeBase = get("common", "surge_rule_base") || global.surgeBase;
  global.surfboardBase = get("common", "surfboard_rule_base") || global.surfboardBase;
  global.mellowBase = get("common", "mellow_rule_base") || global.mellowBase;
  global.quanBase = get("common", "quan_rule_base") || global.quanBase;
  global.quanXBase = get("common", "quanx_rule_base") || global.quanXBase;
  global.loonBase = get("common", "loon_rule_base") || global.loonBase;
  global.SSSubBase = get("common", "sssub_rule_base") || global.SSSubBase;
  global.singBoxBase = get("common", "singbox_rule_base") || global.singBoxBase;
  global.proxyConfig = get("common", "proxy_config");
  global.proxyRuleset = get("common", "proxy_ruleset");
  global.proxySubscription = get("common", "proxy_subscription");
  global.appendProxyType = getBool("common", "append_proxy_type", false);
  global.managedConfigPrefix = get("managed_config", "managed_config_prefix");
  global.writeManagedConfig = getBool("managed_config", "write_managed_config", false);
  global.configUpdateInterval = getInt("managed_config", "config_update_interval", 86400);
  global.addEmoji = getBool("emojis", "add_emoji", false);
  global.removeEmoji = getBool("emojis", "remove_old_emoji", true);
  global.enableRuleGen = getBool("ruleset", "enabled", true);
  global.overwriteOriginalRules = getBool("ruleset", "overwrite_original_rules", false);
  global.updateRulesetOnRequest = getBool("ruleset", "update_ruleset_on_request", false);
  global.maxAllowedRulesets = getInt("advanced", "max_allowed_rulesets", 0);
  global.maxAllowedRules = getInt("advanced", "max_allowed_rules", 0);
  global.skipFailedLinks = getBool("advanced", "skip_failed_links", false);
  global.cacheSubscription = getInt("advanced", "cache_subscription", 60);
  global.cacheConfig = getInt("advanced", "cache_config", 300);
  global.cacheRuleset = getInt("advanced", "cache_ruleset", 21600);
  // rename/emoji/ruleset arrays use comma-separated values in INI (simplified)
  const renames = ini.getAll("clash_proxy_group", "rename") ?? [];
  void renames;
  return true;
}

// INIBinding::from<RulesetConfig>::from_ini (binding.h:306) — "group,url[,interval]", where
// "url" starting with "[]" is literal inline rule content. Callers map this to their own shape.
export function fromIniRulesetConfs(lines: string[]): [string, string, number][] {
  const out: [string, string, number][] = [];
  for (const x of lines) {
    const pos = x.indexOf(",");
    if (pos === -1) continue;
    const group = x.substring(0, pos);
    const rest = x.substring(pos + 1);
    if (rest.startsWith("[]")) {
      out.push([group, rest, 0]);
      continue;
    }
    const epos = x.lastIndexOf(",");
    if (pos !== epos) out.push([group, x.substring(pos + 1, epos), toInt(x.substring(epos + 1), 0)]);
    else out.push([group, rest, 0]);
  }
  return out;
}

export async function refreshRulesets(
  rulesetConfigs: [string, string, string, number][], rulesetContent: RulesetContent[],
): Promise<void> {
  rulesetContent.length = 0;
  let total = 0;
  const results = await Promise.all(
    rulesetConfigs.map(async ([group, path, type, interval]) => {
      if (global.maxAllowedRulesets > 0 && total++ > global.maxAllowedRulesets) return null;
      // settings.cpp:259 — inline ruleset: "[]" anywhere in the url marks literal rule content
      // (e.g. "[]GEOIP,CN" / "rules/xx.list[]FINAL"); content is the url from "[]" onwards.
      const pos = path.indexOf("[]");
      if (pos !== -1) {
        return {
          rule_group: group,
          rule_path: "",
          rule_path_typed: "",
          rule_format: "surge-ruleset",
          rule_type: RULESET_SURGE,
          rule_content: path.substring(pos),
          update_interval: 0,
        } satisfies RulesetContent;
      }
      const content = await fetchFile(path, global.proxyRuleset, global.cacheRuleset);
      const rc: RulesetContent = {
        rule_group: group,
        rule_path: path,
        rule_path_typed: path,
        rule_format: type,
        rule_type: rulesetTypeFromName(type),
        rule_content: content,
        update_interval: interval,
      };
      return rc;
    }),
  );
  for (const rc of results) if (rc) rulesetContent.push(rc);
}

function rulesetTypeFromName(type: string): number {
  switch (type) {
    case "quanx-ruleset":
      return 1;
    case "clash-domain":
      return 2;
    case "clash-ipcidr":
      return 3;
    case "clash-classic":
      return 4;
    default:
      return 0;
  }
}

export async function loadExternalConfig(path: string, ext: ExternalConfig): Promise<boolean> {
  const content = await fetchFile(path, global.proxyConfig, global.cacheConfig);
  if (content.length === 0) return false;
  const parsed = parseTomlLike(content) as Record<string, unknown> | null;
  if (!parsed) return false;

  const common = (parsed.common ?? parsed) as Record<string, unknown>;
  if ("clash_rule_base" in common) ext.clashRuleBase = String(common.clash_rule_base ?? "");
  if ("surge_rule_base" in common) ext.surgeRuleBase = String(common.surge_rule_base ?? "");
  if ("surfboard_rule_base" in common) ext.surfboardRuleBase = String(common.surfboard_rule_base ?? "");
  if ("mellow_rule_base" in common) ext.mellowRuleBase = String(common.mellow_rule_base ?? "");
  if ("quan_rule_base" in common) ext.quanRuleBase = String(common.quan_rule_base ?? "");
  if ("quanx_rule_base" in common) ext.quanXRuleBase = String(common.quanx_rule_base ?? "");
  if ("loon_rule_base" in common) ext.loonRuleBase = String(common.loon_rule_base ?? "");
  if ("sssub_rule_base" in common) ext.ssSubBase = String(common.sssub_rule_base ?? "");
  if ("singbox_rule_base" in common) ext.singBoxBase = String(common.singbox_rule_base ?? "");
  if ("enable_rule_generator" in common) ext.enableRuleGen = common.enable_rule_generator !== false;
  if ("overwrite_original_rules" in common) ext.overwriteOriginalRules = common.overwrite_original_rules === true;
  if ("managed_config_prefix" in common) ext.managedConfigPrefix = String(common.managed_config_prefix ?? "");

  ext.exclude = asStrArr(common.exclude_remarks);
  ext.include = asStrArr(common.include_remarks);
  if (Array.isArray(parsed.rename_node)) ext.rename = toRegexMatchConfigs(parsed.rename_node);
  const emojis = parsed.emojis as Record<string, unknown> | undefined;
  if (emojis && Array.isArray(emojis.emoji)) {
    const emojiList = await importArrayItems(emojis.emoji as { import?: string }[], global.proxyConfig);
    ext.emoji = toRegexMatchConfigs(emojiList);
  }

  const rulesetConf = parsed.rulesets ?? parsed.ruleset;
  if (Array.isArray(rulesetConf)) {
    const list = await importArrayItems(rulesetConf as { import?: string }[], global.proxyConfig);
    ext.customRulesets = toRulesetConfigs(list);
  }
  const groups = parsed.custom_groups;
  if (Array.isArray(groups)) {
    const list = await importArrayItems(groups as { import?: string }[], global.proxyConfig);
    ext.customProxyGroups = toProxyGroupConfigs(list);
  }
  return true;
}

export function toProxyGroupConfigs(v: unknown): ProxyGroupConfig[] {
  const out: ProxyGroupConfig[] = [];
  if (!Array.isArray(v)) return out;
  for (const item of v) {
    if (!item || typeof item !== "object") continue;
    const m = item as Record<string, unknown>;
    const typeStr = String(m.type ?? "select").toLowerCase();
    let type = ProxyGroupType.Select;
    switch (typeStr) {
      case "select": type = ProxyGroupType.Select; break;
      case "url-test": case "urltest": type = ProxyGroupType.URLTest; break;
      case "fallback": type = ProxyGroupType.Fallback; break;
      case "load-balance": type = ProxyGroupType.LoadBalance; break;
      case "relay": type = ProxyGroupType.Relay; break;
      case "ssid": type = ProxyGroupType.SSID; break;
      case "smart": type = ProxyGroupType.Smart; break;
      default: continue;
    }
    const g: ProxyGroupConfig = {
      Name: String(m.name ?? ""),
      Type: type,
      Proxies: asStrArr(m.rule),
      UsingProvider: [],
      Url: String(m.url ?? ""),
      Interval: toInt(String(m.interval ?? "0"), 0),
      Timeout: toInt(String(m.timeout ?? "0"), 0),
      Tolerance: toInt(String(m.tolerance ?? "0"), 0),
      Strategy: String(m.strategy ?? "") === "round-robin" ? BalanceStrategy.RoundRobin : BalanceStrategy.ConsistentHashing,
      Lazy: new tribool(m.lazy === undefined ? undefined : m.lazy === true),
      DisableUdp: new tribool(m.disable_udp === undefined ? undefined : m.disable_udp === true),
      Persistent: new tribool(),
      EvaluateBeforeUse: new tribool(),
      Extras: {},
    };
    out.push(g);
  }
  return out;
}
