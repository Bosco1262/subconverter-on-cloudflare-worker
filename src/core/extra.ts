// Port of src/generator/config/subexport.h (extra_settings) + src/config/proxygroup.h + ruleconvert.h types

import { tribool } from "../lib/tribool";
import type { RegexMatchConfigs } from "./info";

export type ProxyGroupConfigs = ProxyGroupConfig[];

export interface extra_settings {
  enable_rule_generator: boolean;
  overwrite_original_rules: boolean;
  rename_array: RegexMatchConfigs;
  emoji_array: RegexMatchConfigs;
  add_emoji: boolean;
  remove_emoji: boolean;
  append_proxy_type: boolean;
  nodelist: boolean;
  sort_flag: boolean;
  filter_deprecated: boolean;
  clash_new_field_name: boolean;
  clash_script: boolean;
  surge_ssr_path: string;
  managed_config_prefix: string;
  quanx_dev_id: string;
  udp: tribool;
  tfo: tribool;
  xudp: tribool;
  skip_cert_verify: tribool;
  tls13: tribool;
  clash_classical_ruleset: boolean;
  sort_script: string;
  clash_proxies_style: string;
  clash_proxy_groups_style: string;
  authorized: boolean;
}

export function newExtraSettings(): extra_settings {
  return {
    enable_rule_generator: true,
    overwrite_original_rules: true,
    rename_array: [],
    emoji_array: [],
    add_emoji: false,
    remove_emoji: false,
    append_proxy_type: false,
    nodelist: false,
    sort_flag: false,
    filter_deprecated: false,
    clash_new_field_name: false,
    clash_script: false,
    surge_ssr_path: "",
    managed_config_prefix: "",
    quanx_dev_id: "",
    udp: new tribool(),
    tfo: new tribool(),
    xudp: new tribool(),
    skip_cert_verify: new tribool(),
    tls13: new tribool(),
    clash_classical_ruleset: false,
    sort_script: "",
    clash_proxies_style: "flow",
    clash_proxy_groups_style: "flow",
    authorized: false,
  };
}

export enum ProxyGroupType {
  Select,
  URLTest,
  Fallback,
  LoadBalance,
  Relay,
  SSID,
  Smart,
}

export enum BalanceStrategy {
  ConsistentHashing,
  RoundRobin,
}

export interface ProxyGroupConfig {
  Name: string;
  Type: ProxyGroupType;
  Proxies: string[];
  UsingProvider: string[];
  Url: string;
  Interval: number;
  Timeout: number;
  Tolerance: number;
  Strategy: BalanceStrategy;
  Lazy: tribool;
  DisableUdp: tribool;
  Persistent: tribool;
  EvaluateBeforeUse: tribool;
  Extras: Record<string, string>;
}

export function proxyGroupTypeStr(type: ProxyGroupType): string {
  switch (type) {
    case ProxyGroupType.Select:
      return "select";
    case ProxyGroupType.URLTest:
      return "url-test";
    case ProxyGroupType.LoadBalance:
      return "load-balance";
    case ProxyGroupType.Fallback:
      return "fallback";
    case ProxyGroupType.Relay:
      return "relay";
    case ProxyGroupType.SSID:
      return "ssid";
    case ProxyGroupType.Smart:
      return "smart";
  }
  return "";
}

export function proxyGroupStrategyStr(strategy: BalanceStrategy): string {
  switch (strategy) {
    case BalanceStrategy.ConsistentHashing:
      return "consistent-hashing";
    case BalanceStrategy.RoundRobin:
      return "round-robin";
  }
  return "";
}

export const RULESET_SURGE = 0;
export const RULESET_QUANX = 1;
export const RULESET_CLASH_DOMAIN = 2;
export const RULESET_CLASH_IPCIDR = 3;
export const RULESET_CLASH_CLASSICAL = 4;

export interface RulesetContent {
  rule_group: string;
  rule_path: string;
  rule_path_typed: string;
  rule_format: string;
  rule_type: number;
  rule_content: string; // resolved content (Workers fetch upfront)
  update_interval: number;
}
