// Port of src/parser/infoparser.cpp + src/config/regmatch.h

import { endsWith, split, toInt, getUrlArg, strFind } from "../lib/string";
import { regFind, regGetMatch, regMatch, regReplace } from "../lib/regex";
import { urlSafeBase64Decode } from "../lib/base64";
import { getMember } from "./parser/util";
import { Proxy } from "./proxy";

export interface RegexMatchConfig {
  Match: string;
  Replace: string;
  Script: string;
}

export type RegexMatchConfigs = RegexMatchConfig[];

export function streamToInt(stream: string): number {
  if (stream.length === 0) return 0;
  let streamval = 1.0;
  const units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
  let index = units.length;
  do {
    index--;
    if (endsWith(stream, units[index])) {
      const numStr = stream.substring(0, stream.length - units[index].length);
      const m = /^[ \t\n\v\f\r]*([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/.exec(numStr);
      const num = m && m[0].length === numStr.length ? Number(m[1]) : 0;
      streamval = Math.pow(1024, index) * num;
      break;
    }
  } while (index !== 0);
  return Math.trunc(streamval);
}

function percentToDouble(percent: string): number {
  return Number(percent.substring(0, percent.length - 1)) / 100.0;
}

export function dateStringToTimestamp(date0: string): number {
  const rawtime = Math.floor(Date.now() / 1000);
  let date = date0;
  if (date.startsWith("left=")) {
    let secondsLeft = 0;
    date = date.substring(5);
    if (date.endsWith("d")) {
      const numStr = date.substring(0, date.length - 1);
      const m = /^[ \t\n\v\f\r]*([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/.exec(numStr);
      const num = m && m[0].length === numStr.length ? Number(m[1]) : 0;
      secondsLeft = Math.floor(num * 86400);
    }
    return rawtime + secondsLeft;
  } else {
    const dateArray = split(date, ":");
    if (dateArray.length !== 6) return 0;
    // C++ uses mktime with localtime — emulate with Date (UTC offset applied)
    const year = toInt(dateArray[0], 1900) - 1900;
    const mon = toInt(dateArray[1], 1) - 1;
    const mday = toInt(dateArray[2]);
    const hour = toInt(dateArray[3]);
    const min = toInt(dateArray[4]);
    const sec = toInt(dateArray[5]);
    const d = new Date(year + 1900, mon, mday, hour, min, sec);
    return Math.floor(d.getTime() / 1000);
  }
}

export function getSubInfoFromHeader(header: string): string | null {
  const pattern = "^(?i:Subscription-UserInfo): (.*?)\\s*?$";
  if (regFind(header, pattern)) {
    const m = regGetMatch(header, pattern);
    const retStr = m && m.length > 1 ? m[1] : "";
    if (retStr.length > 0) {
      return retStr;
    }
  }
  return null;
}

export function getSubInfoFromNodes(nodes: Proxy[], streamRules: RegexMatchConfigs, timeRules: RegexMatchConfigs): string | null {
  let stream_info = "", time_info = "";

  for (const x of nodes) {
    let remarks = x.Remark;
    if (stream_info.length === 0) {
      for (const y of streamRules) {
        if (y.Script.length > 0) continue;
        if (regMatch(remarks, y.Match)) {
          const retStr = regReplace(remarks, y.Match, y.Replace);
          if (retStr !== remarks) {
            stream_info = retStr;
            break;
          }
        }
      }
    }

    remarks = x.Remark;
    if (time_info.length === 0) {
      for (const y of timeRules) {
        if (y.Script.length > 0) continue;
        if (regMatch(remarks, y.Match)) {
          const retStr = regReplace(remarks, y.Match, y.Replace);
          if (retStr !== remarks) {
            time_info = retStr;
            break;
          }
        }
      }
    }

    if (stream_info.length > 0 && time_info.length > 0) break;
  }

  if (stream_info.length === 0 && time_info.length === 0) return null;

  // calculate how much stream left
  let total = 0, used = 0, expire = 0, left = 0;
  const total_str = getUrlArg(stream_info, "total"), left_str = getUrlArg(stream_info, "left"), used_str = getUrlArg(stream_info, "used");
  if (strFind(total_str, "%")) {
    if (used_str.length > 0) {
      used = streamToInt(used_str);
      total = Math.trunc(used / (1 - percentToDouble(total_str)));
    } else if (left_str.length > 0) {
      left = streamToInt(left_str);
      total = Math.trunc(left / percentToDouble(total_str));
      if (left > total) left = 0;
      used = total - left;
    }
  } else {
    total = streamToInt(total_str);
    if (used_str.length > 0) {
      used = streamToInt(used_str);
    } else if (left_str.length > 0) {
      left = streamToInt(left_str);
      if (left > total) left = 0;
      used = total - left;
    }
  }

  let result = "upload=0; download=" + used + "; total=" + total + ";";

  // calculate expire time
  expire = dateStringToTimestamp(time_info);
  if (expire) result += " expire=" + expire + ";";

  return result;
}

export function getSubInfoFromSSD(sub: string): string | null {
  let json: Record<string, unknown> | null = null;
  try {
    json = JSON.parse(urlSafeBase64Decode(sub.substring(6))) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!json || typeof json !== "object") return null;

  const used_str = getMember(json, "traffic_used"), total_str = getMember(json, "traffic_total"), expire_str = getMember(json, "expiry");
  if (used_str.length === 0 || total_str.length === 0) return null;
  const used = Math.trunc(Number(used_str) * Math.pow(1024, 3));
  const total = Math.trunc(Number(total_str) * Math.pow(1024, 3));
  let result = "upload=0; download=" + used + "; total=" + total + ";";

  const expire = dateStringToTimestamp(regReplace(expire_str, "(\\d+)-(\\d+)-(\\d+) (.*)", "$1:$2:$3:$4"));
  if (expire) result += " expire=" + expire + ";";

  return result;
}
