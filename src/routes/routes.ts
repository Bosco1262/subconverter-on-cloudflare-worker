// Route handlers — port of all endpoints registered in src/main.cpp + handlers in interfaces.cpp

import { global } from "../core/settings";
import { subconverter } from "../core/orchestrator";
import { getRulesetHandler, surgeConfToClashHandler, getProfileHandler, renderTemplateHandler } from "./handlers";
import { uploadGist } from "../lib/gist";
import { flushCache, webGet } from "../lib/fetch";
import { readConf } from "../core/settings";
import { fileGet } from "../lib/vfs";
import { urlSafeBase64Encode } from "../lib/base64";

export { subconverter };

export const VERSION = "1.0.0-worker";

export function versionHandler(): SubResultLite {
  return { status: 200, body: `subconverter ${VERSION} backend\n` };
}

export interface SubResultLite {
  status: number;
  body: string;
  headers?: [string, string][];
}

export async function refreshRulesHandler(): Promise<SubResultLite> {
  // upstream re-fetches all custom rulesets; our cache is fetch-time
  return { status: 200, body: "done\n" };
}

export async function readConfHandler(): Promise<SubResultLite> {
  const ok = await readConf();
  return { status: ok ? 200 : 500, body: ok ? "done\n" : "failed\n" };
}

export async function updateConfHandler(postdata: string): Promise<SubResultLite> {
  await import("../lib/vfs").then(async (vfs) => {
    await vfs.fileWrite(global.prefPath, postdata, true);
  });
  const ok = await readConf();
  return { status: ok ? 200 : 500, body: ok ? "done\n" : "failed\n" };
}

export function flushCacheHandler(): SubResultLite {
  flushCache();
  return { status: 200, body: "done\n" };
}

// /get — plain webGet proxy (disabled in API mode)
export async function getUrlHandler(url: string): Promise<SubResultLite> {
  const content = await webGet(url, { cacheTTL: 0 });
  return { status: 200, body: content };
}

// /getlocal — local file reader (disabled in API mode)
export function getLocalHandler(path: string): SubResultLite {
  return { status: 200, body: fileGet(path, true) };
}

export { getRulesetHandler, surgeConfToClashHandler, getProfileHandler, renderTemplateHandler, uploadGist, urlSafeBase64Encode };
