// Worker entry — route table matching src/main.cpp registration + webserver_httplib.cpp pre-routing

import { subconverter, type SubRequest } from "./core/orchestrator";
import { getRulesetHandler, surgeConfToClashHandler, getProfileHandler, renderTemplateHandler } from "./routes/handlers";
import {
  versionHandler, refreshRulesHandler, readConfHandler, updateConfHandler, flushCacheHandler,
  getUrlHandler, getLocalHandler, VERSION,
} from "./routes/routes";
import { readConf, global } from "./core/settings";
import { setTemplateFileGet } from "./core/template";
import { setKvBinding, fileGet, fileCopy, preloadKv } from "./lib/vfs";
import { clearRegexCache } from "./lib/regex";
import { urlDecode } from "./lib/urlencode";
import { startsWith } from "./lib/string";

export interface Env {
  API_MODE?: string;
  API_TOKEN?: string;
  MANAGED_PREFIX?: string;
  MAX_NODES?: string;
  MAX_RULESET_LINES?: string;
  KV?: KVNamespace;
}

// wire template file access to the VFS
setTemplateFileGet((path, scopeLimit) => fileGet(path, scopeLimit ?? true));

// query parsing — multimap (duplicate keys preserved in order)
function parseQuery(url: URL): [string, string][] {
  const args: [string, string][] = [];
  for (const [k, v] of url.searchParams.entries()) {
    args.push([k, v]);
  }
  return args;
}

function headersToMap(req: Request): Map<string, string> {
  const map = new Map<string, string>();
  req.headers.forEach((v, k) => {
    const kl = k.toLowerCase();
    if (kl === "host" || kl === "accept" || kl === "accept-encoding") return;
    map.set(k, v);
  });
  return map;
}

function applyCors(resp: Response): Response {
  const out = new Response(resp.body, resp);
  out.headers.set("Access-Control-Allow-Origin", "*");
  out.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD");
  out.headers.set("Access-Control-Allow-Headers", "*");
  out.headers.set("Server", `subconverter/${VERSION} cURL/8.0`);
  return out;
}

function jsonResp(status: number, body: string, headers?: Headers | [string, string][]): Response {
  const h = new Headers();
  if (headers) {
    if (headers instanceof Headers) {
      headers.forEach((v, k) => h.set(k, v));
    } else {
      for (const [k, v] of headers) h.set(k, v);
    }
  }
  return new Response(body, { status, headers: h });
}

let confLoaded = false;

async function loadConfigOnce(env: Env): Promise<void> {
  if (confLoaded) return;
  if (env.KV) {
    setKvBinding(
      (key) => env.KV!.get(key),
      (key, value) => env.KV!.put(key, value),
    );
    // preload KV-backed config files before readConf
    await preloadKv(["pref.toml", "pref.yml", "pref.ini", "gistconf.ini"]);
  }
  // upstream main.cpp copies pref.example.* → pref.* when missing
  if (fileGet("pref.toml").length === 0) {
    for (const [src, dest] of [["pref.example.toml", "pref.toml"], ["pref.example.yml", "pref.yml"], ["pref.example.ini", "pref.ini"]] as const) {
      if (fileGet(src).length > 0) {
        fileCopy(src, dest);
        break;
      }
    }
  }
  await readConf();
  // env vars override pref
  if (env.API_MODE !== undefined) global.apiMode = env.API_MODE === "true";
  if (env.API_TOKEN !== undefined && env.API_TOKEN.length > 0) global.accessToken = env.API_TOKEN;
  if (env.MANAGED_PREFIX !== undefined && env.MANAGED_PREFIX.length > 0) global.managedConfigPrefix = env.MANAGED_PREFIX;
  if (env.MAX_NODES !== undefined) global.maxAllowedNodes = Number(env.MAX_NODES) || 0;
  if (env.MAX_RULESET_LINES !== undefined) global.maxAllowedRules = Number(env.MAX_RULESET_LINES) || 0;
  confLoaded = true;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    await loadConfigOnce(env);

    const url = new URL(request.url);
    const path = url.pathname;

    // OPTIONS preflight
    if (request.method === "OPTIONS") {
      return applyCors(new Response("", { status: 204 }));
    }

    // alias redirects (from pref [[aliases]])
    for (const alias of global.aliases) {
      if (alias.uri === path) {
        const target = new URL(alias.target, url.origin);
        const qs = url.search ? url.search : "";
        return applyCors(Response.redirect(target.origin + target.pathname + target.search + qs, 302));
      }
    }

    // loop detection: request already went through a subconverter
    if (request.headers.has("SubConverter-Request")) {
      return jsonResp(500, "Loop detected!");
    }

    const argument = parseQuery(url);
    const subReq: SubRequest = {
      method: request.method,
      argument,
      headers: headersToMap(request),
      userAgent: request.headers.get("User-Agent") ?? "",
    };
    const postdata = request.method === "POST" ? await request.text() : "";

    // resolve alias targets with query args appended
    let effectivePath = path;
    if (startsWith(path, "/sub?")) effectivePath = "/sub";

    let resp: Response;
    try {
      resp = await dispatch(effectivePath, request, env, subReq, postdata);
    } catch (e) {
      resp = jsonResp(500, "Internal error: " + String(e instanceof Error ? e.message : e));
    }
    return applyCors(resp);
  },
};

async function dispatch(path: string, request: Request, env: Env, subReq: SubRequest, postdata: string): Promise<Response> {
  const url = new URL(request.url);

  switch (path) {
    case "/version":
      return jsonResp(...destructure(versionHandler()));
    case "/refreshrules": {
      if (!checkToken(url)) return jsonResp(403, "Forbidden");
      return jsonResp(...destructure(await refreshRulesHandler()));
    }
    case "/readconf": {
      if (!checkToken(url)) return jsonResp(403, "Forbidden");
      return jsonResp(...destructure(await readConfHandler()));
    }
    case "/updateconf": {
      if (!checkToken(url)) return jsonResp(403, "Forbidden");
      if (request.method !== "POST") return jsonResp(405, "Method not allowed");
      const data = extractPostData(request, postdata);
      return jsonResp(...destructure(await updateConfHandler(data)));
    }
    case "/flushcache": {
      if (!checkToken(url)) return jsonResp(403, "Forbidden");
      return jsonResp(...destructure(flushCacheHandler()));
    }
    case "/sub":
    case "/sub2clashr": {
      if (path === "/sub2clashr") {
        // legacy compat: expects sublink=<url>
        const arg = url.searchParams.toString();
        const sublinkIdx = arg.indexOf("sublink=");
        if (sublinkIdx !== 0 || arg.length <= 8) {
          return jsonResp(400, "Invalid request!");
        }
        const subUrl = urlDecode(arg.substring(8));
        url.searchParams.set("target", "clashr");
        url.searchParams.set("url", subUrl);
        subReq.argument = [...url.searchParams.entries()];
      }
      const result = await subconverter(subReq);
      return jsonResp(result.status, result.body, result.headers);
    }
    case "/getruleset": {
      const result = await getRulesetHandler(subReq);
      return jsonResp(result.status, result.body, result.headers);
    }
    case "/getprofile": {
      const result = await getProfileHandler(subReq);
      return jsonResp(result.status, result.body, result.headers);
    }
    case "/surge2clash": {
      const result = await surgeConfToClashHandler(subReq);
      return jsonResp(result.status, result.body, result.headers);
    }
    case "/render": {
      const result = await renderTemplateHandler(subReq);
      return jsonResp(result.status, result.body, result.headers);
    }
    case "/get": {
      if (global.apiMode) return jsonResp(403, "Not authorized");
      const target = url.searchParams.get("url") ?? "";
      if (target.length === 0) return jsonResp(400, "Invalid request!");
      return jsonResp(...destructure(await getUrlHandler(target)));
    }
    case "/getlocal": {
      if (global.apiMode) return jsonResp(403, "Not authorized");
      const target = url.searchParams.get("path") ?? "";
      if (target.length === 0) return jsonResp(400, "Invalid request!");
      return jsonResp(...destructure(getLocalHandler(target)));
    }
    default:
      return jsonResp(404, "Not found");
  }
  void env;
  void clearRegexCache;
}

function checkToken(url: URL): boolean {
  if (!global.apiMode) return true;
  const token = url.searchParams.get("token") ?? "";
  return token.length > 0 && token === global.accessToken;
}

function extractPostData(request: Request, postdata: string): string {
  const ct = request.headers.get("Content-Type") ?? "";
  if (ct.includes("application/x-www-form-urlencoded")) {
    // form: take the `value=` field or raw body
    const params = new URLSearchParams(postdata);
    const v = params.get("value");
    return v ?? postdata;
  }
  return postdata;
}

type HandlerResult = { status: number; body: string; headers?: [string, string][] };
function destructure(r: HandlerResult): [number, string, Headers | undefined] {
  if (!r.headers || r.headers.length === 0) return [r.status, r.body, undefined];
  const h = new Headers();
  for (const [k, v] of r.headers) h.set(k, v);
  return [r.status, r.body, h];
}
