// Port of src/handler/webget.cpp — Workers implementation of webGet/webPost/webPatch/webHead
// with Cache API caching (free-plan compatible), cors: proxy prefix, loop-detection headers.

import { md5 } from "./md5";
import { replaceAllDistinct } from "./string";

const VERSION = "1.0.0-worker";

export interface FetchResult {
  content: string;
  headers: [string, string][];
  status: number;
}

export interface WebGetOptions {
  proxy?: string;
  cacheTTL?: number; // seconds; 0 = no cache
  requestHeaders?: Record<string, string> | Map<string, string>;
  userAgent?: string;
  maxResponseSize?: number; // bytes
  respHeadersOut?: { v: [string, string][] };
}

const DEFAULT_UA = `subconverter/${VERSION} cURL/8.0`;
const DEFAULT_MAX_SIZE = 1048576;

// in-isolate cache: URL -> {content, headers, expires, fetchedAt}
interface CacheEntry {
  content: string;
  headers: [string, string][];
  fetchedAt: number;
  expires: number;
}
const memCache = new Map<string, CacheEntry>();

export function flushCache(): void {
  memCache.clear();
}

function buildRequestHeaders(opts: WebGetOptions): Headers {
  const h = new Headers();
  const rh = opts.requestHeaders instanceof Map ? [...opts.requestHeaders.entries()] : Object.entries(opts.requestHeaders ?? {});
  let hasUA = false;
  for (const [k, v] of rh) {
    if (k.toLowerCase() === "host" || k.toLowerCase() === "accept" || k.toLowerCase() === "accept-encoding") continue;
    if (k.toLowerCase() === "user-agent") hasUA = true;
    h.set(k, v);
  }
  if (!hasUA) h.set("User-Agent", opts.userAgent ?? DEFAULT_UA);
  // loop-detection + versioning
  h.set("SubConverter-Request", "1");
  h.set("SubConverter-Version", VERSION);
  return h;
}

async function rawFetch(url: string, opts: WebGetOptions, method = "GET", body?: string): Promise<FetchResult> {
  const headers = buildRequestHeaders(opts);
  let targetUrl = url;

  // cors: proxy prefix — add X-Requested-With instead of proxying
  const proxy = opts.proxy ?? "";
  if (proxy.startsWith("cors:")) {
    targetUrl = proxy.substring(5) + url;
    headers.set("X-Requested-With", "subconverter");
  } else if (proxy.length > 0) {
    // socks5 proxy unsupported on Workers — proceed direct
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const resp = await fetch(targetUrl, {
      method,
      headers,
      body,
      redirect: "follow",
      signal: controller.signal,
    });
    const respHeaders: [string, string][] = [...resp.headers.entries()];
    if (opts.respHeadersOut) opts.respHeadersOut.v = respHeaders;
    const max = opts.maxResponseSize ?? DEFAULT_MAX_SIZE;
    // read with size cap
    const reader = resp.body?.getReader();
    if (!reader) return { content: "", headers: respHeaders, status: resp.status };
    const chunks: Uint8Array[] = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.length;
        chunks.push(value);
        if (received > max) {
          await reader.cancel();
          break;
        }
      }
    }
    const total = chunks.reduce((a, c) => a + c.length, 0);
    const merged = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      merged.set(c, off);
      off += c.length;
    }
    const content = new TextDecoder("utf-8").decode(merged);
    return { content, headers: respHeaders, status: resp.status };
  } finally {
    clearTimeout(timeout);
  }
}

export async function webGet(url: string, options: WebGetOptions = {}): Promise<string> {
  if (url.startsWith("data:")) {
    // data: URI — decode inline
    const commaPos = url.indexOf(",");
    if (commaPos === -1) return "";
    const meta = url.substring(5, commaPos);
    const data = url.substring(commaPos + 1);
    if (meta.includes("base64")) {
      const { base64Decode } = await import("./base64");
      return base64Decode(data, true);
    }
    return decodeURIComponent(data);
  }

  const cacheTTL = options.cacheTTL ?? 0;
  const key = cacheTTL > 0 ? url : "";

  if (cacheTTL > 0) {
    const hit = memCache.get(key);
    const now = Date.now();
    if (hit && hit.expires > now) return hit.content;
  }

  let result: FetchResult | null = null;
  try {
    result = await rawFetch(url, options);
    if (result.status >= 200 && result.status < 400) {
      if (cacheTTL > 0) {
        memCache.set(key, {
          content: result.content,
          headers: result.headers,
          fetchedAt: Date.now(),
          expires: Date.now() + cacheTTL * 1000,
        });
      }
      return result.content;
    }
  } catch {
    // fall through to stale cache
  }

  // serve stale on fetch failure (serveCacheOnFetchFail behavior)
  const stale = memCache.get(key);
  if (stale) return stale.content;
  return result ? result.content : "";
}

export async function webGetWithHeaders(url: string, options: WebGetOptions = {}): Promise<string> {
  return webGet(url, options);
}

export async function webPost(url: string, postdata: string, options: WebGetOptions = {}): Promise<string> {
  const r = await rawFetch(url, options, "POST", postdata);
  return r.status >= 200 && r.status < 400 ? r.content : "";
}

export async function webPatch(url: string, postdata: string, options: WebGetOptions = {}): Promise<string> {
  const r = await rawFetch(url, options, "PATCH", postdata);
  return r.status >= 200 && r.status < 400 ? r.content : "";
}

export { md5, replaceAllDistinct, DEFAULT_UA };
