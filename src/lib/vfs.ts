// Port of src/utils/file.cpp — Workers implementation over embedded assets.
// Relative paths resolve like the C++ app: "base/all_base.tpl", "snippets/emoji.txt" etc.
// Writes (pref.toml via /updateconf, gistconf.ini) are in-isolate (Map); optional KV binding upgrades persistence.

import { EMBEDDED_FILES } from "../embed/files";

// in-isolate writable overlay (session-scoped persistence)
const overlay = new Map<string, string>();

// optional KV persistence hook — set from index.ts when a KV binding exists
let kvGet: ((key: string) => Promise<string | null>) | null = null;
let kvPut: ((key: string, value: string) => Promise<void>) | null = null;
export function setKvBinding(get: (key: string) => Promise<string | null>, put: (key: string, value: string) => Promise<void>): void {
  kvGet = get;
  kvPut = put;
}

// isInScope: reject absolute paths and '..' traversal (like upstream)
function isInScope(path: string): boolean {
  if (path.startsWith("/") || path.includes(":\\")) return false;
  const parts = path.split(/[\\/]/);
  return !parts.includes("..");
}

export function fileExist(path: string, scopeLimit = false): boolean {
  if (scopeLimit && !isInScope(path)) return false;
  return overlay.has(path) || Object.prototype.hasOwnProperty.call(EMBEDDED_FILES, path);
}

export function fileGet(path: string, scopeLimit = false): string {
  if (scopeLimit && !isInScope(path)) return "";
  if (overlay.has(path)) return overlay.get(path)!;
  const embedded = EMBEDDED_FILES[path];
  if (embedded !== undefined) return embedded;
  // KV-backed persistent overlay (async lookup is not possible in sync fileGet;
  // preloadKv() should be awaited at request start for KV-backed files)
  return "";
}

const kvPending = new Map<string, Promise<string | null>>();

export async function preloadKv(paths: string[]): Promise<void> {
  if (!kvGet) return;
  const pending: Promise<void>[] = [];
  for (const p of paths) {
    if (overlay.has(p) || EMBEDDED_FILES[p] !== undefined) continue;
    let pr = kvPending.get(p);
    if (!pr) {
      pr = kvGet(p);
      kvPending.set(p, pr);
    }
    pending.push(
      pr.then((v) => {
        if (v !== null) overlay.set(p, v);
      }),
    );
  }
  await Promise.allSettled(pending);
}

export async function fileWrite(path: string, content: string, overwrite = true): Promise<boolean> {
  if (!overwrite && (overlay.has(path) || EMBEDDED_FILES[path] !== undefined)) return false;
  overlay.set(path, content);
  if (kvPut) await kvPut(path, content);
  return true;
}

export function fileCopy(src: string, dest: string): void {
  const content = fileGet(src);
  if (content.length > 0) overlay.set(dest, content);
}

export function clearOverlay(): void {
  overlay.clear();
  kvPending.clear();
}

// path join helper mirroring upstream base-path resolution
export function fetchFileScoped(path: string, basePath: string): string {
  if (fileExist(path)) return fileGet(path);
  return fileGet(basePath.replace(/\/?$/, "/") + path);
}
