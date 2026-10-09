// Port of src/handler/upload.cpp — Gist upload (webPost/webPatch)
//
// Upstream shape (upload.cpp:30-117):
//   gistconf.ini must exist and hold a [common] section with `token` (and optionally `id`,
//   `username`); the upload path defaults to the generator name unless a section named after the
//   generator provides `path`. With no `id` a new gist is created (POST /gists), otherwise the
//   existing one is patched (PATCH /gists/<id>); after a successful upload the file is rewritten
//   with [common] token/id/username plus a [<path>] section carrying type/url.

import { webPost, webPatch } from "./fetch";
import { fileGet, fileWrite, fileExist } from "./vfs";
import { global } from "../core/settings";
import { trim } from "./string";
import { INIReader } from "./ini";

export interface GistConf {
  token: string;
  id: string;
  username: string;
  /** section name → `path` item, i.e. the per-generator upload filename */
  paths: Map<string, string>;
  present: boolean;
}

const GIST_API = "https://api.github.com/gists";

// Exported for unit tests (the upload itself always talks to the GitHub API).
export function readGistConf(): GistConf {
  const conf: GistConf = { token: "", id: "", username: "", paths: new Map(), present: false };
  // Upstream parses gistconf.ini with a PLAIN INIReader (`ini.parse_file`, upload.cpp:44). The port
  // used `store_any_line` + `addDirectSaveSection("common")`, and in that mode the reader stores every
  // non-section line as a `{NONAME}` item holding the raw text (the direct-save branch runs before the
  // key=value branch), so `token=…` never became the key `token`, the key switch never matched, and
  // uploadGist always bailed out with "Gist token not set".
  const content = fileGet("gistconf.ini");
  if (content.length === 0) return conf;
  const ini = new INIReader();
  if (ini.parse(content) !== 0) return conf;
  conf.present = true;
  if (ini.sectionExist("common")) {
    conf.token = trim(ini.get("common", "token"));
    conf.id = trim(ini.get("common", "id"));
    conf.username = trim(ini.get("common", "username"));
  }
  for (const section of ini.getSectionNames()) {
    if (section === "common") continue;
    const p = trim(ini.get(section, "path"));
    if (p.length > 0) conf.paths.set(section, p);
  }
  return conf;
}

// Mirrors upstream's erase_section()/set()/to_file() rewrite of gistconf.ini: upstream erases only
// the current ([common]) and the [<path>] section, so sections recorded for OTHER generators are
// preserved. Exported for tests.
export async function writeGistConf(conf: GistConf, path: string, type: string, url: string): Promise<void> {
  const ini = new INIReader();
  const existing = fileGet("gistconf.ini");
  if (existing.length > 0) ini.parse(existing);

  let out = "[common]\n";
  out += "token=" + conf.token + "\n";
  out += "id=" + conf.id + "\n";
  out += "username=" + conf.username + "\n";
  out += "\n[" + path + "]\n";
  out += "type=" + type + "\n";
  out += "url=" + url + "\n";
  for (const section of ini.getSectionNames()) {
    if (section === "common" || section === path) continue;
    out += "\n[" + section + "]\n";
    for (const [k, v] of ini.getItems(section)) out += k + "=" + v + "\n";
  }
  await fileWrite("gistconf.ini", out, true);
}

export async function uploadGist(target: string, path: string, content: string, writeManageURL: boolean): Promise<void> {
  if (!global.uploadGist && path.length === 0) return;
  if (!fileExist("gistconf.ini")) {
    console.warn("gistconf.ini not found — skipping upload for target '" + target + "'.");
    return;
  }
  const conf = readGistConf();
  if (conf.token.length === 0) {
    console.warn("Gist token not set — skipping upload for target '" + target + "'.");
    return;
  }

  let uploadPath = trim(path);
  if (uploadPath.length === 0) {
    // upstream: `if(ini.item_exist("path")) path = ini.get(name, "path"); else path = name;`
    uploadPath = conf.paths.get(target) ?? target;
  }

  const headers: Record<string, string> = {
    Authorization: "token " + conf.token,
    "Content-Type": "application/json",
  };

  let result = "";
  if (conf.id.length === 0) {
    result = await webPost(GIST_API, buildGistData(uploadPath, content), { requestHeaders: headers, cacheTTL: 0 });
  } else {
    // `writeManageURL` (the caller's 4th argument) prepends the managed-config line — upstream
    // upload.cpp:87-88. The port ignored the parameter entirely, so uploaded Surge/Surfboard configs
    // lost the very header the feature exists for.
    const rawUrl = "https://gist.githubusercontent.com/" + conf.username + "/" + conf.id + "/raw/" + uploadPath;
    const body = writeManageURL ? "#!MANAGED-CONFIG " + rawUrl + "\n" + content : content;
    result = await webPatch(GIST_API + "/" + conf.id, buildGistData(uploadPath, body), { requestHeaders: headers, cacheTTL: 0 });
  }

  if (result.length === 0) {
    console.warn("Gist upload failed for target '" + target + "'.");
    return;
  }

  let id = conf.id;
  let username = conf.username;
  try {
    const parsed = JSON.parse(result) as Record<string, unknown>;
    if (typeof parsed["id"] === "string") id = parsed["id"];
    const owner = parsed["owner"] as Record<string, unknown> | undefined;
    if (owner && typeof owner["login"] === "string") username = owner["login"];
  } catch {
    console.warn("Gist upload returned unparsable data for target '" + target + "'.");
    return;
  }

  const url = "https://gist.githubusercontent.com/" + username + "/" + id + "/raw/" + uploadPath;
  conf.id = id;
  conf.username = username;
  await writeGistConf(conf, uploadPath, target, url);
  console.log("Gist uploaded: " + url);
}

function buildGistData(name: string, content: string): string {
  const files: Record<string, unknown> = {};
  files[name] = { content };
  return JSON.stringify({ description: "subconverter", public: false, files });
}
