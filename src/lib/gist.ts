// Port of src/handler/upload.cpp — Gist upload (webPost/webPatch)

import { webPost, webPatch } from "./fetch";
import { fileGet, fileWrite } from "./vfs";
import { global } from "../core/settings";
import { split, startsWith, trim } from "./string";
import { INIReader } from "./ini";

interface GistStruct {
  GistURL: string;
  GistToken: string;
  GistPath: string;
  GistDomain: string;
  GistContent: string;
}

const gistStruct: GistStruct = {
  GistURL: "",
  GistToken: "",
  GistPath: "",
  GistDomain: "",
  GistContent: "",
};

async function readGistConf(): Promise<void> {
  const content = fileGet("gistconf.ini");
  if (content.length === 0) return;
  const ini = new INIReader();
  ini.store_any_line = true;
  ini.addDirectSaveSection("common");
  if (ini.parse(content) !== 0) return;
  const common = ini.getItems("common");
  for (const [k, v] of common) {
    if (k === "{NONAME}") continue;
    const key = trim(k);
    switch (key) {
      case "GistURL":
      case "GistToken":
      case "GistPath":
      case "GistDomain":
        (gistStruct as unknown as Record<string, string>)[key] = trim(v);
        break;
      default:
        break;
    }
  }
}

export async function uploadGist(target: string, path: string, content: string, includeContent: boolean): Promise<void> {
  if (!global.uploadGist && path.length === 0) return;
  await readGistConf();

  let uploadURL = gistStruct.GistURL;
  if (uploadURL.length === 0) uploadURL = "https://api.github.com/gists";
  let uploadPath = gistStruct.GistPath;
  let token = gistStruct.GistToken;
  const uploader = split(path, "|")[0];
  if (uploader.length > 0) {
    // per-uploader override: "name|path" style
    const pos = path.indexOf("|");
    uploadPath = path.substring(pos + 1);
  } else {
    uploadPath = path.length > 0 ? path : uploadPath;
  }
  void uploader;

  if (uploadPath.length === 0) {
    console.warn("Gist upload path not provided — skipping upload for target '" + target + "'.");
    return;
  }
  if (token.length === 0) {
    console.warn("Gist token not set — skipping upload for target '" + target + "'.");
    return;
  }

  const headers: Record<string, string> = {
    Authorization: "Bearer " + token,
    "Content-Type": "application/json",
  };

  // check whether the gist already exists (stored GistURL map not available without KV; do a search by filename)
  let gistUrl = "";
  if (gistStruct.GistURL.length > 0 && startsWith(gistStruct.GistURL, "https://gist.github.com/")) {
    gistUrl = gistStruct.GistURL;
  }

  const fileName = uploadPath;
  const payload = (jsonUrl: string): string => {
    const files: Record<string, unknown> = {};
    files[fileName] = { content };
    const body: Record<string, unknown> = { files, public: false, description: "subconverter " + target };
    if (jsonUrl.length > 0) body["description"] = "subconverter " + target;
    return JSON.stringify(body);
  };

  let result = "";
  if (gistUrl.length > 0) {
    // PATCH existing gist — extract gist id
    const id = gistUrl.substring(gistUrl.lastIndexOf("/") + 1);
    result = await webPatch(uploadURL + "/" + id, payload(""), { requestHeaders: headers, cacheTTL: 0 });
  } else {
    result = await webPost(uploadURL, payload(""), { requestHeaders: headers, cacheTTL: 0 });
  }

  if (result.length > 0) {
    try {
      const parsed = JSON.parse(result) as Record<string, unknown>;
      const htmlUrl = parsed["html_url"];
      if (typeof htmlUrl === "string" && htmlUrl.length > 0) {
        gistStruct.GistURL = htmlUrl;
        // persist the gist url for later PATCHes (KV or in-isolate)
        await fileWrite("gistconf.ini", fileGet("gistconf.ini") + "\nGistURL=" + htmlUrl + "\n", true);
        console.log("Gist uploaded: " + htmlUrl);
        return;
      }
    } catch {
      // fallthrough
    }
  }
  console.warn("Gist upload failed for target '" + target + "'.");
  void includeContent;
  void split;
}
