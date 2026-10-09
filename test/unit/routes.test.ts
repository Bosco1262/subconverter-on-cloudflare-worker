import { describe, expect, it, beforeAll } from "vitest";
import { versionHandler, flushCacheHandler, readConfHandler, updateConfHandler, getUrlHandler, getLocalHandler, VERSION } from "../../src/routes/routes";
import { renderTemplateHandler, getProfileHandler } from "../../src/routes/handlers";
import type { SubRequest } from "../../src/core/orchestrator";
import { readConf, global } from "../../src/core/settings";
import { fileGet, fileCopy } from "../../src/lib/vfs";
import { base64Encode } from "../../src/lib/base64";

beforeAll(async () => {
  if (fileGet("pref.toml").length === 0) {
    for (const [src, dest] of [
      ["pref.example.toml", "pref.toml"],
      ["pref.example.yml", "pref.yml"],
      ["pref.example.ini", "pref.ini"],
    ] as const) {
      if (fileGet(src).length > 0) {
        fileCopy(src, dest);
        break;
      }
    }
  }
  await readConf();
});

function req(args: [string, string][] = []): SubRequest {
  return { method: "GET", argument: args, headers: new Map(), userAgent: "" };
}

describe("admin routes", () => {
  it("/version reports the worker backend", () => {
    const r = versionHandler();
    expect(r.status).toBe(200);
    expect(r.body).toBe(`subconverter ${VERSION} backend\n`);
    expect(VERSION).toBe("1.0.0-worker");
  });

  it("/flushcache returns done", () => {
    const r = flushCacheHandler();
    expect(r.status).toBe(200);
    expect(r.body).toBe("done\n");
  });

  it("/readconf reloads pref", async () => {
    const r = await readConfHandler();
    expect(r.status).toBe(200);
    expect(r.body).toBe("done\n");
  });

  it("/updateconf writes the conf and reloads it", async () => {
    const before = global.defaultUrls.length;
    void before;
    const body = '[common]\napi_mode = false\napi_access_token = "password"\ndefault_url = []\nenable_insert = true\ninsert_url = []\nprepend_insert_url = true\nenable_rule_generator = true\noverwrite_original_rules = false\n';
    const r = await updateConfHandler(body);
    expect(r.status).toBe(200);
    expect(r.body).toBe("done\n");
    // reload the real example pref so later tests in this file see the standard settings
    const original = fileGet("pref.example.toml");
    const restored = await updateConfHandler(original);
    expect(restored.status).toBe(200);
  });

  it("/get proxies a data uri", async () => {
    const r = await getUrlHandler("data:text/plain,hello");
    expect(r.status).toBe(200);
    expect(r.body).toBe("hello");
  });

  it("/getlocal reads an embedded file", () => {
    const r = getLocalHandler("pref.example.toml");
    expect(r.status).toBe(200);
    expect(r.body).toContain("[common]");
  });
});

describe("/render", () => {
  it("with an empty template_path any existing file passes the scope check (upstream parity)", async () => {
    // interfaces.cpp:1394 — `!startsWith(path, global.templatePath) || !fileExist(path)`; when
    // template_path is "" every path satisfies startsWith, so only fileExist() gates the render.
    const saved = global.templatePath;
    global.templatePath = "";
    const r = await renderTemplateHandler(req([["path", "base/all_base.tpl"], ["target", "clash"]]));
    global.templatePath = saved;
    expect(r.status, r.body.substring(0, 200)).toBe(200);
    expect(r.body).toContain("port:");
  });

  it("404s for a template outside template_path", async () => {
    const saved = global.templatePath;
    global.templatePath = "snippets/";
    const r = await renderTemplateHandler(req([["path", "base/all_base.tpl"]]));
    global.templatePath = saved;
    expect(r.status).toBe(404);
  });

  it("404s for a missing file", async () => {
    const saved = global.templatePath;
    global.templatePath = "";
    const r = await renderTemplateHandler(req([["path", "base/nope.tpl"]]));
    global.templatePath = saved;
    expect(r.status).toBe(404);
  });

  it("renders a template inside template_path", async () => {
    const saved = global.templatePath;
    global.templatePath = "base/";
    const r = await renderTemplateHandler(req([["path", "base/all_base.tpl"], ["target", "clash"]]));
    global.templatePath = saved;
    expect(r.status, r.body.substring(0, 200)).toBe(200);
    expect(r.body).toContain("port:");
  });
});

describe("/getprofile", () => {
  it("403 without name/token", async () => {
    const r = await getProfileHandler(req([]));
    expect(r.status).toBe(403);
  });

  it("404 for an unknown profile", async () => {
    const r = await getProfileHandler(req([["name", "profiles/nope.ini"], ["token", "password"]]));
    expect(r.status).toBe(404);
  });

  it("passes a resolvable profile through to subconverter()", async () => {
    // The embedded example_profile.ini points at a live trojan server; install a temporary profile
    // whose url is an inline data subscription so the profile -> subconverter() wiring is exercised
    // fully offline. The url is stored base64-wrapped, matching how the handler re-fetches it.
    const sub = base64Encode(
      ["ss://YWVzLTI1Ni1nY206cHcx@1.2.3.4:8388", "ss://YWVzLTI1Ni1nY206cHcx@5.6.7.8:8388"].join("\n"),
    );
    const link = "data:application/octet-stream;base64," + base64Encode(sub);
    const { fileWrite } = await import("../../src/lib/vfs");
    await fileWrite("profiles/unit_test_profile.ini", `[Profile]\ntarget=mixed\nurl=${link}\n`);
    const r = await getProfileHandler(req([["name", "profiles/unit_test_profile.ini"], ["token", "password"]]));
    console.log("PROFILE_STATUS=" + r.status + " LEN=" + r.body.length);
    expect(r.status, r.body.substring(0, 200)).toBe(200);
    expect(r.body.length).toBeGreaterThan(0);
  });
});
