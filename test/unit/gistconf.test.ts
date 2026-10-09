import { describe, expect, it } from "vitest";
import { INIReader } from "../../src/lib/ini";
import { readGistConf, writeGistConf, uploadGist } from "../../src/lib/gist";
import { fileGet, fileWrite } from "../../src/lib/vfs";

// Gist upload (src/lib/gist.ts) — port of src/handler/upload.cpp.
//
// Upstream requires gistconf.ini to hold a [common] section with `token` (plus optional `id` and
// `username`), parsed with a PLAIN INIReader. The port used to configure the reader with
// `store_any_line` + `addDirectSaveSection("common")`, and in that mode the reader stores every
// non-section line as a `{NONAME}` item holding the raw text (the direct-save branch runs before the
// key=value branch), so `token=…` never became the key `token` and every upload bailed out with
// "Gist token not set". It also read the wrong key names (GistToken/GistURL/GistPath instead of
// token/id/username) and wrote back a bare `GistURL=` line that the reader rejected as OUTOFBOUND.

describe("gistconf.ini parsing", () => {
  it("reads an upstream-shaped [common] section", async () => {
    await fileWrite(
      "gistconf.ini",
      "[common]\ntoken=ghp_x\nid=abc123\nusername=alice\n\n[clash]\ntype=clash\nurl=https://gist.githubusercontent.com/alice/abc123/raw/custom.yaml\npath=custom.yaml\n",
      true,
    );
    const conf = readGistConf();
    expect(conf.token).toBe("ghp_x");
    expect(conf.id).toBe("abc123");
    expect(conf.username).toBe("alice");
    // per-generator upload path, upstream `ini.get(name, "path")`
    expect(conf.paths.get("clash")).toBe("custom.yaml");
  });

  it("ignores a file without a [common] section", async () => {
    await fileWrite("gistconf.ini", "[other]\ntoken=nope\n", true);
    expect(readGistConf().token).toBe("");
  });

  it("returns empty values when the file is missing", async () => {
    await fileWrite("gistconf.ini", "", true);
    const conf = readGistConf();
    expect([conf.token, conf.present]).toEqual(["", false]);
  });

  it("documents why the direct-save reader configuration broke it", () => {
    // The old configuration: every line of [common] became a {NONAME} raw-text item.
    const direct = new INIReader();
    direct.store_any_line = true;
    direct.addDirectSaveSection("common");
    expect(direct.parse("[common]\ntoken=ghp_x\n")).toBe(0);
    expect(direct.getItems("common")).toEqual([["{NONAME}", "token=ghp_x"]]);
    expect(direct.get("common", "token")).toBe("");

    // A plain reader reads the token.
    const plain = new INIReader();
    expect(plain.parse("[common]\ntoken=ghp_x\n")).toBe(0);
    expect(plain.get("common", "token")).toBe("ghp_x");
  });
});

describe("gistconf.ini write-back", () => {
  it("round-trips through readGistConf", async () => {
    await writeGistConf(
      { token: "ghp_x", id: "id1", username: "bob", paths: new Map(), present: true },
      "clash",
      "clash",
      "https://gist.githubusercontent.com/bob/id1/raw/clash",
    );
    const conf = readGistConf();
    expect([conf.token, conf.id, conf.username]).toEqual(["ghp_x", "id1", "bob"]);
    const content = fileGet("gistconf.ini");
    expect(content).toContain("[common]");
    expect(content).toContain("[clash]");
    expect(content).toContain("url=https://gist.githubusercontent.com/bob/id1/raw/clash");
    // the old bare-key write-back shape must be gone (the reader returned OUTOFBOUND on it)
    expect(content).not.toContain("GistURL=");
  });

  it("keeps sections recorded for other generators (upstream erases only common + the current path)", async () => {
    await fileWrite(
      "gistconf.ini",
      "[common]\ntoken=t\nid=i\nusername=u\n\n[surge]\ntype=surge\nurl=old\npath=surge.conf\n",
      true,
    );
    await writeGistConf({ token: "t", id: "i", username: "u", paths: new Map(), present: true }, "clash", "clash", "https://x/clash");
    const content = fileGet("gistconf.ini");
    expect(content).toContain("[clash]");
    expect(content).toContain("[surge]");
    expect(content).toContain("path=surge.conf");
    expect(readGistConf().paths.get("surge")).toBe("surge.conf");

    // rewriting the same path must replace, not duplicate, that section
    await writeGistConf({ token: "t", id: "i", username: "u", paths: new Map(), present: true }, "clash", "clash", "https://x/clash2");
    const again = fileGet("gistconf.ini");
    expect((again.match(/\[clash\]/g) ?? []).length).toBe(1);
    expect(again).toContain("https://x/clash2");
  });
});

describe("uploadGist guards", () => {
  it("skips without a token instead of calling the API", async () => {
    await fileWrite("gistconf.ini", "[common]\nid=abc\n", true);
    // an explicit path so the first guard (dead global flag + empty path) does not short-circuit;
    // must resolve without throwing and without any network access
    await expect(uploadGist("clash", "custom.yaml", "content", true)).resolves.toBeUndefined();
  });

  it("skips when gistconf.ini is empty", async () => {
    await fileWrite("gistconf.ini", "", true);
    await expect(uploadGist("clash", "custom.yaml", "content", true)).resolves.toBeUndefined();
  });
});
