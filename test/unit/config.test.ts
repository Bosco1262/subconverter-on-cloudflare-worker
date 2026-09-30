import { describe, expect, it } from "vitest";
import { regReplace, regFind, regGetMatch } from "../../src/lib/regex";
import { readTOMLConf, global } from "../../src/core/settings";
import { fileCopy, fileGet } from "../../src/lib/vfs";

describe("pref config loading (workerd)", () => {
  it("rename regex from pref behaves like PCRE2 (倍率 → x normalization)", () => {
    // upstream rename_node rule: visible effect is "N倍率" → "Nx"
    const p = "\\(?((x|X)?(\\d+)(\\.?\\d+)?)((\\s?倍率?)|(x|X))\\)?";
    expect(regReplace("香港 2倍率", p, "$1x")).toBe("香港 2x");
    expect(regReplace("香港 2x", p, "$1x")).toBe("香港 2x");
    expect(regReplace("香港 01", p, "$1x")).toBe("香港 01");
  });

  it("loads pref.example.toml with snippets imports", async () => {
    fileCopy("pref.example.toml", "pref.toml");
    const ok = await readTOMLConf(fileGet("pref.example.toml"));
    expect(ok).toBe(true);
    expect(global.clashBase).toBe("base/all_base.tpl");
    expect(global.renames.length).toBe(1);
    expect(global.emojis.length).toBeGreaterThan(3);
    expect(global.currentRulesets.length).toBeGreaterThan(3);
    expect(global.customProxyGroups.length).toBeGreaterThan(3);
    expect(global.excludeRemarks).toEqual(["(到期|剩余流量|时间|官网|产品)"]);
    expect(global.templateVars["clash.http_port"]).toBe("7890");
  });
});
