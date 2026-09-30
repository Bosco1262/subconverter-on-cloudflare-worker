import { describe, expect, it } from "vitest";
import { renderTemplate } from "../../src/lib/template-mini";

describe("template-mini (inja subset)", () => {
  it("renders variables with default()", () => {
    const out = renderTemplate(
      'port: {{ default(global.clash.http_port, "7890") }}',
      { global: { clash: {} } },
      { callbacks: {} },
    );
    expect(out).toBe("port: 7890");
  });

  it("renders set values over default", () => {
    const out = renderTemplate(
      'port: {{ default(global.clash.http_port, "7890") }}',
      { global: { clash: { http_port: "8080" } } },
      { callbacks: {} },
    );
    expect(out).toBe("port: 8080");
  });

  it("if/else with string comparison", () => {
    const tpl = '{% if request.target == "clash" %}A{% else %}B{% endif %}';
    expect(renderTemplate(tpl, { request: { target: "clash" } }, { callbacks: {} })).toBe("A");
    expect(renderTemplate(tpl, { request: { target: "surge" } }, { callbacks: {} })).toBe("B");
  });

  it("lstrip_blocks + trim_blocks removes control lines", () => {
    const tpl = "{% if x == \"1\" %}\nline1\n{% endif %}\nline2\n";
    expect(renderTemplate(tpl, { x: "1" }, { callbacks: {} })).toBe("line1\nline2\n");
    const tpl2 = '{% if x == "1" %}\nA\n{% else %}\nB\n{% endif %}\nC';
    expect(renderTemplate(tpl2, { x: "0" }, { callbacks: {} })).toBe("B\nC");
  });

  it("bool() and nested calls", () => {
    const tpl = '{% if bool(default(global.singbox.allow_lan, "")) %}LAN{% else %}LOOP{% endif %}';
    expect(renderTemplate(tpl, { global: { singbox: { allow_lan: "true" } } }, { callbacks: {} })).toBe("LAN");
    expect(renderTemplate(tpl, { global: { singbox: { allow_lan: "" } } }, { callbacks: {} })).toBe("LOOP");
  });

  it("for loop", () => {
    const out = renderTemplate("{% for x in list %}[{{ x }}]{% endfor %}", { list: ["a", "b"] }, { callbacks: {} });
    expect(out).toBe("[a][b]");
  });

  it("set + find/replace callbacks", () => {
    const out = renderTemplate(
      '{% set key = "abc" %}{{ key }}-{{ find("hello", "ell") }}',
      {},
      { callbacks: { find: { arity: 2, fn: (args) => String(args[0]).includes(String(args[1])) } } },
    );
    expect(out).toBe("abc-true");
  });

  it("or/and/not", () => {
    expect(renderTemplate('{% if a == "1" or b == "1" %}Y{% else %}N{% endif %}', { a: "1", b: "" }, { callbacks: {} })).toBe("Y");
    expect(renderTemplate('{% if a == "1" and b == "1" %}Y{% else %}N{% endif %}', { a: "1", b: "" }, { callbacks: {} })).toBe("N");
  });

  it("UrlEncode callback", () => {
    const out = renderTemplate("{{ UrlEncode(v) }}", { v: "a b&c" }, { callbacks: { UrlEncode: { arity: 1, fn: (args) => encodeURIComponent(String(args[0])) } } });
    expect(out).toBe("a%20b%26c");
  });
});
