// YAML stringify helper (yaml-cpp YAML::Dump equivalent — block style)

import { stringify as yamlStringify } from "yaml";

export function stringify(value: unknown): string {
  return yamlStringify(value, { lineWidth: 0, version: "1.1" });
}
