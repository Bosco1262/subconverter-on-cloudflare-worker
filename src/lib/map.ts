// Port of src/utils/map_extra.h — case-insensitive map + multimap semantics

export class string_icase_map {
  private map = new Map<string, string>();

  get size(): number {
    return this.map.size;
  }

  set(key: string, value: string): this {
    this.map.set(key.toLowerCase(), value);
    return this;
  }

  get(key: string): string | undefined {
    return this.map.get(key.toLowerCase());
  }

  has(key: string): boolean {
    return this.map.has(key.toLowerCase());
  }

  delete(key: string): boolean {
    return this.map.delete(key.toLowerCase());
  }

  clear(): void {
    this.map.clear();
  }

  entries(): [string, string][] {
    return [...this.map.entries()];
  }

  forEach(fn: (value: string, key: string) => void): void {
    this.map.forEach(fn);
  }
}

// string_multimap (std::multimap) — ordered map allowing duplicate keys (insertion order for dups)
export class string_multimap {
  private items: [string, string][] = [];

  get size(): number {
    return this.items.length;
  }

  insert(key: string, value: string): void {
    // std::multimap: keys sorted; equal keys keep insertion order. We emulate ordering by sorted keys.
    this.items.push([key, value]);
  }

  emplace(key: string, value: string): void {
    this.insert(key, value);
  }

  // first value for key
  get(key: string): string | undefined {
    for (const [k, v] of this.items) if (k === key) return v;
    return undefined;
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  // all values for key (in insertion order)
  getAll(key: string): string[] {
    return this.items.filter(([k]) => k === key).map(([, v]) => v);
  }

  entries(): [string, string][] {
    // std::map/multimap iterates in key order (case-sensitive less)
    return [...this.items].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }

  clear(): void {
    this.items = [];
  }
}

// plain string->string map with sorted iteration (std::map semantics)
export class string_map {
  private map = new Map<string, string>();

  get size(): number {
    return this.map.size;
  }

  set(key: string, value: string): this {
    this.map.set(key, value);
    return this;
  }

  get(key: string): string | undefined {
    return this.map.get(key);
  }

  has(key: string): boolean {
    return this.map.has(key);
  }

  delete(key: string): boolean {
    return this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  entries(): [string, string][] {
    return [...this.map.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }
}
