// Port of src/utils/ini_reader/ini_reader.h — sections in named order, items in multimap (key-sorted) order

import { trim, trimWhitespace, toInt, toNumber, getLineBreak, processEscapeChar, processEscapeCharReverse } from "./string";

export const INIREADER_EXCEPTION = {
  EMPTY: -5,
  DUPLICATE: -4,
  OUTOFBOUND: -3,
  NOTEXIST: -2,
  NOTPARSED: -1,
  NONE: 0,
} as const;

export type IniItem = [string, string];

export class INIReader {
  store_any_line = false;
  store_isolated_line = false;
  allow_dup_section_titles = false;
  keep_empty_section = true;
  do_utf8_to_gbk = false;

  private parsed = false;
  private current_section = "";
  // section -> items (kept sorted by key, stable for equal keys, like std::multimap)
  private ini_content = new Map<string, IniItem[]>();
  private exclude_sections: string[] = [];
  private include_sections: string[] = [];
  private direct_save_sections: string[] = [];
  private section_order: string[] = [];
  private isolated_items_section = "";

  private last_error: number = INIREADER_EXCEPTION.NONE;

  private saveError(x: number): number {
    this.last_error = x;
    return x;
  }

  private chkIgnore(section: string): boolean {
    const excluded = this.exclude_sections.includes(section);
    const included = this.include_sections.length > 0 ? this.include_sections.includes(section) : true;
    return excluded || !included;
  }

  private chkDirectSave(section: string): boolean {
    return this.direct_save_sections.includes(section);
  }

  excludeSection(section: string): void {
    this.exclude_sections.push(section);
  }

  includeSection(section: string): void {
    this.include_sections.push(section);
  }

  addDirectSaveSection(section: string): void {
    this.direct_save_sections.push(section);
  }

  setIsolatedItemsSection(section: string): void {
    this.isolated_items_section = section;
  }

  eraseAll(): void {
    this.ini_content.clear();
    this.section_order = [];
    this.parsed = false;
  }

  parse(content: string): number {
    if (content.length === 0) return this.saveError(INIREADER_EXCEPTION.EMPTY);
    if (content.startsWith("\uFEFF")) content = content.substring(1);

    const sections = new Map<string, IniItem[]>();
    const order: string[] = [];
    let inIsolatedSection = false;
    let curSection = "";
    let itemGroup: IniItem[] = [];
    const read_sections: string[] = [];
    const delimiter = getLineBreak(content);

    const flushSection = (isFinal: boolean) => {
      if (curSection.length === 0) return;
      if (!(this.keep_empty_section || itemGroup.length > 0)) return;
      const existing = sections.get(curSection);
      if (existing) {
        if (this.allow_dup_section_titles || (isFinal && this.isolated_items_section === curSection)) {
          existing.push(...itemGroup);
          sortItems(existing);
        }
        // else: duplicate not allowed — upstream stops; we keep going with merged data
        return;
      }
      if (!inIsolatedSection || this.isolated_items_section !== curSection) {
        if (itemGroup.length > 0) read_sections.push(curSection);
        if (!order.includes(curSection)) order.push(curSection);
        sections.set(curSection, sortItems(itemGroup));
      }
    };

    const lines = content.split(delimiter === "\n" ? "\n" : "\r");
    let inExcludedSection = false;
    let inDirectSaveSection = false;

    if (this.store_isolated_line && this.isolated_items_section.length > 0) {
      curSection = this.isolated_items_section;
      inExcludedSection = this.chkIgnore(curSection);
      inDirectSaveSection = this.chkDirectSave(curSection);
      inIsolatedSection = true;
    }

    for (let rawLine of lines) {
      rawLine = trimWhitespace(rawLine);
      const lineSize = rawLine.length;
      const pos_equal = rawLine.indexOf("=");
      if ((lineSize === 0 || rawLine[0] === ";" || rawLine[0] === "#" || (lineSize >= 2 && rawLine[0] === "/" && rawLine[1] === "/")) && !inDirectSaveSection)
        continue;
      const strLine = processEscapeChar(rawLine);
      if (strLine.length === 0) continue;
      if (strLine[0] === "[" && strLine[strLine.length - 1] === "]") {
        const thisSection = strLine.substring(1, strLine.length - 1);
        inExcludedSection = this.chkIgnore(thisSection);
        inDirectSaveSection = this.chkDirectSave(thisSection);
        flushSection(false);
        inIsolatedSection = false;
        itemGroup = [];
        curSection = thisSection;
      } else if (((this.store_any_line && pos_equal === -1) || inDirectSaveSection) && !inExcludedSection && curSection.length > 0) {
        itemGroup.push(["{NONAME}", strLine]);
      } else if (pos_equal !== -1) {
        if (inExcludedSection) continue;
        if (curSection.length === 0) return this.saveError(INIREADER_EXCEPTION.OUTOFBOUND);
        const itemName = trim(strLine.substring(0, pos_equal));
        let posValue = pos_equal + 1;
        while (posValue < strLine.length && strLine[posValue] === " ") posValue++;
        if (posValue < strLine.length) {
          itemGroup.push([itemName, strLine.substring(posValue)]);
        } else {
          itemGroup.push([itemName, ""]);
        }
      }
      if (this.include_sections.length > 0 && arraysEqual(this.include_sections, read_sections)) break;
    }
    flushSection(true);

    this.ini_content = sections;
    this.section_order = order;
    this.parsed = true;
    return this.saveError(INIREADER_EXCEPTION.NONE);
  }

  sectionExist(section: string): boolean {
    return this.ini_content.has(section);
  }

  sectionCount(): number {
    return this.ini_content.size;
  }

  getSectionNames(): string[] {
    return [...this.section_order];
  }

  enterSection(section: string): number {
    if (!this.sectionExist(section)) return this.saveError(INIREADER_EXCEPTION.NOTEXIST);
    this.current_section = section;
    return this.saveError(INIREADER_EXCEPTION.NONE);
  }

  setCurrentSection(section: string): void {
    this.current_section = section;
  }

  itemExist(section: string, itemName: string): boolean {
    if (!this.sectionExist(section)) return false;
    const items = this.ini_content.get(section)!;
    return items.some(([k]) => k === itemName);
  }

  itemCount(section: string): number {
    const items = this.ini_content.get(section);
    return items ? items.length : 0;
  }

  // all items in section, in multimap (key-sorted) order
  getItems(section: string): IniItem[] {
    return this.ini_content.get(section) ?? [];
  }

  getItemsCurrent(): IniItem[] {
    return this.current_section ? this.getItems(this.current_section) : [];
  }

  // items with name prefix
  getAll(section: string, itemName: string): string[] {
    const items = this.ini_content.get(section);
    if (!items) return [];
    return items.filter(([k]) => k.startsWith(itemName)).map(([, v]) => v);
  }

  getAllCurrent(itemName: string): string[] {
    return this.current_section ? this.getAll(this.current_section, itemName) : [];
  }

  get(section: string, itemName: string): string {
    const items = this.ini_content.get(section);
    if (!items) return "";
    for (const [k, v] of items) if (k === itemName) return v;
    return "";
  }

  getCurrent(itemName: string): string {
    return this.current_section ? this.get(this.current_section, itemName) : "";
  }

  getBool(section: string, itemName: string): boolean {
    return this.get(section, itemName) === "true";
  }

  getInt(section: string, itemName: string): number {
    return toInt(this.get(section, itemName), 0);
  }

  getFirst(section: string, itemName: string): string {
    const all = this.getAll(section, itemName);
    return all.length > 0 ? all[0] : "";
  }

  set(section: string, itemName: string, itemVal: string): number {
    if (section.length === 0) return this.saveError(INIREADER_EXCEPTION.NOTEXIST);
    if (!this.parsed) this.parsed = true;
    const existing = this.ini_content.get(section);
    if (existing) {
      existing.push([itemName, itemVal]);
      sortItems(existing);
    } else {
      this.ini_content.set(section, sortItems([[itemName, itemVal]]));
      this.section_order.push(section);
    }
    return this.saveError(INIREADER_EXCEPTION.NONE);
  }

  setBool(section: string, itemName: string, itemVal: boolean): number {
    return this.set(section, itemName, itemVal ? "true" : "false");
  }

  erase(section: string, itemName: string): number {
    const items = this.ini_content.get(section);
    if (!items) return this.saveError(INIREADER_EXCEPTION.NOTEXIST);
    let removed = 0;
    for (let i = items.length - 1; i >= 0; i--) {
      if (items[i][0] === itemName) {
        items.splice(i, 1);
        removed++;
      }
    }
    return removed;
  }

  eraseFirst(section: string, itemName: string): number {
    const items = this.ini_content.get(section);
    if (!items) return this.saveError(INIREADER_EXCEPTION.NOTEXIST);
    const idx = items.findIndex(([k]) => k === itemName);
    if (idx !== -1) {
      items.splice(idx, 1);
      return this.saveError(INIREADER_EXCEPTION.NONE);
    }
    return this.saveError(INIREADER_EXCEPTION.NOTEXIST);
  }

  eraseSection(section: string): void {
    const items = this.ini_content.get(section);
    if (items) items.length = 0;
  }

  removeSection(section: string): void {
    this.ini_content.delete(section);
    const idx = this.section_order.indexOf(section);
    if (idx !== -1) this.section_order.splice(idx, 1);
  }

  renameSection(oldName: string, newName: string): number {
    if (!this.sectionExist(oldName) || this.sectionExist(newName)) return this.saveError(INIREADER_EXCEPTION.DUPLICATE);
    this.ini_content.set(newName, this.ini_content.get(oldName)!);
    this.ini_content.delete(oldName);
    const idx = this.section_order.indexOf(oldName);
    if (idx !== -1) this.section_order[idx] = newName;
    return this.saveError(INIREADER_EXCEPTION.NONE);
  }

  toString(): string {
    let content = "";
    if (!this.parsed) return "";
    for (const x of this.section_order) {
      content += "[" + x + "]\n";
      const section = this.ini_content.get(x);
      if (section) {
        if (section.length === 0) {
          content += "\n";
          continue;
        }
        for (const [k, v0] of section) {
          if (k !== "{NONAME}") content += k + "=";
          content += processEscapeCharReverse(v0) + "\n";
        }
      }
    }
    return content;
  }
}

function sortItems(items: IniItem[]): IniItem[] {
  // stable sort by key — std::multimap iteration order
  return items
    .map((item, i) => [item, i] as const)
    .sort((a, b) => (a[0][0] < b[0][0] ? -1 : a[0][0] > b[0][0] ? 1 : a[1] - b[1]))
    .map(([item]) => item);
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export { toNumber };
