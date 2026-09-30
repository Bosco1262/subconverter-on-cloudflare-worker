// Port of src/utils/tribool.h

export enum TriboolValue {
  Indeterminate = 0,
  False = 1,
  True = 2,
}

export class tribool {
  private value: TriboolValue = TriboolValue.Indeterminate;

  constructor(v?: boolean | string | tribool) {
    if (v === undefined) return;
    if (typeof v === "boolean") this.set(v);
    else if (typeof v === "string") this.setString(v);
    else if (v instanceof tribool) this.value = v.value;
  }

  static from(v: boolean | string | tribool | undefined): tribool {
    return new tribool(v);
  }

  isUndef(): boolean {
    return this.value === TriboolValue.Indeterminate;
  }

  // operator bool
  valueOf(): boolean {
    return this.value === TriboolValue.True;
  }

  get(defValue = false): boolean {
    if (this.isUndef()) return defValue;
    return this.value === TriboolValue.True;
  }

  getStr(): string {
    switch (this.value) {
      case TriboolValue.Indeterminate:
        return "undef";
      case TriboolValue.False:
        return "false";
      case TriboolValue.True:
        return "true";
    }
  }

  // tribool& define(const T&): only sets when currently undefined
  define(value: boolean | tribool): this {
    if (this.isUndef()) {
      if (typeof value === "boolean") this.set(value);
      else this.value = value.value;
    }
    return this;
  }

  // alias used in some call sites
  parse(value: boolean | tribool): this {
    return this.define(value);
  }

  reverse(): this {
    if (this.value === TriboolValue.False) this.value = TriboolValue.True;
    else if (this.value === TriboolValue.True) this.value = TriboolValue.False;
    return this;
  }

  set(value: boolean): this {
    this.value = value ? TriboolValue.True : TriboolValue.False;
    return this;
  }

  setString(str: string): boolean {
    switch (str) {
      case "true":
      case "1":
        this.value = TriboolValue.True;
        break;
      case "false":
      case "0":
        this.value = TriboolValue.False;
        break;
      default: {
        // to_int(str, 0) > 1 → true; else indeterminate
        let n = 0;
        const m = /^[ \t\n\v\f\r]*([+-]?\d+)/.exec(str);
        if (m) n = parseInt(m[1], 10);
        else n = 0;
        if (str.length > 0 && n > 1) this.value = TriboolValue.True;
        else this.value = TriboolValue.Indeterminate;
        break;
      }
    }
    return !this.isUndef();
  }

  clear(): void {
    this.value = TriboolValue.Indeterminate;
  }

  eq(other: tribool): boolean {
    return this.value === other.value;
  }
}
