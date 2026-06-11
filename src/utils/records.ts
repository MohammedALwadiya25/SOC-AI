import { isPlainRecord } from "../domain/errors.js";

export function getPath(source: unknown, path: readonly string[]): unknown {
  let current = source;
  for (const segment of path) {
    if (!isPlainRecord(current)) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

export function firstDefined(...values: unknown[]): unknown {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

export function asString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  return undefined;
}

export function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

export function asStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const strings = value.map((entry) => asString(entry)).filter((entry): entry is string => entry !== undefined);
    return strings.length > 0 ? strings : undefined;
  }
  const single = asString(value);
  return single ? [single] : undefined;
}

export function pickDefined(entries: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(entries).filter(([, value]) => value !== undefined && value !== null && value !== ""),
  );
}
