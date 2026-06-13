import { stripVTControlCharacters } from "node:util";
import type { AnalyzeResponse as APIResponse } from "../api/analyze.js";

export function sanitize(s: string): string {
  return stripVTControlCharacters(s);
}

export function sanitizeDeep<T>(value: T): T {
  if (typeof value === "string") {
    return stripVTControlCharacters(value) as unknown as T;
  }
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => sanitizeDeep(v)) as unknown as T;
  }
  if (typeof value === "object") {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(src)) {
      const cleanKey = stripVTControlCharacters(k);
      out[cleanKey] = sanitizeDeep(src[k]);
    }
    return out as unknown as T;
  }
  return value;
}

export function sanitizeResponse(response: APIResponse): APIResponse {
  return sanitizeDeep(response);
}
