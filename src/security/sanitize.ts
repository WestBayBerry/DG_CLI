import { stripVTControlCharacters } from "node:util";
import type { AnalyzeResponse as APIResponse } from "../api/analyze.js";

const CTRL_KEEP_NEWLINE = /[\x00-\x08\x0B-\x1F\x7F-\x9F]/g;
const CTRL_ALL = /[\x00-\x1F\x7F-\x9F]/g;

export function sanitize(s: string): string {
  return stripVTControlCharacters(s).replace(CTRL_KEEP_NEWLINE, "");
}

export function sanitizeLine(s: string): string {
  return stripVTControlCharacters(s).replace(/[\r\n]+/g, " ").replace(CTRL_ALL, "");
}

export function sanitizeDeep<T>(value: T): T {
  if (typeof value === "string") {
    return sanitize(value) as unknown as T;
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
      out[sanitizeLine(k)] = sanitizeDeep(src[k]);
    }
    return out as unknown as T;
  }
  return value;
}

export function sanitizeResponse(response: APIResponse): APIResponse {
  return sanitizeDeep(response);
}
