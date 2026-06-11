import { ZodError } from "zod/v4";
import type { SafeError } from "./models.js";

export const ERROR_CODES = {
  VALIDATION: "VALIDATION_ERROR",
  CONFIGURATION: "CONFIGURATION_ERROR",
  UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
  UPSTREAM_AUTH: "UPSTREAM_AUTHENTICATION_FAILED",
  UPSTREAM_TIMEOUT: "UPSTREAM_TIMEOUT",
  UPSTREAM_BAD_RESPONSE: "UPSTREAM_BAD_RESPONSE",
  NOT_FOUND: "NOT_FOUND",
  RATE_LIMITED: "RATE_LIMITED",
  INTERNAL: "INTERNAL_ERROR",
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

export class AppError extends Error {
  public readonly code: ErrorCode;
  public readonly safeDetails?: Record<string, unknown>;

  public constructor(code: ErrorCode, message: string, safeDetails?: Record<string, unknown>) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.safeDetails = safeDetails;
  }
}

const SECRET_KEY_PATTERN =
  /(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|set-cookie|connection[_-]?string|client[_-]?secret)/i;

const SECRET_VALUE_PATTERNS: RegExp[] = [
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /Basic\s+[A-Za-z0-9+/=]+/gi,
  /(password|token|secret|api[_-]?key)=([^&\s]+)/gi,
  /(https?:\/\/)([^:@/\s]+):([^@/\s]+)@/gi,
  /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)+[^\\/:*?"<>|\r\n]*/g,
];

export function redactSecrets(value: unknown): unknown {
  if (typeof value === "string") {
    return redactString(value);
  }

  if (Array.isArray(value)) {
    return value.map((entry) => redactSecrets(entry));
  }

  if (isPlainRecord(value)) {
    const redacted: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      redacted[key] = SECRET_KEY_PATTERN.test(key) ? "[REDACTED]" : redactSecrets(entry);
    }
    return redacted;
  }

  return value;
}

export function redactString(value: string): string {
  return SECRET_VALUE_PATTERNS.reduce(
    (current, pattern) => current.replace(pattern, (match: string, ...groups: string[]) => {
      if (pattern.source.includes("https?")) {
        return `${groups[0] ?? ""}[REDACTED]@`;
      }
      if (pattern.source.includes("password|token")) {
        return `${groups[0] ?? "secret"}=[REDACTED]`;
      }
      return match.includes(":\\") ? "[REDACTED_PATH]" : "[REDACTED]";
    }),
    value,
  );
}

export function toSafeError(error: unknown): SafeError {
  if (error instanceof AppError) {
    return {
      code: error.code,
      message: redactString(error.message),
      details: error.safeDetails ? (redactSecrets(error.safeDetails) as Record<string, unknown>) : undefined,
    };
  }

  if (error instanceof ZodError) {
    return {
      code: ERROR_CODES.VALIDATION,
      message: "Invalid request input.",
      details: {
        issues: error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      },
    };
  }

  return {
    code: ERROR_CODES.INTERNAL,
    message: "An internal error occurred while processing the request.",
  };
}

export function errorCodeFromHttpStatus(status: number): ErrorCode {
  if (status === 401 || status === 403) {
    return ERROR_CODES.UPSTREAM_AUTH;
  }
  if (status === 404) {
    return ERROR_CODES.NOT_FOUND;
  }
  if (status === 408 || status === 504) {
    return ERROR_CODES.UPSTREAM_TIMEOUT;
  }
  if (status === 429) {
    return ERROR_CODES.RATE_LIMITED;
  }
  return ERROR_CODES.UPSTREAM_UNAVAILABLE;
}

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
