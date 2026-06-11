import { isIP } from "node:net";
import type { IndicatorType } from "../domain/models.js";

const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$/;
const SHA256_PATTERN = /^[A-Fa-f0-9]{64}$/;
const SHA1_PATTERN = /^[A-Fa-f0-9]{40}$/;
const MD5_PATTERN = /^[A-Fa-f0-9]{32}$/;
const USER_PATTERN = /^[A-Za-z0-9._@\\-]{1,128}$/;

export function isValidIp(value: string): boolean {
  return isIP(value) !== 0;
}

export function isValidDomain(value: string): boolean {
  return DOMAIN_PATTERN.test(value);
}

export function isValidHash(value: string): boolean {
  return SHA256_PATTERN.test(value) || SHA1_PATTERN.test(value) || MD5_PATTERN.test(value);
}

export function isValidUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

export function isValidUser(value: string): boolean {
  return USER_PATTERN.test(value);
}

export function normalizeIndicator(type: IndicatorType, value: string): string {
  const trimmed = value.trim();
  if (type === "domain" || type === "url" || type === "hash") {
    return trimmed.toLowerCase();
  }
  return trimmed;
}

export function isPrivateIp(value: string): boolean {
  if (isIP(value) === 0) {
    return false;
  }

  if (value.includes(":")) {
    const lower = value.toLowerCase();
    return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80:");
  }

  const octets = value.split(".").map((entry) => Number(entry));
  const [first, second] = octets;
  if (first === undefined || second === undefined) {
    return false;
  }

  return (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    first === 127 ||
    (first === 169 && second === 254)
  );
}
