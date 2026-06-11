import type { AppConfig } from "../../infrastructure/config.js";

export interface ServiceContext {
  config: AppConfig;
}

export function effectiveLimit(requested: number | undefined, context: ServiceContext): number {
  return Math.min(requested ?? context.config.defaultLimit, context.config.maxLimit);
}
