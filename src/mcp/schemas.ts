import * as z from "zod/v4";
import {
  isValidDomain,
  isValidHash,
  isValidIp,
  isValidUrl,
  isValidUser,
} from "../utils/indicator.js";

const isoTimestampSchema = z
  .string()
  .min(1)
  .refine((value) => !Number.isNaN(Date.parse(value)), "Invalid timestamp.");

export const timeRangeSchema = z
  .object({
    start: isoTimestampSchema,
    end: isoTimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    const start = Date.parse(value.start);
    const end = Date.parse(value.end);
    if (start >= end) {
      context.addIssue({
        code: "custom",
        path: ["end"],
        message: "Time range end must be after start.",
      });
      return;
    }

    const maxDays = 31;
    if (end - start > maxDays * 24 * 60 * 60 * 1000) {
      context.addIssue({
        code: "custom",
        path: ["end"],
        message: `Time range must not exceed ${maxDays} days.`,
      });
    }
  });

export const limitSchema = z.number().int().min(1).max(500);
export const severityScoreSchema = z.number().int().min(0).max(15);
export const alertIdSchema = z.string().min(1).max(256).regex(/^[A-Za-z0-9_.:@-]+$/);
export const agentIdSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9_.:@-]+$/);
export const ruleIdSchema = z.string().min(1).max(128).regex(/^[A-Za-z0-9_.:@-]+$/);
export const ipSchema = z.string().refine(isValidIp, "Invalid IP address.");
export const domainSchema = z.string().refine(isValidDomain, "Invalid domain.");
export const urlSchema = z.string().refine(isValidUrl, "Invalid URL.");
export const hashSchema = z.string().refine(isValidHash, "Invalid hash.");
export const userSchema = z.string().refine(isValidUser, "Invalid user identifier.");
export const mitreTechniqueIdSchema = z.string().regex(/^T\d{4}(?:\.\d{3})?$/);
export const keywordSchema = z
  .string()
  .min(1)
  .max(128)
  .refine((value) => !/[\u0000-\u001F]/.test(value), "Keyword contains control characters.");

const baseQuerySchema = z
  .object({
    timeRange: timeRangeSchema.optional(),
    limit: limitSchema.optional(),
  })
  .strict();

export const emptyInputSchema = z.object({}).strict();

export const alertListInputSchema = baseQuerySchema;

export const alertSearchInputSchema = baseQuerySchema
  .extend({
    keyword: keywordSchema.optional(),
    severityMin: severityScoreSchema.optional(),
    agentId: agentIdSchema.optional(),
    ruleId: ruleIdSchema.optional(),
    ip: ipSchema.optional(),
  })
  .strict();

export const alertByIdInputSchema = z
  .object({
    alertId: alertIdSchema,
  })
  .strict();

export const highSeverityInputSchema = baseQuerySchema
  .extend({
    severityMin: severityScoreSchema.default(10),
  })
  .strict();

export const agentListInputSchema = z
  .object({
    status: z.enum(["active", "disconnected", "never_connected", "pending"]).optional(),
    osPlatform: z.string().min(1).max(64).optional(),
    limit: limitSchema.optional(),
  })
  .strict();

export const agentByIdInputSchema = z
  .object({
    agentId: agentIdSchema,
  })
  .strict();

export const zeekFilterSchema = z
  .object({
    sourceIp: ipSchema.optional(),
    destinationIp: ipSchema.optional(),
    protocol: z.string().min(1).max(32).optional(),
    service: z.string().min(1).max(64).optional(),
    query: domainSchema.optional(),
    answer: z.string().min(1).max(253).optional(),
  })
  .strict();

export const zeekSearchInputSchema = baseQuerySchema
  .extend({
    logType: z.enum(["dns", "conn", "http", "ssl", "notice", "files"]).optional(),
    filters: zeekFilterSchema.optional(),
  })
  .strict();

export const zeekBeaconingInputSchema = baseQuerySchema
  .extend({
    sourceIp: ipSchema.optional(),
    destinationIp: ipSchema.optional(),
  })
  .strict();

export const suricataFilterSchema = z
  .object({
    sourceIp: ipSchema.optional(),
    destinationIp: ipSchema.optional(),
    signature: keywordSchema.optional(),
    signatureId: z.string().min(1).max(64).regex(/^[A-Za-z0-9_.:-]+$/).optional(),
    category: z.string().min(1).max(128).optional(),
    severityMin: z.number().int().min(1).max(5).optional(),
  })
  .strict();

export const suricataSearchInputSchema = baseQuerySchema
  .extend({
    filters: suricataFilterSchema.optional(),
  })
  .strict();

export const topNInputSchema = baseQuerySchema
  .extend({
    limit: z.number().int().min(1).max(100).optional(),
  })
  .strict();

export const timelineInputSchema = baseQuerySchema
  .extend({
    bucketSizeMinutes: z.number().int().min(1).max(1440).default(60),
  })
  .strict();

export const mitreMapAlertInputSchema = z
  .object({
    alertId: alertIdSchema.optional(),
    alert: z.record(z.string(), z.unknown()).optional(),
  })
  .strict()
  .refine((value) => value.alertId !== undefined || value.alert !== undefined, {
    message: "Either alertId or alert is required.",
  });

export const mitreTechniqueInputSchema = z
  .object({
    techniqueId: mitreTechniqueIdSchema,
  })
  .strict();

export const mitreCoverageInputSchema = z
  .object({
    ruleId: ruleIdSchema.optional(),
    group: z.string().min(1).max(128).optional(),
    limit: limitSchema.optional(),
  })
  .strict();

export const correlateIpInputSchema = z
  .object({
    ip: ipSchema,
    timeRange: timeRangeSchema.optional(),
    limit: limitSchema.optional(),
  })
  .strict();

export const correlateAlertInputSchema = z
  .object({
    alertId: alertIdSchema,
    windowMinutes: z.number().int().min(1).max(1440).default(30),
    limit: limitSchema.optional(),
  })
  .strict();

export const summarizeIncidentInputSchema = z
  .object({
    alertIds: z.array(alertIdSchema).min(1).max(25).optional(),
    entityIp: ipSchema.optional(),
    timeRange: timeRangeSchema.optional(),
    limit: limitSchema.optional(),
  })
  .strict()
  .refine((value) => value.alertIds !== undefined || value.entityIp !== undefined, {
    message: "Either alertIds or entityIp is required.",
  });

export const reasonIncidentInputSchema = summarizeIncidentInputSchema
  .extend({
    question: z.string().min(1).max(500).optional(),
  })
  .strict();

export const enrichIndicatorInputSchema = z
  .object({
    type: z.enum(["ip", "domain", "url", "hash", "user"]),
    value: z.string().min(1).max(2048),
  })
  .strict()
  .superRefine((value, context) => {
    const valid =
      (value.type === "ip" && isValidIp(value.value)) ||
      (value.type === "domain" && isValidDomain(value.value)) ||
      (value.type === "url" && isValidUrl(value.value)) ||
      (value.type === "hash" && isValidHash(value.value)) ||
      (value.type === "user" && isValidUser(value.value));

    if (!valid) {
      context.addIssue({
        code: "custom",
        path: ["value"],
        message: `Invalid ${value.type} indicator.`,
      });
    }
  });

export function publicInputSchema(keys: readonly string[]): z.ZodObject<Record<string, z.ZodOptional<z.ZodUnknown>>> {
  const shape = Object.fromEntries(keys.map((key) => [key, z.unknown().optional()]));
  return z.object(shape).passthrough();
}
