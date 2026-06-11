import type { ErrorEnvelope, ResponseEnvelope, ResponseMeta, SafeError, SuccessEnvelope } from "./models.js";

export function successEnvelope<TData>(
  data: TData,
  meta: Omit<ResponseMeta, "timestamp"> & Partial<Pick<ResponseMeta, "timestamp">> = {},
): SuccessEnvelope<TData> {
  return {
    success: true,
    data,
    error: null,
    meta: {
      ...meta,
      timestamp: meta.timestamp ?? new Date().toISOString(),
    },
  };
}

export function errorEnvelope(
  error: SafeError,
  meta: Omit<ResponseMeta, "timestamp"> & Partial<Pick<ResponseMeta, "timestamp">> = {},
): ErrorEnvelope {
  return {
    success: false,
    data: null,
    error,
    meta: {
      ...meta,
      timestamp: meta.timestamp ?? new Date().toISOString(),
    },
  };
}

export function isSuccessEnvelope<TData>(envelope: ResponseEnvelope<TData>): envelope is SuccessEnvelope<TData> {
  return envelope.success;
}
