import type { TimeRange } from "../domain/models.js";

export function defaultTimeRange(hours: number): TimeRange {
  const end = new Date();
  const start = new Date(end.getTime() - hours * 60 * 60 * 1000);
  return {
    start: start.toISOString(),
    end: end.toISOString(),
  };
}

export function expandAround(timestamp: string, windowMinutes: number): TimeRange {
  const center = new Date(timestamp);
  const delta = windowMinutes * 60 * 1000;
  return {
    start: new Date(center.getTime() - delta).toISOString(),
    end: new Date(center.getTime() + delta).toISOString(),
  };
}

export function compareIsoAsc(left: string, right: string): number {
  return new Date(left).getTime() - new Date(right).getTime();
}

export function bucketTimestamp(timestamp: string, bucketSizeMinutes: number): string {
  const date = new Date(timestamp);
  const bucketMs = bucketSizeMinutes * 60 * 1000;
  return new Date(Math.floor(date.getTime() / bucketMs) * bucketMs).toISOString();
}
