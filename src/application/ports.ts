import type { TimeRange, WazuhAgent } from "../domain/models.js";

export interface Logger {
  info(event: Record<string, unknown>, message?: string): void;
  warn(event: Record<string, unknown>, message?: string): void;
  error(event: Record<string, unknown>, message?: string): void;
}

export interface IndexerSearchRequest {
  index: string;
  body: Record<string, unknown>;
}

export interface IndexerHit {
  id: string;
  index?: string;
  source: Record<string, unknown>;
}

export interface IndexerSearchResponse {
  hits: IndexerHit[];
  total: number;
}

export interface WazuhIndexerClient {
  health(): Promise<boolean>;
  search(request: IndexerSearchRequest): Promise<IndexerSearchResponse>;
}

export interface WazuhApiClient {
  health(): Promise<boolean>;
  listAgents(input: { limit: number; status?: string; osPlatform?: string }): Promise<WazuhAgent[]>;
  getAgent(agentId: string): Promise<WazuhAgent | null>;
}

export interface QueryOptions {
  timeRange?: TimeRange;
  limit: number;
}

export interface ToolCaller {
  callTool<TData>(name: string, args: Record<string, unknown>): Promise<import("../domain/models.js").ResponseEnvelope<TData>>;
}

export interface LlmMessage {
  role: "system" | "user";
  content: string;
}

export interface LlmJsonRequest {
  messages: LlmMessage[];
  temperature: number;
  maxTokens: number;
}

export interface LlmJsonResponse {
  provider: "openai-compatible";
  model: string;
  json: unknown;
}

export interface LlmClient {
  completeJson(request: LlmJsonRequest): Promise<LlmJsonResponse>;
}
