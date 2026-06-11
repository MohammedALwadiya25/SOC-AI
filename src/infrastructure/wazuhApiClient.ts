import type { WazuhApiClient } from "../application/ports.js";
import { AppError, ERROR_CODES, isPlainRecord } from "../domain/errors.js";
import type { WazuhAgent } from "../domain/models.js";
import { asString, getPath } from "../utils/records.js";
import type { HttpJsonClient } from "./httpClient.js";

interface RawAgentsResponse {
  data?: {
    affected_items?: Record<string, unknown>[];
  };
}

export class WazuhApiHttpClient implements WazuhApiClient {
  private token?: {
    value: string;
    expiresAt: number;
  };

  public constructor(
    private readonly http: HttpJsonClient,
    private readonly credentials?: { username: string; password: string },
  ) {}

  public async health(): Promise<boolean> {
    try {
      await this.requestJson<Record<string, unknown>>("GET", "/");
      return true;
    } catch {
      return false;
    }
  }

  public async listAgents(input: { limit: number; status?: string; osPlatform?: string }): Promise<WazuhAgent[]> {
    const params = new URLSearchParams({
      limit: String(input.limit),
    });
    if (input.status) {
      params.set("status", input.status);
    }
    if (input.osPlatform) {
      params.set("os.platform", input.osPlatform);
    }

    const response = await this.requestJson<RawAgentsResponse>("GET", `/agents?${params.toString()}`);
    const items = response.data?.affected_items ?? [];
    return items.map(normalizeAgent);
  }

  public async getAgent(agentId: string): Promise<WazuhAgent | null> {
    const params = new URLSearchParams({
      agents_list: agentId,
      limit: "1",
    });
    const response = await this.requestJson<RawAgentsResponse>("GET", `/agents?${params.toString()}`);
    const item = response.data?.affected_items?.[0];
    return item ? normalizeAgent(item) : null;
  }

  private async requestJson<TResponse>(method: "GET" | "POST", path: string): Promise<TResponse> {
    const token = await this.getToken();
    return this.http.json<TResponse>({
      method,
      path,
      headers: {
        authorization: `Bearer ${token}`,
      },
    });
  }

  private async getToken(): Promise<string> {
    if (this.token && this.token.expiresAt > Date.now() + 60_000) {
      return this.token.value;
    }

    if (!this.credentials) {
      throw new AppError(ERROR_CODES.CONFIGURATION, "Wazuh API credentials are not configured.");
    }

    const basic = Buffer.from(`${this.credentials.username}:${this.credentials.password}`, "utf8").toString("base64");
    const response = await this.http.text({
      method: "POST",
      path: "/security/user/authenticate?raw=true",
      headers: {
        authorization: `Basic ${basic}`,
      },
    });

    const token = response.trim();
    if (!token || token.startsWith("{")) {
      throw new AppError(ERROR_CODES.UPSTREAM_BAD_RESPONSE, "Wazuh API authentication did not return a token.");
    }

    this.token = {
      value: token,
      expiresAt: Date.now() + 14 * 60 * 1000,
    };
    return token;
  }
}

function normalizeAgent(item: Record<string, unknown>): WazuhAgent {
  return {
    id: asString(item.id) ?? "unknown",
    name: asString(item.name),
    status: asString(item.status),
    ip: asString(item.ip),
    version: asString(item.version),
    os: isPlainRecord(item.os)
      ? {
          name: asString(getPath(item, ["os", "name"])),
          version: asString(getPath(item, ["os", "version"])),
          platform: asString(getPath(item, ["os", "platform"])),
        }
      : undefined,
    lastSeen: asString(item.lastKeepAlive),
  };
}
