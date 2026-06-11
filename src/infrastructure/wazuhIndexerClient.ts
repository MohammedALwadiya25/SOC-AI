import type { IndexerSearchRequest, IndexerSearchResponse, WazuhIndexerClient } from "../application/ports.js";
import { AppError, ERROR_CODES, isPlainRecord } from "../domain/errors.js";
import type { HttpJsonClient } from "./httpClient.js";

interface RawIndexerSearchResponse {
  hits?: {
    total?: number | { value?: number };
    hits?: Array<{
      _id?: string;
      _index?: string;
      _source?: Record<string, unknown>;
    }>;
  };
}

export class WazuhIndexerHttpClient implements WazuhIndexerClient {
  public constructor(
    private readonly http: HttpJsonClient,
    private readonly credentials?: { username: string; password: string },
  ) {}

  public async health(): Promise<boolean> {
    try {
      await this.http.json<Record<string, unknown>>({
        method: "GET",
        path: "/",
        headers: this.authHeader(),
      });
      return true;
    } catch {
      return false;
    }
  }

  public async search(request: IndexerSearchRequest): Promise<IndexerSearchResponse> {
    const raw = await this.http.json<RawIndexerSearchResponse>({
      method: "POST",
      path: `/${encodeURIComponent(request.index)}/_search`,
      headers: this.authHeader(),
      body: request.body,
    });

    if (!isPlainRecord(raw.hits) || !Array.isArray(raw.hits.hits)) {
      throw new AppError(ERROR_CODES.UPSTREAM_BAD_RESPONSE, "Indexer response did not include search hits.");
    }

    const total =
      typeof raw.hits.total === "number"
        ? raw.hits.total
        : isPlainRecord(raw.hits.total) && typeof raw.hits.total.value === "number"
          ? raw.hits.total.value
          : raw.hits.hits.length;

    return {
      total,
      hits: raw.hits.hits
        .filter((hit) => isPlainRecord(hit._source))
        .map((hit) => ({
          id: hit._id ?? "unknown",
          index: hit._index,
          source: hit._source ?? {},
        })),
    };
  }

  private authHeader(): Record<string, string> {
    if (!this.credentials) {
      return {};
    }
    const token = Buffer.from(`${this.credentials.username}:${this.credentials.password}`, "utf8").toString("base64");
    return {
      authorization: `Basic ${token}`,
    };
  }
}
