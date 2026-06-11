import { Agent, fetch, type Dispatcher } from "undici";
import { AppError, ERROR_CODES, errorCodeFromHttpStatus, redactString } from "../domain/errors.js";

export interface HttpClientOptions {
  baseUrl: string;
  timeoutMs: number;
  retryAttempts: number;
  retryBaseDelayMs: number;
  tlsRejectUnauthorized: boolean;
}

export interface HttpRequest {
  method: "GET" | "POST";
  path: string;
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
}

export class HttpJsonClient {
  private readonly dispatcher: Dispatcher;
  private readonly baseUrl: URL;

  public constructor(private readonly options: HttpClientOptions) {
    this.baseUrl = new URL(options.baseUrl);
    this.dispatcher = new Agent({
      connect: {
        rejectUnauthorized: options.tlsRejectUnauthorized,
      },
    });
  }

  public async json<TResponse>(request: HttpRequest): Promise<TResponse> {
    const text = await this.requestText(request);
    try {
      return JSON.parse(text) as TResponse;
    } catch (error) {
      throw new AppError(ERROR_CODES.UPSTREAM_BAD_RESPONSE, "Upstream service returned invalid JSON.", {
        cause: error instanceof Error ? error.name : "unknown",
      });
    }
  }

  public async text(request: HttpRequest): Promise<string> {
    return this.requestText(request);
  }

  private async requestText(request: HttpRequest): Promise<string> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= this.options.retryAttempts; attempt += 1) {
      try {
        return await this.sendOnce(request);
      } catch (error) {
        lastError = error;
        if (!shouldRetry(error) || attempt >= this.options.retryAttempts) {
          break;
        }
        await delay(this.options.retryBaseDelayMs * 2 ** attempt);
      }
    }

    if (lastError instanceof AppError) {
      throw lastError;
    }
    throw new AppError(ERROR_CODES.UPSTREAM_UNAVAILABLE, "Upstream service request failed.");
  }

  private async sendOnce(request: HttpRequest): Promise<string> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    const url = new URL(request.path, this.baseUrl);

    try {
      const response = await fetch(url, {
        method: request.method,
        dispatcher: this.dispatcher,
        signal: controller.signal,
        headers: {
          accept: "application/json",
          ...(request.body ? { "content-type": "application/json" } : {}),
          ...request.headers,
        },
        body: request.body ? JSON.stringify(request.body) : undefined,
      });

      const responseText = await response.text();
      if (!response.ok) {
        throw new AppError(errorCodeFromHttpStatus(response.status), "Upstream service returned an error.", {
          status: response.status,
          statusText: redactString(response.statusText),
        });
      }
      return responseText;
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      if (error instanceof Error && error.name === "AbortError") {
        throw new AppError(ERROR_CODES.UPSTREAM_TIMEOUT, "Upstream service request timed out.");
      }
      throw new AppError(ERROR_CODES.UPSTREAM_UNAVAILABLE, "Upstream service is unavailable.");
    } finally {
      clearTimeout(timeout);
    }
  }
}

function shouldRetry(error: unknown): boolean {
  if (!(error instanceof AppError)) {
    return true;
  }
  return (
    error.code === ERROR_CODES.UPSTREAM_UNAVAILABLE ||
    error.code === ERROR_CODES.UPSTREAM_TIMEOUT ||
    error.code === ERROR_CODES.RATE_LIMITED
  );
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
