import type { LlmClient, LlmJsonRequest, LlmJsonResponse } from "../application/ports.js";
import { AppError, ERROR_CODES, isPlainRecord } from "../domain/errors.js";
import type { HttpJsonClient } from "./httpClient.js";

interface ChatCompletionResponse {
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
}

export class OpenAiCompatibleLlmClient implements LlmClient {
  public constructor(
    private readonly http: HttpJsonClient,
    private readonly apiKey: string,
    private readonly model: string,
  ) {}

  public async completeJson(request: LlmJsonRequest): Promise<LlmJsonResponse> {
    const response = await this.http.json<ChatCompletionResponse>({
      method: "POST",
      path: "/v1/chat/completions",
      headers: {
        authorization: `Bearer ${this.apiKey}`,
      },
      body: {
        model: this.model,
        messages: request.messages,
        temperature: request.temperature,
        max_tokens: request.maxTokens,
        response_format: {
          type: "json_object",
        },
      },
    });

    const content = response.choices?.[0]?.message?.content;
    if (!content) {
      throw new AppError(ERROR_CODES.UPSTREAM_BAD_RESPONSE, "LLM response did not include message content.");
    }

    try {
      const parsed = JSON.parse(content) as unknown;
      if (!isPlainRecord(parsed)) {
        throw new AppError(ERROR_CODES.UPSTREAM_BAD_RESPONSE, "LLM response JSON must be an object.");
      }
      return {
        provider: "openai-compatible",
        model: this.model,
        json: parsed,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }
      throw new AppError(ERROR_CODES.UPSTREAM_BAD_RESPONSE, "LLM response content was not valid JSON.");
    }
  }
}
