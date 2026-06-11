# Unified SOC MCP Server and AI SOC Agent

Production-style TypeScript implementation of a read-only Unified SOC MCP Server for Wazuh-centered investigations, plus a deterministic AI SOC Agent orchestration layer.

## Architecture

- `src/domain`: normalized SOC models, response envelope, sanitized errors.
- `src/infrastructure`: typed config, structured logging, HTTP retry client, Wazuh API/Indexer clients, dependency injection.
- `src/application`: Wazuh, Zeek-over-Wazuh, Suricata-over-Wazuh, MITRE, enrichment, health, correlation, and incident summary services.
- `src/mcp`: MCP server bootstrap, Zod validation schemas, safe tool registration.
- `src/agent`: read-only SOC agent workflows that consume MCP tool results.
- `tests`: validation, failure, edge-case, service, tool envelope, and agent workflow tests.

## Implemented Tools

- `health_check`
- `wazuh_get_alerts`
- `wazuh_search_alerts`
- `wazuh_get_alert_by_id`
- `wazuh_get_high_severity_alerts`
- `wazuh_list_agents`
- `wazuh_get_agent_status`
- `wazuh_get_agent_summary`
- `zeek_search_logs`
- `zeek_get_dns_activity`
- `zeek_get_connection_activity`
- `zeek_detect_beaconing`
- `suricata_get_alerts`
- `suricata_get_top_signatures`
- `suricata_get_top_talkers`
- `suricata_timeline`
- `mitre_map_alert`
- `mitre_get_technique`
- `mitre_rule_coverage`
- `correlate_ip_activity`
- `correlate_alert_context`
- `summarize_incident`
- `reason_about_incident`
- `enrich_indicator`

Every tool validates input with Zod through the safe executor, catches exceptions, logs structured execution metadata to stderr, returns JSON-only content, and uses the unified response envelope.

## Response Envelope

```json
{
  "success": true,
  "data": {},
  "error": null,
  "meta": {
    "tool": "health_check",
    "durationMs": 12,
    "timestamp": "2026-06-11T08:00:00.000Z"
  }
}
```

Errors use the same envelope:

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request input."
  },
  "meta": {
    "tool": "correlate_ip_activity",
    "durationMs": 2,
    "timestamp": "2026-06-11T08:00:00.000Z"
  }
}
```

## Local Setup

```bash
npm install
npm run typecheck
npm test
npm run build
```

Copy `.env.example` to `.env` and set read-only Wazuh credentials.

```bash
npm run dev:server
```

The MCP server uses stdio transport in version 1, so logs are written to stderr to keep stdout clean for JSON-RPC traffic.

## AI SOC Agent CLI

Build first, then run:

```bash
npm run build
node dist/agent/cli.js health
node dist/agent/cli.js triage
node dist/agent/cli.js alert ALERT_ID
node dist/agent/cli.js ip 203.0.113.10
node dist/agent/cli.js technique T1110
node dist/agent/cli.js report-ip 203.0.113.10
```

The agent refuses destructive commands such as `block`, `restart`, and `modify` in version 1.

## Optional LLM Reasoning

The project works without an LLM. If you want LLM-written explanations, set these environment variables:

```env
LLM_PROVIDER=openai-compatible
LLM_BASE_URL=https://api.openai.com
LLM_API_KEY=your-key
LLM_MODEL=your-model
```

The LLM only receives normalized incident JSON. If the LLM is not configured or fails, `ReasoningService` returns deterministic fallback reasoning instead of crashing.

## Docker

```bash
docker compose build
docker compose run --rm unified-soc-mcp
```

For Azure, use the same environment variables from `.env.example` as container app or VM environment settings. Keep TLS verification enabled unless a lab deployment explicitly requires otherwise.

## Security Notes

- Credentials are read from environment variables only.
- Secrets are redacted from structured logs and safe error details.
- Tool handlers do not execute shell commands, access local files, expose filesystem paths, or modify infrastructure.
- Query filters are built from allow-listed fields and typed DSL clauses.
- Raw log bodies are not returned by normalizers.
- Query limits are bounded by `MAX_LIMIT`, defaulting to `500`.

## Test Coverage

Current tests cover:

- Input validation for IPs, indicators, timestamps, MITRE IDs.
- Error sanitization and redaction.
- Safe query builder behavior.
- Alert normalization without raw log leakage.
- Unified tool envelope success and validation failure paths.
- Partial-failure correlation behavior.
- Agent destructive-action refusal and evidence-based triage.
