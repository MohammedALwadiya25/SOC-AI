export type SeverityLabel = "low" | "medium" | "high" | "critical" | "unknown";

export interface TimeRange {
  start: string;
  end: string;
}

export interface Pagination {
  limit: number;
  returned: number;
  hasMore: boolean;
}

export interface SourceFailure {
  source: string;
  code: string;
  message: string;
}

export interface ResponseMeta {
  tool?: string;
  durationMs?: number;
  timestamp: string;
  pagination?: Pagination;
  warnings?: string[];
  partialFailures?: SourceFailure[];
}

export interface SafeError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface SuccessEnvelope<TData> {
  success: true;
  data: TData;
  error: null;
  meta: ResponseMeta;
}

export interface ErrorEnvelope {
  success: false;
  data: null;
  error: SafeError;
  meta: ResponseMeta;
}

export type ResponseEnvelope<TData> = SuccessEnvelope<TData> | ErrorEnvelope;

export interface MitreTechniqueRef {
  id: string;
  name?: string;
  tactic?: string;
}

export interface NormalizedAlert {
  id: string;
  timestamp: string;
  severity: SeverityLabel;
  severityScore: number;
  source: "wazuh" | "suricata" | "zeek" | "pfsense" | "unknown";
  agent?: {
    id?: string;
    name?: string;
    ip?: string;
  };
  rule?: {
    id?: string;
    level?: number;
    description?: string;
    groups?: string[];
    mitre?: MitreTechniqueRef[];
  };
  network?: {
    sourceIp?: string;
    sourcePort?: number;
    destinationIp?: string;
    destinationPort?: number;
    protocol?: string;
  };
  message?: string;
  normalizedFields: Record<string, unknown>;
}

export interface WazuhAgent {
  id: string;
  name?: string;
  status?: string;
  ip?: string;
  version?: string;
  os?: {
    name?: string;
    version?: string;
    platform?: string;
  };
  lastSeen?: string;
}

export interface ZeekEvent {
  id: string;
  timestamp: string;
  logType: "dns" | "conn" | "http" | "ssl" | "notice" | "files" | "unknown";
  sourceIp?: string;
  sourcePort?: number;
  destinationIp?: string;
  destinationPort?: number;
  protocol?: string;
  service?: string;
  query?: string;
  answer?: string;
  action?: string;
  durationMs?: number;
  bytesIn?: number;
  bytesOut?: number;
  normalizedFields: Record<string, unknown>;
}

export interface SuricataAlert {
  id: string;
  timestamp: string;
  signature?: string;
  signatureId?: string;
  category?: string;
  severity?: number;
  sourceIp?: string;
  sourcePort?: number;
  destinationIp?: string;
  destinationPort?: number;
  protocol?: string;
  action?: string;
  normalizedFields: Record<string, unknown>;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
}

export interface MitreMapping {
  alertId?: string;
  techniques: MitreTechnique[];
  confidence: "low" | "medium" | "high";
  reason: string;
}

export interface TimelineEvent {
  timestamp: string;
  source: "wazuh" | "zeek" | "suricata" | "pfsense" | "agent" | "mitre";
  title: string;
  severity: SeverityLabel;
  entity?: string;
  evidenceId?: string;
  details: Record<string, unknown>;
}

export interface CorrelationFinding {
  title: string;
  severity: SeverityLabel;
  confidence: "low" | "medium" | "high";
  evidenceCount: number;
  rationale: string;
}

export interface CorrelationResult {
  entity: string;
  timeRange: TimeRange;
  timeline: TimelineEvent[];
  findings: CorrelationFinding[];
  evidenceCounts: Record<string, number>;
}

export type IndicatorType = "ip" | "domain" | "url" | "hash" | "user";

export interface IndicatorContext {
  type: IndicatorType;
  value: string;
  normalizedValue: string;
  classification: "private" | "public" | "reserved" | "unknown" | "user";
  notes: string[];
}

export interface HealthStatus {
  service: string;
  ok: boolean;
  status: "healthy" | "degraded" | "unhealthy";
  dependencies: Array<{
    name: string;
    ok: boolean;
    status: string;
    errorCode?: string;
  }>;
}

export interface IncidentSummary {
  title: string;
  severity: SeverityLabel;
  status: "new" | "triaged" | "investigating" | "insufficient_evidence";
  affectedAssets: string[];
  timeline: TimelineEvent[];
  evidence: Array<{
    source: string;
    id: string;
    summary: string;
  }>;
  mitre: MitreMapping[];
  confidence: "low" | "medium" | "high";
  recommendedNextSteps: string[];
  limitations: string[];
}

export interface ReasoningResult {
  provider: "disabled" | "openai-compatible" | "fallback";
  model?: string;
  summary: string;
  analysis: string[];
  recommendations: string[];
  evidenceUsed: string[];
  confidence: "low" | "medium" | "high";
  limitations: string[];
}

export interface ReasonedIncident {
  incident: IncidentSummary;
  reasoning: ReasoningResult;
}

export interface AgentAnswer {
  mode:
    | "triage"
    | "alert_investigation"
    | "ip_investigation"
    | "mitre_explanation"
    | "incident_report"
    | "refusal"
    | "clarification";
  title: string;
  severity?: SeverityLabel;
  evidence: string[];
  analysis: string[];
  recommendations: string[];
  limitations: string[];
  data?: unknown;
}
