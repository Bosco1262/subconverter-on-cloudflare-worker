// Request/Response bridge types used by the orchestrator (Workers-agnostic)

export interface RequestLike {
  method: string;
  argument: [string, string][];
  headers: Map<string, string>;
  userAgent: string;
}

export interface ResponseLike {
  status: number;
  headers: [string, string][];
}
