export interface HealthCheckResponse {
  status: "Healthy" | "Unhealthy" | "Degraded";
  timestamp: string;
  totalDurationMs: number;
  checks?: Array<{
    component: string;
    status: string;
    description: string | null;
    durationMs: number;
    error: string | null;
  }>;
}

export interface ApiInfoResponse {
  application: string;
  version: string;
  environment: string;
  timestampUtc: string;
  status: string;
  apiVersioningConvention: string;
  plannedModules: string[];
}

export class ApiClientError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly rawResponse?: unknown
  ) {
    super(message);
    this.name = "ApiClientError";
  }
}

export class ApiClient {
  private readonly baseUrl: string;

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";
  }

  private async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          Accept: "application/json",
          ...options?.headers,
        },
        cache: "no-store",
      });

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        throw new ApiClientError(
          `Request to ${endpoint} failed with HTTP ${response.status}`,
          response.status,
          data
        );
      }

      return data as T;
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        throw err;
      }
      const message = err instanceof Error ? err.message : "Unknown network error";
      throw new ApiClientError(`Cannot connect to backend API at ${this.baseUrl}: ${message}`);
    }
  }

  async checkLiveHealth(): Promise<HealthCheckResponse> {
    return this.request<HealthCheckResponse>("/health/live");
  }

  async checkReadyHealth(): Promise<HealthCheckResponse> {
    return this.request<HealthCheckResponse>("/health/ready");
  }

  async getApiInfo(): Promise<ApiInfoResponse> {
    return this.request<ApiInfoResponse>("/api/v1/info");
  }
}

export const apiClient = new ApiClient();
