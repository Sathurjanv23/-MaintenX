"use client";

import { useEffect, useState } from "react";
import { apiClient, HealthCheckResponse, ApiInfoResponse } from "@/lib/api-client";
import {
  Activity,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Server,
  Layers,
  Database,
  Smartphone,
  ShieldCheck,
  Building2,
} from "lucide-react";

export default function HomePage() {
  const [liveStatus, setLiveStatus] = useState<HealthCheckResponse | null>(null);
  const [readyStatus, setReadyStatus] = useState<HealthCheckResponse | null>(null);
  const [apiInfo, setApiInfo] = useState<ApiInfoResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const [live, ready, info] = await Promise.allSettled([
        apiClient.checkLiveHealth(),
        apiClient.checkReadyHealth(),
        apiClient.getApiInfo(),
      ]);

      if (live.status === "fulfilled") {
        setLiveStatus(live.value);
      } else {
        setLiveStatus(null);
      }

      if (ready.status === "fulfilled") {
        setReadyStatus(ready.value);
      } else {
        // If ready is 503 (e.g. DB offline), extract details if available
        setReadyStatus(null);
      }

      if (info.status === "fulfilled") {
        setApiInfo(info.value);
      } else {
        setApiInfo(null);
      }

      if (live.status === "rejected" && ready.status === "rejected" && info.status === "rejected") {
        setErrorMessage("Unable to connect to the MaintenX API backend at http://localhost:5000. Ensure the ASP.NET Core API service is running.");
      }
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to query backend status.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900 pb-16">
      {/* Header */}
      <header className="border-b border-slate-200 bg-white/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-sky-600 flex items-center justify-center text-white shadow-sm font-bold text-xl">
              <Building2 className="w-6 h-6" />
            </div>
            <div>
              <span className="text-xl font-bold tracking-tight text-slate-900">MaintenX</span>
              <span className="ml-2 text-xs font-semibold px-2 py-0.5 rounded-full bg-sky-100 text-sky-800">
                Bootstrap
              </span>
            </div>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <span className="text-slate-500 hidden sm:inline">Modular Monolith SaaS</span>
            <button
              onClick={fetchStatus}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium bg-slate-100 hover:bg-slate-200 text-slate-700 transition"
              title="Refresh health status"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-sky-600" : ""}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 pb-8">
        <div className="text-center max-w-3xl mx-auto">
          <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-slate-900">
            Enterprise Facility Maintenance Platform
          </h1>
          <p className="mt-4 text-lg text-slate-600">
            A real-world multi-tenant SaaS architecture engineered with Clean Architecture, Domain-Driven Design, ASP.NET Core, Next.js, and PostgreSQL.
          </p>
        </div>

        {/* Backend Connectivity Status Card */}
        <div className="mt-10 max-w-2xl mx-auto bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4 mb-4">
            <div className="flex items-center gap-2.5">
              <Activity className="w-5 h-5 text-sky-600" />
              <h2 className="font-semibold text-slate-900">Backend API Connectivity Status</h2>
            </div>
            {loading ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full bg-slate-100 text-slate-600">
                <RefreshCw className="w-3 h-3 animate-spin" /> Checking...
              </span>
            ) : liveStatus?.status === "Healthy" ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full bg-emerald-100 text-emerald-800">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Connected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full bg-amber-100 text-amber-800">
                <XCircle className="w-3.5 h-3.5 text-amber-600" /> Standby / Disconnected
              </span>
            )}
          </div>

          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between py-1.5 border-b border-slate-50">
              <span className="text-slate-500">API Endpoint</span>
              <span className="font-mono text-xs text-slate-800 bg-slate-100 px-2 py-0.5 rounded">
                http://localhost:5000
              </span>
            </div>

            <div className="flex items-center justify-between py-1.5 border-b border-slate-50">
              <span className="text-slate-500">Liveness Probe (/health/live)</span>
              {liveStatus?.status === "Healthy" ? (
                <span className="font-semibold text-emerald-600 flex items-center gap-1">
                  Healthy ({liveStatus.totalDurationMs}ms)
                </span>
              ) : (
                <span className="text-slate-400">Offline</span>
              )}
            </div>

            <div className="flex items-center justify-between py-1.5 border-b border-slate-50">
              <span className="text-slate-500">Readiness Probe (/health/ready - PostgreSQL)</span>
              {readyStatus?.status === "Healthy" ? (
                <span className="font-semibold text-emerald-600 flex items-center gap-1">
                  PostgreSQL Online ({readyStatus.totalDurationMs}ms)
                </span>
              ) : (
                <span className="text-amber-600 font-medium">
                  {loading ? "Checking..." : "Database Standby (Awaiting Docker Compose)"}
                </span>
              )}
            </div>

            {apiInfo && (
              <div className="flex items-center justify-between py-1.5">
                <span className="text-slate-500">API Version & Environment</span>
                <span className="font-medium text-slate-700">
                  {apiInfo.version} ({apiInfo.environment})
                </span>
              </div>
            )}

            {errorMessage && (
              <div className="mt-4 p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-800">
                <p className="font-medium">Connectivity Notice:</p>
                <p className="mt-1">{errorMessage}</p>
                <p className="mt-1 text-slate-500">
                  Run <code className="bg-amber-100 px-1 py-0.5 rounded font-mono">dotnet run --project services/api</code> to launch the backend API.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Platform Architecture Highlights */}
        <div className="mt-12 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <div className="w-9 h-9 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center mb-3">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-900">Modular Monolith</h3>
            <p className="mt-1 text-xs text-slate-500">
              Clean architecture domain modules (Tenancy, Assets, Work Orders) inside a single deployable unit.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <div className="w-9 h-9 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center mb-3">
              <Database className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-900">PostgreSQL Source of Truth</h3>
            <p className="mt-1 text-xs text-slate-500">
              Reliable relational storage with strict tenant isolation, connection pooling, and health verification.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <div className="w-9 h-9 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center mb-3">
              <Server className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-900">ASP.NET Core Web API</h3>
            <p className="mt-1 text-xs text-slate-500">
              High-performance backend featuring OpenAPI/Swagger, RFC 7807 Problem Details, and DI.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
            <div className="w-9 h-9 rounded-lg bg-orange-50 text-orange-600 flex items-center justify-center mb-3">
              <Smartphone className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-slate-900">Multi-Client Ready</h3>
            <p className="mt-1 text-xs text-slate-500">
              Designed concurrently for Next.js App Router and Flutter mobile cross-platform clients.
            </p>
          </div>
        </div>
      </div>
    </main>
  );
}
