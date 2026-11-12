# ADR-0001: Adoption of Modular Monolith Architecture Pattern

## Status
Accepted

## Date
2026-11-12

## Context
MaintenX is a facility maintenance SaaS platform serving commercial real estate owners, property managers, and field technicians. The platform involves interconnected domains: multi-tenancy, facilities, assets, work orders, preventative maintenance scheduling, and technician dispatching.

We evaluated three potential architectural approaches for the backend service:
1. **Traditional Layered Monolith**: Highly coupled single application where business logic frequently crosses boundaries without enforcement.
2. **Microservices Architecture**: Independent deployable microservices partitioned by domain from day one, communicating via HTTP/gRPC/message queues.
3. **Modular Monolith**: A single deployable application composed of strictly bounded, domain-oriented modules communicating via well-defined interfaces and in-process events.

## Decision
We decided to adopt the **Modular Monolith** architecture pattern for the MaintenX backend API using ASP.NET Core and Clean Architecture principles.

### Architecture Principles Adopted:
1. **Module Boundaries**: Each domain is encapsulated in its own module with its own domain logic, data models, and service interfaces.
2. **Communication Contracts**: Modules communicate across boundaries exclusively via public interfaces (`IModule`) or strongly typed events, never by reaching into another module's internal database tables.
3. **Single Database with Logical Isolation**: All modules share the PostgreSQL instance, but enforce logical isolation and row-level tenant security.
4. **Single Deployment Unit**: Simplifies CI/CD pipelines, local development setup, debugging, and infrastructure cost.

## Consequences

### Positive
- **Rapid Development Velocity**: No network latency between modules; simplified local development and debugging without orchestrating multiple independent microservices.
- **Transactional Consistency**: Relational database transactions across related aggregates remain possible within modular boundaries.
- **Maintainable DDD Boundaries**: Eliminates the "big ball of mud" syndrome of traditional monoliths while retaining the operational ease of a single deployable artifact.
- **Microservice Extraction Path**: If an individual module (e.g. IoT asset telemetry or notification dispatch) experiences disproportionate scale requirements, it can be extracted into an independent microservice with minimal architectural friction.

### Negative / Trade-offs
- Requires discipline in code reviews to prevent developers from bypassing module boundaries or creating circular module dependencies.
- Shared process resources: a catastrophic unhandled memory leak or crash in one module can impact the entire API host. Global exception handling and resource monitoring mitigate this risk.
