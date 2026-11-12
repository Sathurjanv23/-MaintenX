# MaintenX — Engineering Rules

## Technology Stack
- Web: Next.js App Router, TypeScript
- API: ASP.NET Core Web API, .NET 10 LTS, C#
- Database: PostgreSQL
- ORM: Entity Framework Core
- Mobile: Flutter
- Backend architecture: Modular Monolith
- Design: Clean Architecture and DDD principles
- Testing: xUnit, integration tests, frontend tests
- Infrastructure: Docker, GitHub Actions

## Architecture Rules
1. Use domain-oriented module boundaries.
2. Keep business logic out of API controllers.
3. Keep the domain layer independent of frameworks.
4. Use dependency injection.
5. Use strongly typed DTOs and request validation.
6. Follow SOLID principles where appropriate.
7. Avoid unnecessary abstractions and overengineering.
8. Do not introduce microservices without a real need.
9. PostgreSQL is the source of truth.
10. Design backend APIs for both web and mobile clients.

## Security Rules
- Never hardcode credentials or secrets.
- Never commit .env files containing secrets.
- Validate and authorize all requests.
- Enforce tenant isolation on tenant-owned resources.
- Never trust a client-supplied tenant ID alone.
- Use secure authentication and authorization patterns.
- Never expose internal errors or sensitive data.

## Git Workflow
For EVERY feature:
1. Inspect repository status.
2. Start from the latest reviewed main branch.
3. Create a dedicated feature branch.
4. Implement only the assigned feature.
5. Add or update relevant tests.
6. Run relevant build, lint and test commands.
7. Update README.md with the new feature.
8. Update relevant documentation.
9. Review changed files and check for secrets.
10. Create one focused conventional commit.
11. Report branch name and commit SHA.
12. Never automatically merge into main.

## Quality Rules
- No fake implementations.
- No fake test results.
- No hardcoded production data.
- No silent exception swallowing.
- No unreviewed breaking API changes.
- No unexplained architecture decisions.
- Prefer readable, maintainable production-style code.
- Add unit and integration tests where appropriate.
- Handle validation, error and empty states.
- Do not claim production readiness without evidence.

