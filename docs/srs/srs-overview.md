# MaintenX — System Requirements Specification (SRS) Overview

## 1. Introduction & Purpose
MaintenX is a cloud-based multi-tenant software-as-a-service (SaaS) platform tailored for commercial facility operators, property managers, maintenance supervisors, and field technicians. The platform automates reactive maintenance workflows, recurring preventative maintenance schedules, and asset lifecycle tracking.

## 2. Target Users & Personas
- **Facility Manager**: Oversees buildings, monitors SLAs, reviews maintenance budgets, and assigns tickets.
- **Maintenance Technician**: Receives mobile work order assignments, updates statuses in the field, logs labor and parts, captures before/after photos.
- **Tenant / Property Occupant**: Submits maintenance requests, tracks ticket progress, and rates service quality.
- **System Administrator**: Provisions tenant organizations, manages user permissions, monitors platform health and audit logs.

## 3. High-Level Functional Requirements
- **FR-01: Multi-Tenancy**: Complete logical isolation of data, users, assets, and configurations per tenant.
- **FR-02: Facility Hierarchy**: Multi-level spatial organization (Campus → Building → Floor → Zone/Room).
- **FR-03: Asset Tracking**: Lifecycle management, warranty logging, equipment QR codes, and maintenance history.
- **FR-04: Work Order Management**: Request intake, triage, priority levels, assignment, SLA timers, and completion sign-off.
- **FR-05: Preventative Maintenance**: Automated recurrence engines generating proactive work orders based on time or runtime thresholds.
- **FR-06: Notifications**: Real-time push, SMS, and email alerts for critical facility issues.

## 4. Non-Functional Requirements
- **NFR-01: Security**: Enforce tenant isolation on all queries; OAuth2/JWT authorization; zero credential leaks.
- **NFR-02: Availability**: 99.9% uptime target with automated health checks (`/health/live`, `/health/ready`).
- **NFR-03: Performance**: Sub-200ms p95 API response times for standard queries.
- **NFR-04: Cross-Platform Support**: Responsive web application for desktop managers and native mobile application for field technicians.
