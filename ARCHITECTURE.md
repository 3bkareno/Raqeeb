# Raqeeb - Web Vulnerability Scanner Architecture

## 1. High-Level System Architecture

Raqeeb follows **Clean Architecture** principles to ensure separation of concerns, testability, and maintainability. The system is designed as a modular, distributed scanning engine orchestrated by a central API.

### Layers
1.  **Domain (Core)**: Contains enterprise logic, entities, value objects, and domain interfaces. No external dependencies.
2.  **Application**: Contains business logic, CQRS handlers, and orchestration logic. Depends on Domain.
3.  **Infrastructure**: Implements interfaces defined in Domain/Application. Handles database, external APIs, file system, and the actual Scanning Engine execution.
4.  **Presentation (API)**: ASP.NET Core Web API. Handles HTTP requests, authentication, and localization.

### Diagram Concept
`[Client/UI] -> [API] -> [Application (CQRS)] -> [Domain]`
`                        |`
`                        v`
`                  [Infrastructure]`
`                  (DB, Queue, Scanner Modules)`

## 2. Tech Stack

-   **Framework**: .NET 10 (ASP.NET Core)
-   **Language**: C# 14
-   **Database**: PostgreSQL (Production) / InMemory (Dev)
-   **ORM**: Entity Framework Core
-   **Messaging/Queue**: RabbitMQ or MassTransit (for distributing scan jobs)
-   **Caching**: Redis
-   **Validation**: FluentValidation
-   **Mapping**: Mapster or AutoMapper
-   **Logging**: Serilog (Structured Logging)
-   **Localization**: Microsoft.Extensions.Localization (Resx)

## 3. Domain Models & Core Entities

-   **Target**: Represents a website/URL to be scanned.
    -   Properties: `Id`, `Url`, `OwnerId`, `CreatedAt`, `AuthCredentials`.
-   **ScanJob**: Represents a single execution of a scan.
    -   Properties: `Id`, `TargetId`, `Status` (Queued, Running, Completed, Failed), `ProfileId`, `StartTime`, `EndTime`.
-   **ScanProfile**: Configuration for a scan (e.g., "Full Scan", "Quick Scan", "XSS Only").
    -   Properties: `Id`, `EnabledModules`, `RequestTimeout`, `MaxConcurrency`.
-   **Vulnerability**: A detected issue.
    -   Properties: `Id`, `ScanJobId`, `Severity` (Critical, High, Medium, Low, Info), `Name`, `Description`, `Evidence`, `Remediation`.

## 4. Scanning Engine Design

The scanning engine is designed to be **modular** and **pluggable**.

### Interfaces
-   `IScannerModule`: Interface for a specific vulnerability check (e.g., `SqlInjectionScanner`, `XssScanner`).
    -   `Task<IEnumerable<Vulnerability>> ScanAsync(Target target, ScanContext context);`
-   `IScanEngine`: Orchestrates the execution of modules.
-   `IHttpCrawler`: Helper service to crawl the target and discover endpoints.

### Extensibility
New vulnerabilities are added by creating a class that implements `IScannerModule`. The engine dynamically loads these modules (via DI or plugin architecture).

## 5. Localization Strategy

-   **Resource Files**: `.resx` files for English (`en-US`) and Arabic (`ar-SA`).
-   **RTL Support**: The API returns a `Content-Language` header. The frontend handles UI direction (RTL/LTR).
-   **Data Localization**: Vulnerability descriptions can be stored in resource files or a database with localized content.

## 6. Security Considerations

-   **Authorization**: Role-Based Access Control (RBAC). Only "Admin" or "SecurityEngineer" can initiate scans.
-   **Safe Usage**:
    -   Scans must be authorized by the target owner (verified via file upload or DNS record).
    -   Rate limiting to prevent DoS on targets.
    -   "Safe Mode" flag to disable destructive payloads.
-   **Data Protection**:
    -   Scan results (which may contain sensitive data) are encrypted at rest.
    -   Secrets (API keys, target credentials) are stored using a secure vault (e.g., Azure Key Vault, HashiCorp Vault).

## 7. Folder & Project Structure

```text
/Raqeeb
  /src
    /Raqeeb.Domain          # Entities, Interfaces, Enums
    /Raqeeb.Application     # CQRS, DTOs, Validators, Services
    /Raqeeb.Infrastructure  # EF Core, Scanner Implementation, External Services
    /Raqeeb.Api             # Controllers, Middleware, Program.cs
  /tests
    /Raqeeb.UnitTests
```

## 8. Roadmap

1.  **Phase 1: Core Skeleton** (Current)
    -   Setup Clean Architecture.
    -   Define Domain Entities.
    -   Implement Basic Scanner Interface.
2.  **Phase 2: Scanning Engine**
    -   Implement HTTP Crawler.
    -   Create "Passive" modules (Header analysis).
    -   Create "Active" modules (Injection testing - Safe).
3.  **Phase 3: Job Management**
    -   Integrate Queue (BackgroundService).
    -   Persist results to DB.
4.  **Phase 4: UI & Reporting**
    -   Build Dashboard API.
    -   Generate PDF/HTML Reports.
