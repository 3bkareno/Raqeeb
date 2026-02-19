# Raqeeb Vulnerability Scanner - Development Roadmap

> **Version**: 2.0 Planning Document  
> **Created**: January 2026  
> **Repository**: https://github.com/3bkareno/Raqeeb  
> **Target Completion**: Q4 2026

---

## ?? Executive Summary

This roadmap outlines the development plan to transform Raqeeb from an MVP vulnerability scanner into a production-ready, enterprise-grade security platform. The plan is divided into 8 phases over 12 months.

---

## ?? Project Goals

1. **Security First**: Build a comprehensive vulnerability detection platform
2. **Enterprise Ready**: Multi-tenant, scalable, and secure
3. **User Experience**: Intuitive Arabic & English interface
4. **Extensibility**: Plugin architecture for scanner modules
5. **Automation**: CI/CD integration and scheduled scanning

---

## ?? Current State Analysis

### ? Implemented Features
- [x] Basic Blazor Server UI
- [x] Target management (CRUD)
- [x] Scan profiles
- [x] Scan execution engine
- [x] Header Security Scanner module
- [x] Vulnerability storage & display
- [x] Basic localization (EN/AR)
- [x] SQL Server persistence
- [x] MediatR CQRS pattern

### ? Missing Features
- [ ] Authentication & Authorization
- [ ] Additional scanner modules (XSS, SQLi, etc.)
- [ ] Scheduled/automated scans
- [ ] Reporting (PDF, Excel)
- [ ] Email notifications
- [ ] API documentation
- [ ] RTL layout support
- [ ] Background job processing
- [ ] And 65+ more features...

---

## ??? Development Phases

---

### Phase 1: Foundation & Security (Weeks 1-4)
**Goal**: Establish secure authentication and core infrastructure

#### 1.1 Authentication System
| Task | Description | Est. Hours |
|------|-------------|------------|
| User Entity | Create User, Role, Permission entities | 4h |
| ASP.NET Identity | Integrate Identity with EF Core | 8h |
| Login Page | Create login UI with validation | 6h |
| Register Page | User registration with email confirm | 6h |
| Password Reset | Email-based password recovery | 4h |
| JWT Tokens | API authentication tokens | 6h |
| Auth Guards | Protect routes and components | 4h |

#### 1.2 Authorization & Roles
| Task | Description | Est. Hours |
|------|-------------|------------|
| Role System | Admin, User, Viewer roles | 4h |
| Permission System | Granular permissions | 6h |
| Role Management UI | Admin page to manage roles | 4h |
| User Management UI | Admin page to manage users | 6h |

#### 1.3 Infrastructure
| Task | Description | Est. Hours |
|------|-------------|------------|
| Audit Logging | Track all user actions | 6h |
| Health Checks | /health and /ready endpoints | 2h |
| Rate Limiting | API request throttling | 4h |
| HTTPS Enforcement | Strict transport security | 2h |

**Phase 1 Total**: ~72 hours (2 weeks)

---

### Phase 2: Scanner Modules (Weeks 5-10)
**Goal**: Implement comprehensive vulnerability detection

#### 2.1 High Priority Scanners
| Module | Description | Est. Hours |
|--------|-------------|------------|
| XSS Scanner | Reflected & Stored XSS detection | 16h |
| SQL Injection | Error-based & blind SQLi | 16h |
| CSRF Scanner | Token validation checks | 8h |
| SSL/TLS Analyzer | Certificate & cipher analysis | 12h |
| CORS Scanner | Misconfiguration detection | 6h |

#### 2.2 Medium Priority Scanners
| Module | Description | Est. Hours |
|--------|-------------|------------|
| Open Redirect | URL redirect vulnerabilities | 6h |
| Clickjacking | X-Frame-Options analysis | 4h |
| Directory Bruteforce | Hidden path discovery | 10h |
| Subdomain Enum | Discover subdomains | 8h |
| Port Scanner | TCP port enumeration | 8h |

#### 2.3 Scanner Framework
| Task | Description | Est. Hours |
|------|-------------|------------|
| Plugin Architecture | Dynamic module loading | 12h |
| Module Configuration | Per-module settings | 6h |
| Result Normalization | Standardized findings format | 4h |
| Severity Calculator | CVSS-like scoring | 6h |

**Phase 2 Total**: ~122 hours (3 weeks)

---

### Phase 3: Automation & Scheduling (Weeks 11-14)
**Goal**: Enable automated and scheduled scanning

#### 3.1 Background Processing
| Task | Description | Est. Hours |
|------|-------------|------------|
| Hangfire Integration | Background job processor | 8h |
| Job Dashboard | Monitor running jobs | 4h |
| Retry Logic | Failed job retry handling | 4h |
| Queue Management | Priority-based queuing | 6h |

#### 3.2 Scheduling System
| Task | Description | Est. Hours |
|------|-------------|------------|
| Schedule Entity | CRON-based scheduling | 6h |
| Schedule UI | Create/edit schedules | 8h |
| Recurring Scans | Daily/weekly/monthly | 6h |
| Schedule Calendar | Visual calendar view | 8h |

#### 3.3 Notifications
| Task | Description | Est. Hours |
|------|-------------|------------|
| Email Service | SMTP/SendGrid integration | 6h |
| Email Templates | Scan complete, alerts | 6h |
| In-App Notifications | Notification center | 8h |
| Webhook System | POST to external URLs | 6h |

**Phase 3 Total**: ~76 hours (2 weeks)

---

### Phase 4: Reporting & Export (Weeks 15-18)
**Goal**: Professional reporting capabilities

#### 4.1 Report Generation
| Task | Description | Est. Hours |
|------|-------------|------------|
| HTML Reports | Styled HTML export | 8h |
| PDF Generation | QuestPDF/iTextSharp | 12h |
| Excel Export | EPPlus integration | 6h |
| JSON Export | API-friendly export | 2h |

#### 4.2 Report Features
| Task | Description | Est. Hours |
|------|-------------|------------|
| Executive Summary | High-level overview | 6h |
| Technical Details | Full vulnerability data | 4h |
| Remediation Guide | Fix recommendations | 6h |
| Trend Analysis | Historical comparison | 8h |

#### 4.3 Compliance Mapping
| Task | Description | Est. Hours |
|------|-------------|------------|
| OWASP Top 10 | Map findings to OWASP | 6h |
| CWE Mapping | Common Weakness Enum | 4h |
| Custom Templates | User-defined templates | 8h |

**Phase 4 Total**: ~70 hours (2 weeks)

---

### Phase 5: UI/UX & Localization (Weeks 19-22)
**Goal**: Polish interface and complete Arabic support

#### 5.1 RTL Support
| Task | Description | Est. Hours |
|------|-------------|------------|
| RTL CSS Framework | Bidirectional styles | 12h |
| Layout Adjustments | Sidebar, tables, forms | 8h |
| Icon Mirroring | Flip directional icons | 4h |
| Date Formatting | Hijri calendar option | 6h |

#### 5.2 Language Persistence
| Task | Description | Est. Hours |
|------|-------------|------------|
| User Preferences | Save to database | 4h |
| Cookie Storage | Fallback for guests | 2h |
| More Languages | French, Turkish, Spanish | 8h |

#### 5.3 UI Improvements
| Task | Description | Est. Hours |
|------|-------------|------------|
| Dark Mode | Theme toggle return | 6h |
| Mobile Responsive | Better mobile layout | 12h |
| Accessibility | WCAG 2.1 compliance | 10h |
| Loading States | Skeleton loaders | 4h |
| Error Handling | User-friendly errors | 4h |

**Phase 5 Total**: ~80 hours (2 weeks)

---

### Phase 6: API & Integrations (Weeks 23-26)
**Goal**: Enable external integrations and automation

#### 6.1 REST API
| Task | Description | Est. Hours |
|------|-------------|------------|
| API Controllers | RESTful endpoints | 12h |
| Swagger/OpenAPI | Interactive docs | 6h |
| API Versioning | v1, v2 support | 4h |
| API Rate Limiting | Per-key throttling | 4h |

#### 6.2 CI/CD Integration
| Task | Description | Est. Hours |
|------|-------------|------------|
| GitHub Actions | Workflow templates | 6h |
| Azure DevOps | Pipeline templates | 6h |
| CLI Tool | Command-line scanner | 12h |
| Docker Image | Containerization | 8h |

#### 6.3 Third-Party Integrations
| Task | Description | Est. Hours |
|------|-------------|------------|
| Slack Notifications | Slack webhook | 4h |
| Teams Notifications | MS Teams cards | 4h |
| Jira Integration | Create issues | 8h |
| PagerDuty | Alert escalation | 4h |

**Phase 6 Total**: ~78 hours (2 weeks)

---

### Phase 7: Enterprise Features (Weeks 27-32)
**Goal**: Multi-tenant and team collaboration

#### 7.1 Multi-Tenancy
| Task | Description | Est. Hours |
|------|-------------|------------|
| Organization Entity | Company/org model | 6h |
| Tenant Isolation | Data separation | 10h |
| Subdomain Routing | tenant.raqeeb.io | 8h |
| Tenant Settings | Per-org configuration | 6h |

#### 7.2 Team Collaboration
| Task | Description | Est. Hours |
|------|-------------|------------|
| Team Management | Invite/remove members | 8h |
| Shared Targets | Team target pools | 4h |
| Activity Feed | Team activity log | 6h |
| Comments | Vulnerability comments | 6h |

#### 7.3 Advanced Security
| Task | Description | Est. Hours |
|------|-------------|------------|
| MFA/2FA | TOTP authenticator | 8h |
| SSO/SAML | Enterprise SSO | 12h |
| Session Management | Active sessions view | 4h |
| IP Whitelisting | Restrict access by IP | 4h |

**Phase 7 Total**: ~82 hours (3 weeks)

---

### Phase 8: Polish & Launch (Weeks 33-36)
**Goal**: Production readiness and launch

#### 8.1 Performance
| Task | Description | Est. Hours |
|------|-------------|------------|
| Redis Caching | Cache frequently used data | 8h |
| Database Optimization | Indexes, queries | 6h |
| CDN Setup | Static asset delivery | 4h |
| Load Testing | Stress test platform | 6h |

#### 8.2 DevOps
| Task | Description | Est. Hours |
|------|-------------|------------|
| Kubernetes Manifests | K8s deployment | 8h |
| Helm Charts | Package manager | 6h |
| Monitoring | Prometheus/Grafana | 8h |
| Logging | Centralized logging | 6h |

#### 8.3 Documentation
| Task | Description | Est. Hours |
|------|-------------|------------|
| User Guide | End-user documentation | 12h |
| Admin Guide | Administrator docs | 8h |
| API Reference | Endpoint documentation | 6h |
| Video Tutorials | How-to videos | 16h |

#### 8.4 Launch Prep
| Task | Description | Est. Hours |
|------|-------------|------------|
| Security Audit | Penetration testing | 16h |
| Legal/Compliance | Terms, Privacy Policy | 8h |
| Marketing Site | Landing page | 12h |
| Beta Testing | User feedback | 20h |

**Phase 8 Total**: ~150 hours (4 weeks)

---

## ?? Timeline Summary

| Phase | Duration | Focus Area | Est. Hours |
|-------|----------|------------|------------|
| Phase 1 | Weeks 1-4 | Foundation & Security | 72h |
| Phase 2 | Weeks 5-10 | Scanner Modules | 122h |
| Phase 3 | Weeks 11-14 | Automation & Scheduling | 76h |
| Phase 4 | Weeks 15-18 | Reporting & Export | 70h |
| Phase 5 | Weeks 19-22 | UI/UX & Localization | 80h |
| Phase 6 | Weeks 23-26 | API & Integrations | 78h |
| Phase 7 | Weeks 27-32 | Enterprise Features | 82h |
| Phase 8 | Weeks 33-36 | Polish & Launch | 150h |
| **Total** | **36 weeks** | | **~730 hours** |

---

## ??? Technical Architecture

```
???????????????????????????????????????????????????????????????????
?                        PRESENTATION LAYER                        ?
???????????????????????????????????????????????????????????????????
?  Blazor Server UI  ?  REST API  ?  CLI Tool  ?  Webhooks        ?
???????????????????????????????????????????????????????????????????
                                ?
???????????????????????????????????????????????????????????????????
?                        APPLICATION LAYER                         ?
???????????????????????????????????????????????????????????????????
?  Commands  ?  Queries  ?  Handlers  ?  Validators  ?  DTOs      ?
?                     (MediatR CQRS)                               ?
???????????????????????????????????????????????????????????????????
                                ?
???????????????????????????????????????????????????????????????????
?                         DOMAIN LAYER                             ?
???????????????????????????????????????????????????????????????????
?  Entities  ?  Value Objects  ?  Domain Events  ?  Interfaces    ?
?  - User, Role, Permission                                        ?
?  - Target, ScanJob, Vulnerability                                ?
?  - ScanProfile, Schedule                                         ?
?  - Organization, Team                                            ?
???????????????????????????????????????????????????????????????????
                                ?
???????????????????????????????????????????????????????????????????
?                      INFRASTRUCTURE LAYER                        ?
???????????????????????????????????????????????????????????????????
?  EF Core  ?  Identity  ?  Hangfire  ?  Email  ?  Cache          ?
?                                                                  ?
?  ????????????????????????????????????????????????????????????   ?
?  ?                   SCANNER MODULES                         ?   ?
?  ????????????????????????????????????????????????????????????   ?
?  ? HeaderSecurity ? XSS ? SQLi ? CSRF ? SSL ? Ports ? ...   ?   ?
?  ????????????????????????????????????????????????????????????   ?
???????????????????????????????????????????????????????????????????
                                ?
???????????????????????????????????????????????????????????????????
?                        DATA STORES                               ?
???????????????????????????????????????????????????????????????????
?  SQL Server  ?  Redis Cache  ?  Blob Storage  ?  Message Queue  ?
???????????????????????????????????????????????????????????????????
```

---

## ?? Proposed Project Structure

```
Raqeeb/
??? src/
?   ??? Raqeeb.Domain/              # Core business logic
?   ?   ??? Entities/
?   ?   ??? ValueObjects/
?   ?   ??? Events/
?   ?   ??? Interfaces/
?   ?
?   ??? Raqeeb.Application/         # Use cases & CQRS
?   ?   ??? Common/
?   ?   ??? Auth/
?   ?   ??? Scans/
?   ?   ??? Targets/
?   ?   ??? Reports/
?   ?   ??? Notifications/
?   ?
?   ??? Raqeeb.Infrastructure/      # External concerns
?   ?   ??? Persistence/
?   ?   ??? Identity/
?   ?   ??? Email/
?   ?   ??? Caching/
?   ?   ??? Jobs/
?   ?   ??? Scanning/
?   ?       ??? Modules/
?   ?           ??? HeaderSecurityScanner.cs
?   ?           ??? XssScanner.cs
?   ?           ??? SqlInjectionScanner.cs
?   ?           ??? ...
?   ?
?   ??? Raqeeb.Web/                 # Blazor UI
?   ?   ??? Components/
?   ?   ??? Services/
?   ?   ??? wwwroot/
?   ?
?   ??? Raqeeb.Api/                 # REST API
?   ?   ??? Controllers/
?   ?   ??? Middleware/
?   ?   ??? Filters/
?   ?
?   ??? Raqeeb.Cli/                 # Command-line tool
?       ??? Commands/
?
??? tests/
?   ??? Raqeeb.Domain.Tests/
?   ??? Raqeeb.Application.Tests/
?   ??? Raqeeb.Infrastructure.Tests/
?   ??? Raqeeb.Web.Tests/
?
??? docs/
?   ??? api/
?   ??? user-guide/
?   ??? admin-guide/
?
??? deploy/
?   ??? docker/
?   ??? kubernetes/
?   ??? terraform/
?
??? tools/
    ??? scripts/
```

---

## ?? Technology Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | Blazor Server, Bootstrap 5, Chart.js |
| **Backend** | .NET 10, ASP.NET Core, C# 14 |
| **Database** | SQL Server, Redis |
| **ORM** | Entity Framework Core 10 |
| **Auth** | ASP.NET Identity, JWT |
| **CQRS** | MediatR |
| **Jobs** | Hangfire |
| **Reporting** | QuestPDF |
| **Email** | SendGrid / SMTP |
| **Logging** | Serilog |
| **Container** | Docker |
| **Orchestration** | Kubernetes |
| **CI/CD** | GitHub Actions |

---

## ? Milestones & Deliverables

### Milestone 1: Secure Foundation (Week 4) ✅ COMPLETE
- [x] User authentication working
- [x] Role-based access control
- [x] Audit logging enabled
- [x] Health checks implemented

### Milestone 2: Scanner Suite (Week 10) ✅ COMPLETE
- [x] 9+ scanner modules working
- [x] Plugin architecture complete
- [x] Severity scoring system

### Milestone 3: Automation (Week 14) ✅ COMPLETE
- [x] Scheduled scans working
- [x] Email notifications sending
- [x] Background job processing
- [x] Schedule calendar view UI
- [x] In-app notification center

### Milestone 4: Professional Reports (Week 18) ✅ COMPLETE
- [x] PDF report generation
- [x] Excel export
- [x] OWASP mapping

### Milestone 5: Polished UI (Week 22)
- [ ] Full RTL Arabic support
- [ ] Dark mode
- [ ] Mobile responsive

### Milestone 6: API Ready (Week 26)
- [ ] REST API documented
- [ ] CI/CD templates
- [ ] Docker image published

### Milestone 7: Enterprise Ready (Week 32)
- [ ] Multi-tenant support
- [ ] Team collaboration
- [ ] SSO integration

### Milestone 8: Production Launch (Week 36)
- [ ] Security audit passed
- [ ] Documentation complete
- [ ] Public beta launched

---

## ?? Team Requirements

| Role | Count | Responsibilities |
|------|-------|------------------|
| Full-Stack Developer | 2 | Feature development |
| Security Engineer | 1 | Scanner modules, security review |
| DevOps Engineer | 1 | Infrastructure, CI/CD |
| UI/UX Designer | 1 | Design, accessibility |
| QA Engineer | 1 | Testing, automation |
| Technical Writer | 0.5 | Documentation |
| Project Manager | 0.5 | Coordination |

---

## ?? Budget Considerations

| Category | Monthly Cost (Est.) |
|----------|---------------------|
| Azure Hosting | $200-500 |
| SQL Server | $100-300 |
| Redis Cache | $50-100 |
| SendGrid Email | $20-50 |
| Domain/SSL | $20 |
| Third-party APIs | $50-100 |
| **Total** | **$440-1,070/month** |

---

## ?? Getting Started

To begin Phase 1, run these commands:

```bash
# Clone repository
git clone https://github.com/3bkareno/Raqeeb.git
cd Raqeeb

# Create feature branch
git checkout -b feature/phase1-authentication

# Install dependencies
dotnet restore

# Run migrations
dotnet ef database update -p src/Raqeeb.Infrastructure -s src/Raqeeb.Web

# Start development
dotnet run --project src/Raqeeb.Web
```

---

## ?? Contact & Support

- **Repository**: https://github.com/3bkareno/Raqeeb
- **Issues**: https://github.com/3bkareno/Raqeeb/issues
- **Discussions**: https://github.com/3bkareno/Raqeeb/discussions

---

*This roadmap is a living document and will be updated as the project evolves.*

**Last Updated**: January 2026  
**Next Review**: Monthly
