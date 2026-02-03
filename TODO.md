# Raqeeb Development TODO List

> **Status Update**: February 3, 2026 - Phase 1 is ~60-70% complete  
> **See**: `PHASE1_MISSING_PARTS.md` for detailed analysis

## ?? Phase 1: Foundation & Security (Priority: HIGH) - ~60% COMPLETE

### 1.1 Authentication System (~70% Complete)
- [x] Create User entity with email, password hash, roles
- [x] Create Role and Permission entities
- [x] Integrate ASP.NET Core Identity
- [x] Create Login page component
- [x] Create Register page component
- [ ] **[CRITICAL]** Implement email service (SMTP/SendGrid) - 8-10h
- [ ] **[CRITICAL]** Implement email confirmation flow - 4-6h
- [x] Create Forgot Password page (UI only)
- [ ] **[CRITICAL]** Implement password reset backend - 4-6h
- [ ] Add JWT token generation for API (defer to Phase 6) - 6-8h
- [x] Create AuthenticationStateProvider
- [ ] **[CRITICAL]** Add [Authorize] attributes to protected pages - 2-3h
- [x] Create AuthorizeView components (partially)

### 1.2 Authorization & Roles (~80% Complete)
- [x] Define role constants (Admin, User, Viewer)
- [x] Create permission constants
- [x] Implement role-permission mapping (hardcoded)
- [x] Create Role Management page (Admin only)
- [x] Create User Management page (Admin only)
- [ ] **[HIGH]** Implement claims-based authorization - 6-8h
- [ ] Add role claims to JWT (when JWT implemented)

### 1.3 Infrastructure (~90% Complete)
- [x] Add Serilog for structured logging
- [x] Create AuditLog entity and service
- [ ] **[CRITICAL]** Integrate audit logging in AuthService - 3-4h
- [ ] **[CRITICAL]** Integrate audit logging in CRUD operations - 3-4h
- [ ] **[HIGH]** Create Admin/AuditLogs viewer page - 4-5h
- [x] Implement health check endpoints
- [x] Add rate limiting middleware (global)
- [ ] Add per-endpoint rate limiting policies - 2-4h
- [x] Configure HTTPS redirection
- [x] Add security headers middleware
- [ ] Enhance HSTS configuration - 0.5h

**Phase 1 Estimated Remaining Work**: 35-46 hours (critical path)

---

## ?? Phase 2: Scanner Modules (Priority: HIGH)

### 2.1 XSS Scanner
- [ ] Implement reflected XSS detection
- [ ] Implement stored XSS detection
- [ ] Add DOM-based XSS checks
- [ ] Create XSS payload library
- [ ] Handle encoding bypass techniques
- [ ] Add severity classification

### 2.2 SQL Injection Scanner
- [ ] Implement error-based SQLi detection
- [ ] Implement blind SQLi detection
- [ ] Add time-based detection
- [ ] Create SQLi payload library
- [ ] Handle different DB engines
- [ ] Add severity classification

### 2.3 CSRF Scanner
- [ ] Check for CSRF tokens in forms
- [ ] Validate token implementation
- [ ] Check SameSite cookie attribute
- [ ] Verify Referer/Origin headers

### 2.4 SSL/TLS Analyzer
- [ ] Check certificate validity
- [ ] Analyze cipher suites
- [ ] Check protocol versions (TLS 1.2/1.3)
- [ ] Detect weak configurations
- [ ] Check HSTS header

### 2.5 Additional Scanners
- [ ] CORS misconfiguration scanner
- [ ] Open redirect scanner
- [ ] Clickjacking scanner
- [ ] Directory bruteforce
- [ ] Subdomain enumeration
- [ ] Port scanner

### 2.6 Scanner Framework
- [ ] Create IScannerModule interface
- [ ] Implement plugin discovery
- [ ] Add module configuration system
- [ ] Create result normalization
- [ ] Implement CVSS scoring
- [ ] Add scanner progress reporting

---

## ? Phase 3: Automation & Scheduling (Priority: MEDIUM)

### 3.1 Background Processing
- [ ] Install Hangfire NuGet packages
- [ ] Configure Hangfire with SQL Server
- [ ] Create Hangfire dashboard endpoint
- [ ] Implement job retry logic
- [ ] Add job queue prioritization
- [ ] Create job monitoring service

### 3.2 Scheduling System
- [ ] Create Schedule entity
- [ ] Add CRON expression support
- [ ] Create Schedule CRUD pages
- [ ] Implement recurring job creation
- [ ] Add schedule enable/disable
- [ ] Create calendar view UI

### 3.3 Notifications
- [ ] Install SendGrid/SMTP package
- [ ] Create IEmailService interface
- [ ] Implement email templates (Razor)
- [ ] Send scan completion emails
- [ ] Send critical vulnerability alerts
- [ ] Create notification preferences page
- [ ] Add webhook notification support
- [ ] Create in-app notification center

---

## ?? Phase 4: Reporting & Export (Priority: MEDIUM)

### 4.1 Report Generation
- [ ] Install QuestPDF NuGet package
- [ ] Create HTML report template
- [ ] Implement PDF generation
- [ ] Install EPPlus for Excel
- [ ] Create Excel export
- [ ] Add JSON export endpoint

### 4.2 Report Features
- [ ] Create executive summary section
- [ ] Add vulnerability details section
- [ ] Include remediation guidance
- [ ] Add trend analysis charts
- [ ] Create comparison reports

### 4.3 Compliance Mapping
- [ ] Map vulnerabilities to OWASP Top 10
- [ ] Add CWE identifiers
- [ ] Create compliance report template
- [ ] Add custom template support

---

## ?? Phase 5: UI/UX & Localization (Priority: MEDIUM)

### 5.1 RTL Support
- [ ] Create RTL CSS stylesheet
- [ ] Update Bootstrap for RTL
- [ ] Fix sidebar layout for RTL
- [ ] Adjust table layouts
- [ ] Mirror directional icons
- [ ] Test all pages in Arabic

### 5.2 Language Persistence
- [ ] Save language to user profile
- [ ] Add cookie fallback for guests
- [ ] Create language detection
- [ ] Add more languages (FR, TR, ES)
- [ ] Implement Hijri calendar

### 5.3 UI Improvements
- [ ] Add dark mode toggle back
- [ ] Improve mobile responsiveness
- [ ] Add skeleton loading states
- [ ] Improve error messages
- [ ] Add keyboard shortcuts
- [ ] Implement WCAG accessibility
- [ ] Add onboarding tour

---

## ?? Phase 6: API & Integrations (Priority: MEDIUM)

### 6.1 REST API
- [ ] Create API controllers
- [ ] Add Swagger/OpenAPI docs
- [ ] Implement API versioning
- [ ] Add per-API-key rate limiting
- [ ] Create API key management page

### 6.2 CI/CD Integration
- [ ] Create GitHub Actions workflow
- [ ] Create Azure DevOps pipeline
- [ ] Build CLI scanning tool
- [ ] Create Docker image
- [ ] Publish to Docker Hub

### 6.3 Third-Party Integrations
- [ ] Slack webhook integration
- [ ] Microsoft Teams integration
- [ ] Jira issue creation
- [ ] PagerDuty alerts

---

## ?? Phase 7: Enterprise Features (Priority: LOW)

### 7.1 Multi-Tenancy
- [ ] Create Organization entity
- [ ] Implement tenant isolation
- [ ] Add subdomain routing
- [ ] Create org settings page

### 7.2 Team Collaboration
- [ ] Create Team entity
- [ ] Add member invite system
- [ ] Implement shared targets
- [ ] Add activity feed
- [ ] Create vulnerability comments

### 7.3 Advanced Security
- [ ] Implement TOTP 2FA
- [ ] Add SSO/SAML support
- [ ] Create session management
- [ ] Add IP whitelisting

---

## ?? Phase 8: Polish & Launch (Priority: LOW)

### 8.1 Performance
- [ ] Add Redis caching
- [ ] Optimize database queries
- [ ] Add database indexes
- [ ] Configure CDN
- [ ] Run load tests

### 8.2 DevOps
- [ ] Create Kubernetes manifests
- [ ] Create Helm charts
- [ ] Set up Prometheus monitoring
- [ ] Configure Grafana dashboards
- [ ] Implement centralized logging

### 8.3 Documentation
- [ ] Write user guide
- [ ] Write admin guide
- [ ] Complete API documentation
- [ ] Create video tutorials

### 8.4 Launch
- [ ] Conduct security audit
- [ ] Create Terms of Service
- [ ] Create Privacy Policy
- [ ] Build marketing website
- [ ] Run beta testing program

---

## ?? Progress Tracking

| Phase | Total Tasks | Completed | Progress | Status |
|-------|-------------|-----------|----------|--------|
| Phase 1 | 24 | 15 | ~65% | ? IN PROGRESS |
| Phase 2 | 30 | 0 | 0% | ? NOT STARTED |
| Phase 3 | 20 | 0 | 0% | ? NOT STARTED |
| Phase 4 | 14 | 0 | 0% | ? NOT STARTED |
| Phase 5 | 16 | 0 | 0% | ? NOT STARTED |
| Phase 6 | 14 | 0 | 0% | ? NOT STARTED |
| Phase 7 | 13 | 0 | 0% | ? NOT STARTED |
| Phase 8 | 17 | 0 | 0% | ? NOT STARTED |
| **Total** | **148** | **15** | **~10%** | ? EARLY STAGE |

### Phase 1 Breakdown (Updated Feb 3, 2026)
- Authentication System: 70% complete (7/10 tasks)
- Authorization & Roles: 80% complete (5/6 tasks)
- Infrastructure: 90% complete (6/7 tasks)
- **Estimated remaining effort**: 35-46 hours

For detailed Phase 1 analysis, see: **`PHASE1_MISSING_PARTS.md`**

---

*Last Updated: February 3, 2026*
