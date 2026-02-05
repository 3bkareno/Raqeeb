# 🛡️ Raqeeb - رقيب

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow)](ROADMAP.md)
[![Tests](https://img.shields.io/badge/Tests-29%20Passing-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/Coverage-2.2%25-yellow)](TestResults/CoverageReport/)

**Raqeeb** (رقيب - Arabic for "Observer/Watcher") is a modern, modular **web security vulnerability scanner** built with **.NET 10** and designed using **Clean Architecture** principles.

Raqeeb provides **safe, authorized security testing** capabilities, helping developers and security teams identify common web vulnerabilities following OWASP standards.

> ⚠️ **Legal Notice:** Raqeeb must only be used on systems you own or have explicit permission to test. Unauthorized scanning is illegal.

---

## 📊 Project Status

**Current Phase: Phase 3 - Automation & Scheduling** ✅ (100% Complete)

| Phase | Status | Progress |
|-------|--------|----------|
| **Phase 1: Foundation & Security** | ✅ **Complete** | **100%** |
| **Phase 2: Scanner Modules** | ✅ **Complete** | **100%** |
| **Phase 3: Automation & Scheduling** | ✅ **Complete** | **100%** |
| Phase 4: Reporting & Export | ⏳ Pending | 0% |
| Phase 5: UI/UX & Localization | ⏳ Pending | 0% |

### ✅ Phase 1 Completed Features:
- ✅ ASP.NET Core Identity integration
- ✅ User authentication & authorization
- ✅ Role-based access control (Admin, User, Viewer)
- ✅ Permission system
- ✅ Admin dashboard (user & role management)
- ✅ Serilog structured logging
- ✅ Audit logging service
- ✅ Health check endpoints
- ✅ Rate limiting middleware
- ✅ Security headers
- ✅ Blazor Server UI with modern dashboard
- ✅ Theme toggle (light/dark mode)
- ✅ Test infrastructure with xUnit
- ✅ Code coverage reporting (2.2%)
- ✅ Header Security Scanner
- ✅ Vulnerable test endpoints for validation

### ✅ Phase 2 Completed Features:
- ✅ XSS Scanner (Reflected, Stored, DOM-based)
- ✅ SQL Injection Scanner (Error-based, Blind, Time-based)
- ✅ CSRF Scanner (Token validation, SameSite cookies)
- ✅ SSL/TLS Scanner (Certificate validation, HSTS, Mixed content)
- ✅ CORS Scanner (Misconfiguration detection)
- ✅ Open Redirect Scanner
- ✅ Clickjacking Scanner (X-Frame-Options, CSP)
- ✅ Directory Bruteforce Scanner
- ✅ Port Scanner (Common ports, Service detection)
- ✅ Subdomain Enumeration Scanner
- ✅ Comprehensive test suite (29 tests passing)

### ✅ Phase 3 Completed Features:
- ✅ Hangfire background job processing
- ✅ Recurring scan scheduling with CRON expressions
- ✅ Email notifications (scan completion, failures, critical vulnerabilities)
- ✅ Webhook notifications
- ✅ Notification preferences system
- ✅ Schedule management (CRUD operations)
- ✅ Automatic scan execution from schedules
- ✅ Hangfire dashboard for job monitoring

### 🔄 Currently Working On:
- Phase 4: Reporting & Export
- PDF and Excel report generation

📋 Full roadmap: [ROADMAP.md](ROADMAP.md)

---

## 🧪 Test Status

```
✅ Tests: 29 passing (100% pass rate)
📊 Line Coverage: 2.2% (58/2537 lines)
📈 Method Coverage: 11% (25/227 methods)
🎯 Target Coverage: 70%
```

**Run Tests:**
```bash
dotnet test tests/Raqeeb.Tests
```

**Generate Coverage Report:**
```bash
dotnet test tests/Raqeeb.Tests --collect:"XPlat Code Coverage" --results-directory ./TestResults
reportgenerator -reports:"TestResults/**/coverage.cobertura.xml" -targetdir:"TestResults/CoverageReport" -reporttypes:Html
```

---

## 🔍 What is Raqeeb?

Raqeeb helps developers and security teams:

- ✅ Detect common web vulnerabilities (OWASP Top 10)
- ✅ Run modular, job-based security scans
- ✅ Manage multiple scan targets
- ✅ Configure custom scan profiles
- ✅ Generate detailed HTML & JSON reports
- ✅ Track vulnerability history
- ✅ Use modern, responsive dashboard
- ✅ API-first architecture for automation

---

## 🧱 Architecture

Raqeeb follows **Clean Architecture** with clear layer separation:

```
┌─────────────────────────────────────────┐
│          Presentation Layer             │
│  (Raqeeb.Web - Blazor Server)          │
│  (Raqeeb.Api - REST API)               │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│         Infrastructure Layer            │
│  (Raqeeb.Infrastructure)                │
│  - Scanning Engine                      │
│  - Database (EF Core)                   │
│  - External Services                    │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│         Application Layer               │
│  (Raqeeb.Application)                   │
│  - CQRS / MediatR                       │
│  - Business Logic                       │
│  - DTOs                                 │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│           Domain Layer                  │
│  (Raqeeb.Domain)                        │
│  - Entities                             │
│  - Interfaces                           │
│  - Domain Logic                         │
└─────────────────────────────────────────┘
```

**Key Principles:**
- Domain-Driven Design (DDD)
- Dependency Inversion
- Separation of Concerns
- Testability First
- SOLID Principles

---

## ✨ Current Features

### 🔐 Security & Authentication
- ✅ ASP.NET Core Identity integration
- ✅ JWT token authentication
- ✅ Role-based authorization (Admin, User, Viewer)
- ✅ Permission-based access control
- ✅ Secure password hashing
- ✅ Account lockout protection
- ✅ Email confirmation support

### 🔍 Scanning Engine
- ✅ Modular scanner architecture
- ✅ Header Security Scanner (X-Frame-Options, CSP, HSTS, etc.)
- ✅ Asynchronous scanning
- ✅ HTTP crawling capability
- ✅ Scan job management
- ✅ Vulnerability detection & storage
- ✅ Scan profiles (custom configurations)

### 📊 Dashboard & UI
- ✅ Modern Blazor Server interface
- ✅ Dashboard with scan statistics
- ✅ Target management
- ✅ Scan history viewer
- ✅ Vulnerability details
- ✅ User & role management (Admin)
- ✅ Light/Dark theme toggle
- ✅ Responsive design

### 📈 Monitoring & Logging
- ✅ Serilog structured logging
- ✅ Console & file sinks
- ✅ Audit logging for user actions
- ✅ Health check endpoints (/health, /health/ready, /health/live)
- ✅ Rate limiting (100 req/min)
- ✅ Security headers middleware

### 🧪 Testing & Quality
- ✅ xUnit test framework
- ✅ FluentAssertions for readable tests
- ✅ Moq for mocking
- ✅ Code coverage with Coverlet
- ✅ HTML coverage reports
- ✅ Vulnerable test endpoints for validation
- ✅ CI/CD ready structure

---

## 🚧 Coming Soon

### Phase 4: Reporting & Export (Next)
- 📄 PDF report generation
- 📊 Executive summary reports
- 📈 Trend analysis
- 🎨 Customizable report templates
- 📧 Email reports

### Phase 5: Localization
- 🌍 Full Arabic (العربية) translation
- 🌐 RTL (Right-to-Left) support
- 🗣️ Multi-language support

---

## 🛠 Tech Stack

| Category | Technologies |
|----------|-------------|
| **Framework** | .NET 10, C# 14 |
| **Web UI** | Blazor Server, Bootstrap 5 |
| **API** | ASP.NET Core Web API |
| **Database** | SQL Server, Entity Framework Core 10 |
| **Authentication** | ASP.NET Core Identity |
| **Logging** | Serilog |
| **Testing** | xUnit, FluentAssertions, Moq, Coverlet |
| **Architecture** | Clean Architecture, CQRS (MediatR) |
| **Patterns** | Repository, Unit of Work, DDD |

---

## 🚀 Getting Started

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- [SQL Server](https://www.microsoft.com/sql-server/sql-server-downloads) (or SQL Server Express)
- [Visual Studio 2025](https://visualstudio.microsoft.com/) or [VS Code](https://code.visualstudio.com/)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/3bkareno/Raqeeb.git
cd Raqeeb
```

2. **Update database connection string:**

Edit `src/Raqeeb.Web/appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=.;Database=Raqeeb;Trusted_Connection=True;TrustServerCertificate=True"
  }
}
```

3. **Apply database migrations:**
```bash
cd src/Raqeeb.Web
dotnet ef database update --project ../Raqeeb.Infrastructure
```

4. **Run the application:**
```bash
dotnet run --project src/Raqeeb.Web
```

5. **Access the application:**
- **Web UI:** https://localhost:7099
- **API:** https://localhost:7099/swagger

### Default Credentials

```
Email: admin@raqeeb.io
Password: Admin@123
```

**⚠️ Change the default password immediately after first login!**

---

## 🧪 Running Tests

**Run all tests:**
```bash
dotnet test
```

**Run tests with coverage:**
```bash
dotnet test --collect:"XPlat Code Coverage" --results-directory ./TestResults
```

**Generate HTML coverage report:**
```bash
# Install ReportGenerator (one-time)
dotnet tool install --global dotnet-reportgenerator-globaltool

# Generate report
reportgenerator -reports:"TestResults/**/coverage.cobertura.xml" -targetdir:"TestResults/CoverageReport" -reporttypes:Html

# Open report
start TestResults/CoverageReport/index.html
```

---

## 📁 Project Structure

```
Raqeeb/
├── src/
│   ├── Raqeeb.Domain/              # Domain entities, interfaces, enums
│   ├── Raqeeb.Application/         # Business logic, CQRS, DTOs
│   ├── Raqeeb.Infrastructure/      # Data access, scanning engine
│   ├── Raqeeb.Web/                 # Blazor Server UI
│   └── Raqeeb.Api/                 # REST API
├── tests/
│   └── Raqeeb.Tests/               # Unit & integration tests
├── docs/                           # Documentation
├── ROADMAP.md                      # Development roadmap
├── ARCHITECTURE.md                 # Architecture details
└── README.md                       # This file
```

---

## 📚 Documentation

- [Development Roadmap](ROADMAP.md) - Detailed development phases
- [Architecture](ARCHITECTURE.md) - System design and patterns
- [Contributing Guidelines](CONTRIBUTING.md) - How to contribute
- [API Documentation](docs/API.md) - REST API reference
- [Scanner Modules](docs/Scanners.md) - Scanner implementation guide

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Quality Standards

- ✅ All tests must pass
- ✅ Code coverage must not decrease
- ✅ Follow C# coding conventions
- ✅ Add XML documentation for public APIs
- ✅ Update relevant documentation

---

## 📜 Legal & Ethical Notice

**Raqeeb is intended strictly for authorized security testing.**

- ⚠️ Only scan systems you own or have explicit permission to test
- ⚠️ Unauthorized scanning is illegal and unethical
- ⚠️ Follow responsible disclosure practices
- ⚠️ Comply with local laws and regulations

The developers are not responsible for misuse of this tool.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Team

- **Lead Developer:** [@3bkareno](https://github.com/3bkareno)

---

## 🙏 Acknowledgments

- Inspired by OWASP security testing guidelines
- Built with modern .NET technologies
- Community-driven security research

---

## 📞 Contact & Support

- 🐛 **Report Issues:** [GitHub Issues](https://github.com/3bkareno/Raqeeb/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/3bkareno/Raqeeb/discussions)
- 📧 **Email:** support@raqeeb.io

---

**Built with ❤️ for the security community**

---

**Built with ❤️ for the security community**
