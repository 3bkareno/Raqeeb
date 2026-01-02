# Contributing to Raqeeb

Thank you for your interest in contributing to **Raqeeb** 👁️  
We welcome contributions that align with the project’s goals, architecture, and ethical standards.

---

## 🎯 Project Principles

Raqeeb is built around the following core principles:

- **Authorized and ethical security testing only**
- **Observation over exploitation**
- **Clean Architecture and maintainability**
- **Modularity and extensibility**
- **Safety by design**

All contributions must respect these principles.

---

## 🧱 Architecture Guidelines

Raqeeb follows **Clean Architecture** strictly.

### Layers:
- **Domain**: Core entities, business rules, interfaces  
- **Application**: Use cases, CQRS, orchestration logic  
- **Infrastructure**: Persistence, background jobs, external services  
- **Presentation**: ASP.NET Core Web API (API-first)

### Rules:
- Domain must not depend on any other layer
- No business logic in controllers
- Scanning logic must remain modular and pluggable
- Infrastructure concerns must not leak into Domain or Application

Pull requests that violate these rules may be rejected.

---

## 🧪 Scanner Modules

When contributing scanner modules:

- Do **not** include exploit payloads
- Detection logic only (safe observation)
- Follow existing module interfaces
- Provide clear, localized descriptions and recommendations
- Map findings to OWASP categories where applicable

---

## 🌍 Localization

Raqeeb supports localization (English / العربية).

- Use resource files for all user-facing text
- Do not hardcode strings
- Ensure Arabic translations respect RTL layout

---

## 🧹 Code Quality

- Follow existing coding style and conventions
- Write clean, readable, and well-documented code
- Prefer async/await for I/O operations
- Add tests where applicable

---

## 🔐 Security & Ethics

- Do not add features that enable unauthorized scanning
- Do not bypass safeguards or warnings
- Do not submit proof-of-concept exploits

Security-related issues should be reported privately (see `SECURITY.md`).

---

## 🚀 Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure code builds and tests pass
5. Open a pull request with a clear description

---

Thank you for helping make Raqeeb better 🛡️
