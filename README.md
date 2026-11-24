# Secure Document Platform

Security review and hardening of a document-sharing web application (Flask, PostgreSQL), developed for the Secure Software course (MSc in Informatics Engineering, University of Coimbra).

The course provided a deliberately insecure baseline. We mapped its attack surface, found and exploited its vulnerabilities, defined security requirements, implemented them, and added a DevSecOps pipeline that verifies the controls on every change.

**Authors:** Gonçalo Nogueira, Luís Vaz, Pedro Costa

## Vulnerabilities found in the baseline

| ID | Vulnerability | Severity | CWE |
| --- | --- | --- | --- |
| V-01 | Flask debug console exposed (`/console`, remote code execution) | Critical | CWE-489 |
| V-02 | Passwords stored in plaintext | High | CWE-256 |
| V-03 | IDOR on `/documents/<id>` | High | CWE-639 |
| V-04 | Reflected XSS through the `uploaded` parameter | High | CWE-79 |
| V-05 | SQL injection in the document listing (UNION-based credential dump) | Critical | CWE-89 |
| V-06 | SQL injection in the login form (authentication bypass) | Critical | CWE-89 |
| V-07 | Readable session cookie signed with a weak secret | High | CWE-347 |
| V-08 | Sessions without expiry | Medium | CWE-613 |
| V-09 | Command injection in the upload path | Critical | CWE-78 |

Details and proof-of-concept payloads: [`docs/vulnerabilities.md`](docs/vulnerabilities.md).

## Security controls implemented

- **Authentication:** TOTP two-factor authentication, Argon2 password hashing, rate limiting on login and registration
- **Sessions:** signed cookies with `HttpOnly`, `Secure` and `SameSite`, CSRF tokens, session fixation protection, inactivity timeout
- **Authorization:** login and admin guards on every route, ownership checks on every document operation, separate least-privilege database roles
- **Input handling:** allowlist validation and parameterized queries throughout
- **File uploads:** PDF-only, size limits, ClamAV scanning, structure validation with qpdf, blocking of active content (JavaScript, launch actions, embedded files), files stored under their SHA-256 hash in an isolated analyzer service
- **Transport:** TLS on every hop (load balancer, reverse proxies, Elasticsearch, Kibana)
- **Monitoring:** structured security logs shipped through Fluent Bit to Elasticsearch, with Kibana dashboards
- **Error handling:** generic error pages, no stack traces or internal details exposed

## DevSecOps pipeline

**Continuous integration** ([`1-integration.yml`](.github/workflows/1-integration.yml))
- Gitleaks (secrets), Bandit (blocks on high severity), Semgrep (report only), pip-audit (dependencies)
- Smoke tests against the running stack
- Image build, Trivy scan (blocks on high and critical), CycloneDX SBOM, push to GitHub Container Registry

**Continuous delivery** ([`2-delivery.yml`](.github/workflows/2-delivery.yml))
- Deploys the images built in CI behind HTTPS
- pytest suites for the authentication flow and access control
- OWASP ZAP baseline scan; reviewed findings are listed in [`.zap/rules.tsv`](.zap/rules.tsv), any new alert fails the job

## Architecture

```
client ──HTTPS──> lb_entrypoint ──> lb_active / lb_inactive ──> proxy1 / proxy2 ──> web (Flask)
                                                                                    ├── db (PostgreSQL)
                                                                                    └── document-analyzer ── clamd
logs: containers ──> Fluent Bit ──> Elasticsearch ──> Kibana
```

## Running locally

```bash
cp .env.example .env              # set your own secrets
./scripts/generate_certs.sh       # local self-signed TLS material
docker compose up --build
```

The application is served at `https://localhost:8443` and Kibana at `https://localhost:5601`. Certificates are self-signed, so the browser will show a warning.

The seed accounts in `db/init.sql` were required by the course and are kept in plaintext on purpose; accounts created through the application are stored with Argon2. The files in `document-analyzer/upload-samples/` are test inputs for the upload pipeline, including the harmless EICAR antivirus test file.
