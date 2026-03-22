# Security Checks

SSSAI provides 11 scan types, each tailored to a specific security or quality domain. This document explains what each scan type does, which tools it uses, what methodology the AI agent follows, and what kind of findings you can expect.

## How Scans Work

Every scan follows the same AI-driven process:

1. **Planning** — The AI agent receives the scan type prompt and generates a 3-7 step strategy tailored to your target
2. **Execution** — The agent calls scanning tools, interprets results in real-time, and adapts its approach based on what it discovers
3. **Monitoring** — Every 10 tool calls, an execution monitor reviews progress and redirects the agent if needed
4. **Reporting** — The agent produces a structured report with findings, risk scores, and remediation steps

The AI agent decides which specific tools to run and in what order — it's not a fixed script. This means scans adapt to what the agent discovers. For example, if the agent finds WordPress, it will automatically run WordPress-specific checks.

For more details on the agent architecture, see [Architecture](architecture.md).

---

## Scan Types

### security

**Purpose:** General vulnerability scanning — the most common scan type. Identifies CVEs, misconfigurations, weak headers, SSL issues, and exposed services.

**Key Tools:** nmap, nuclei (8,000+ vulnerability templates), nikto, testssl, sslyze

**What the Agent Does:**
1. Port scanning and service detection (nmap)
2. SSL/TLS configuration analysis (testssl, sslyze)
3. Web server vulnerability scanning (nikto)
4. Template-based vulnerability detection across thousands of known CVEs (nuclei)
5. HTTP security header analysis
6. Technology fingerprinting

**Example Findings:**
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Outdated software versions with known CVEs
- SSL/TLS misconfigurations (weak ciphers, expired certificates)
- Open ports exposing unnecessary services
- Server information disclosure

**Best For:** Regular security assessments, compliance checks, first-time scans of a target.

---

### pentest

**Purpose:** Penetration testing using PTES (Penetration Testing Execution Standard) methodology. Goes beyond detection to attempt exploitation and map attack chains.

**Key Tools:** nmap, sqlmap, hydra, wapiti, gobuster

**What the Agent Does:**
1. Reconnaissance and service enumeration
2. Directory and file brute-forcing (gobuster)
3. SQL injection testing (sqlmap)
4. Cross-site scripting (XSS) and injection testing (wapiti)
5. Credential brute-forcing on discovered services (hydra)
6. Attack chain mapping — connecting findings into exploitable paths

**Example Findings:**
- SQL injection vulnerabilities with proof of exploitation
- Default or weak credentials on services
- Directory traversal paths
- Exploitable misconfigurations with step-by-step attack chains
- Authentication bypass vectors

**Best For:** In-depth security testing, pre-release assessments, authorized penetration tests.

**Note:** This scan type performs active testing. Only use on targets you have authorization to test.

---

### seo

**Purpose:** Technical SEO audit covering Core Web Vitals, accessibility, broken links, and performance metrics.

**Key Tools:** lighthouse, pa11y, broken-link-checker (blc), yellowlabtools

**What the Agent Does:**
1. Google Lighthouse audit (performance, accessibility, best practices, SEO scores)
2. Core Web Vitals measurement (LCP, FID, CLS)
3. Accessibility compliance checking against WCAG standards (pa11y)
4. Broken link detection across the site
5. Page weight and resource optimization analysis (yellowlabtools)
6. Meta tag and structured data validation

**Example Findings:**
- Missing or duplicate meta descriptions
- Poor Core Web Vitals scores with specific metrics
- Accessibility violations (missing alt text, contrast issues, ARIA problems)
- Broken internal and external links
- Render-blocking resources, unoptimized images
- Missing structured data (schema.org)

**Best For:** Website launches, SEO audits, accessibility compliance (WCAG), content optimization.

---

### performance

**Purpose:** Load testing and performance benchmarking. Measures how your target handles traffic under stress.

**Key Tools:** hey, wrk, artillery, k6

**What the Agent Does:**
1. Baseline response time measurement
2. Concurrent connection testing with increasing load
3. Throughput measurement (requests/second)
4. Latency distribution analysis (p50, p95, p99)
5. Error rate under load
6. Resource bottleneck identification

**Example Findings:**
- Response time degradation under load (e.g., p99 > 2s at 100 concurrent users)
- Error rate increases at specific thresholds
- Throughput ceiling identification
- Connection timeout patterns
- Slow endpoints or API routes

**Best For:** Pre-launch load testing, capacity planning, performance regression detection.

**Note:** Load testing generates significant traffic. Coordinate with infrastructure teams before running against production targets.

---

### api_security

**Purpose:** API-specific security testing covering authentication, authorization, injection, rate limiting, and API-specific vulnerabilities.

**Key Tools:** nuclei, wapiti, curl, stepci

**What the Agent Does:**
1. API endpoint discovery and mapping
2. Authentication mechanism testing (JWT validation, token expiry, refresh flow)
3. Authorization testing (IDOR, privilege escalation)
4. Input validation and injection testing
5. Rate limiting verification
6. CORS policy analysis
7. API-specific vulnerability templates (nuclei)

**Example Findings:**
- Missing rate limiting on sensitive endpoints
- IDOR (Insecure Direct Object Reference) vulnerabilities
- JWT implementation weaknesses (algorithm confusion, missing expiry)
- Overly permissive CORS policies
- Mass assignment vulnerabilities
- Missing input validation

**Best For:** API security audits, microservice architectures, pre-deployment API reviews.

---

### compliance

**Purpose:** Compliance framework assessment against OWASP Top 10, PCI-DSS, GDPR, and CIS benchmarks.

**Key Tools:** nuclei, testssl, drheader, checkov

**What the Agent Does:**
1. OWASP Top 10 vulnerability mapping
2. PCI-DSS requirement checking (encryption, access control, logging)
3. GDPR technical compliance (data exposure, cookie consent, privacy headers)
4. CIS benchmark checks (server hardening, configuration baselines)
5. Security header compliance scoring
6. SSL/TLS compliance with industry standards

**Example Findings:**
- OWASP Top 10 violations mapped to specific categories (A01-A10)
- PCI-DSS non-compliance items (e.g., TLS 1.0 still enabled)
- GDPR issues (cookies without consent, data exposure)
- CIS benchmark failures
- Compliance summary showing pass/fail/partial per framework

**Report Format:**
The compliance scan produces a special `compliance_summary` section:
```json
{
  "compliance_summary": {
    "owasp_top10": "partial",
    "pci_dss": "fail",
    "gdpr": "pass",
    "tls_best_practices": "pass"
  }
}
```

**Best For:** Regulatory audits, compliance reporting, security baseline assessments.

---

### privacy

**Purpose:** Privacy-focused analysis covering cookie consent, data exposure, email security, and privacy headers.

**Key Tools:** curl, drheader, checkdmarc

**What the Agent Does:**
1. Privacy-related HTTP header analysis
2. Cookie audit (secure flags, SameSite, consent mechanisms)
3. Data exposure scanning (PII in responses, error messages)
4. Email security validation (SPF, DKIM, DMARC records via checkdmarc)
5. Third-party tracker identification
6. Privacy policy and consent flow analysis

**Example Findings:**
- Cookies set without Secure or HttpOnly flags
- Missing or misconfigured DMARC/SPF/DKIM records
- PII exposed in error messages or API responses
- Third-party tracking scripts without consent
- Missing privacy-related headers (Referrer-Policy, Permissions-Policy)

**Best For:** GDPR compliance preparation, privacy audits, email security hardening.

---

### cloud

**Purpose:** Cloud infrastructure and container security scanning. Analyzes IaC templates, container images, and dependencies for vulnerabilities.

**Key Tools:** trivy, checkov, grype

**What the Agent Does:**
1. Container image vulnerability scanning (trivy)
2. Infrastructure-as-Code security analysis (checkov) — Terraform, CloudFormation, Kubernetes
3. Software composition analysis — dependency vulnerabilities (grype)
4. Container misconfiguration detection
5. Secrets detection in configuration files
6. Compliance checking against cloud security benchmarks

**Example Findings:**
- Vulnerable packages in container images with CVE IDs
- IaC misconfigurations (public S3 buckets, overly permissive security groups)
- Hardcoded secrets in Dockerfiles or configuration
- Container running as root
- Missing resource limits in Kubernetes manifests

**Best For:** DevSecOps pipelines, container security, cloud infrastructure audits.

---

### recon

**Purpose:** Reconnaissance only — passive and active information gathering without exploitation. Maps the attack surface.

**Key Tools:** subfinder, whatweb, amass, dnsrecon

**What the Agent Does:**
1. Subdomain enumeration (subfinder, amass)
2. Technology fingerprinting (whatweb)
3. DNS record enumeration and analysis (dnsrecon)
4. Port scanning and service detection
5. WHOIS information gathering
6. Web application framework detection
7. WAF (Web Application Firewall) detection

**Example Findings:**
- Discovered subdomains with their technologies
- Open ports and running services across the attack surface
- DNS configuration issues (zone transfers, dangling records)
- Technology stack details (web servers, frameworks, CMS)
- WAF presence and type

**Best For:** Initial assessment of a new target, attack surface mapping, asset discovery.

---

### uptime

**Purpose:** Availability and health monitoring checks. Verifies that services are up, TLS certificates are valid, and DNS is resolving correctly.

**Key Tools:** curl, openssl, dig

**What the Agent Does:**
1. HTTP/HTTPS endpoint availability checks
2. TLS certificate validation and expiry checking
3. DNS resolution verification
4. Response time measurement
5. SSL certificate chain validation
6. Port connectivity testing

**Example Findings:**
- TLS certificate expiring within 30 days
- DNS resolution failures or slow response
- HTTP endpoints returning error codes
- SSL certificate chain issues
- High response times indicating degradation

**Best For:** Continuous monitoring setup, certificate management, service health verification.

---

### full

**Purpose:** Comprehensive scan that combines all scan types into a single assessment. Provides the most thorough analysis possible.

**Key Tools:** All 69+ tools available in the platform

**What the Agent Does:**
Executes checks from all scan types above in a single, coordinated scan. The AI agent prioritizes and orders the checks intelligently based on what it discovers.

**Best For:** Initial comprehensive assessment of a target, annual security reviews, complete audit reports.

**Note:** Full scans take significantly longer (15-45 minutes) and generate more API token usage. Consider running specific scan types for targeted analysis.

---

## Understanding Risk Scores

Every scan produces a **risk score** from 0 to 100:

| Score Range | Risk Level | Meaning |
|-------------|------------|---------|
| 0-20 | Low | Few or no significant issues found |
| 21-50 | Medium | Some issues that should be addressed |
| 51-79 | High | Significant vulnerabilities requiring attention |
| 80-100 | Critical | Severe vulnerabilities needing immediate action |

The risk score is calculated by the AI agent based on the severity and quantity of findings, taking into account:
- Number and severity of vulnerabilities
- Exploitability of discovered issues
- Potential business impact
- Presence of compensating controls

## Finding Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| `critical` | Actively exploitable, immediate risk | Fix immediately |
| `high` | Significant vulnerability, likely exploitable | Fix within days |
| `medium` | Moderate risk, may require specific conditions | Fix within weeks |
| `low` | Minor issue, limited impact | Fix when convenient |
| `info` | Informational finding, no direct risk | Awareness only |

## Cross-Scan Memory

SSSAI maintains a cross-scan memory that persists knowledge across scans:

| Memory Type | What It Stores |
|-------------|---------------|
| `guide` | Scanning methodologies that worked well for specific targets |
| `finding` | Important findings about a target from previous scans |
| `answer` | Research answers (CVE details, exploit info) reusable in future scans |

This means subsequent scans of the same target are smarter — the agent remembers what it found before and can focus on new areas or verify if previous issues were fixed.

## Further Reading

- [Scanning Tools](scanning-tools.md) — Detailed list of all 69+ tools
- [Architecture](architecture.md) — How the AI agent orchestrates scans
- [API Reference](api-reference.md) — How to trigger and manage scans via API
