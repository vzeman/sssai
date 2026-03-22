# Scanning Tools

SSSAI's worker container includes 69+ security and analysis tools across 22 categories. The AI agent decides which tools to use based on the scan type and what it discovers during the scan.

You can query the full tool registry via the API:

```bash
# List all tools by category
curl http://localhost:8000/api/tools/ -H "Authorization: Bearer $TOKEN"

# List tools for a specific scan type
curl http://localhost:8000/api/tools/scan-type/security -H "Authorization: Bearer $TOKEN"

# Get details for a specific tool
curl http://localhost:8000/api/tools/nmap -H "Authorization: Bearer $TOKEN"
```

---

## Tools by Category

### Network

| Tool | Description |
|------|-------------|
| **nmap** | Port scanning, service detection, OS fingerprinting, NSE scripts |
| **masscan** | High-speed port scanning for large ranges |
| **ping** | ICMP connectivity testing |
| **traceroute** | Network path tracing |

### Vulnerability Scanning

| Tool | Description |
|------|-------------|
| **nuclei** | Template-based vulnerability scanner with 8,000+ detection templates |
| **nikto** | Web server vulnerability scanner |
| **wapiti** | Web application vulnerability scanner (XSS, SQLi, SSRF, etc.) |
| **sqlmap** | Automated SQL injection detection and exploitation |

### SSL/TLS

| Tool | Description |
|------|-------------|
| **testssl** | Comprehensive TLS/SSL testing (ciphers, protocols, vulnerabilities) |
| **sslyze** | Fast SSL/TLS server configuration analysis |
| **sslscan** | SSL/TLS cipher suite and certificate analysis |
| **openssl** | Certificate inspection, connection testing |

### HTTP Headers

| Tool | Description |
|------|-------------|
| **drheader** | Security header analysis against best practices |
| **shcheck** | Security headers checker |
| **curl** | HTTP requests with full header inspection |

### Reconnaissance

| Tool | Description |
|------|-------------|
| **whatweb** | Website technology fingerprinting |
| **subfinder** | Fast subdomain discovery |
| **httpx** | HTTP probing and technology detection |
| **gobuster** | Directory and file brute-forcing |
| **dirb** | Web content scanner |
| **ffuf** | Fast web fuzzer |
| **wafw00f** | Web Application Firewall detection |

### OSINT

| Tool | Description |
|------|-------------|
| **amass** | Attack surface mapping and asset discovery |
| **theHarvester** | Email, subdomain, and name harvesting |
| **spiderfoot** | Automated OSINT collection |

### DNS

| Tool | Description |
|------|-------------|
| **dig** | DNS lookup and query tool |
| **whois** | Domain registration information |
| **dnsrecon** | DNS enumeration and zone transfer testing |

### CORS

| Tool | Description |
|------|-------------|
| **corsy** | CORS misconfiguration scanner |
| **corscanner** | Cross-Origin Resource Sharing policy checker |

### Subdomain Takeover

| Tool | Description |
|------|-------------|
| **subjack** | Subdomain takeover vulnerability checker |
| **dnsreaper** | DNS subdomain takeover detection |

### Secrets Detection

| Tool | Description |
|------|-------------|
| **trufflehog** | Secrets scanning in git repositories |
| **gitleaks** | Git repository secrets detection |

### Container Security

| Tool | Description |
|------|-------------|
| **trivy** | Container image vulnerability scanning |
| **grype** | Software composition analysis |
| **syft** | Software bill of materials (SBOM) generation |

### Infrastructure as Code

| Tool | Description |
|------|-------------|
| **checkov** | IaC security scanning (Terraform, CloudFormation, Kubernetes, etc.) |
| **kics** | Infrastructure as Code security analysis |

### Static Analysis

| Tool | Description |
|------|-------------|
| **semgrep** | Lightweight static analysis for many languages |

### CMS

| Tool | Description |
|------|-------------|
| **wpscan** | WordPress vulnerability scanner |
| **droopescan** | Drupal, SilverStripe, and WordPress scanner |

### Email Security

| Tool | Description |
|------|-------------|
| **checkdmarc** | SPF, DKIM, and DMARC record validation |
| **dnstwist** | Domain name permutation and typosquatting detection |

### SEO & Performance

| Tool | Description |
|------|-------------|
| **lighthouse** | Google Lighthouse (performance, accessibility, SEO, best practices) |
| **pa11y** | Automated accessibility testing (WCAG compliance) |
| **axe** | Accessibility testing engine |
| **blc** | Broken link checker |
| **yellowlabtools** | Page weight and performance analysis |
| **sitespeed.io** | Website performance testing |

### Load Testing

| Tool | Description |
|------|-------------|
| **hey** | HTTP load generator |
| **wrk** | Modern HTTP benchmarking tool |
| **artillery** | Load testing and smoke testing |
| **k6** | Modern load testing with JavaScript scripting |
| **vegeta** | HTTP load testing tool |
| **locust** | Scalable load testing framework |

### Protocol

| Tool | Description |
|------|-------------|
| **h2spec** | HTTP/2 implementation conformance testing |
| **wscat** | WebSocket testing tool |

### Authentication

| Tool | Description |
|------|-------------|
| **hydra** | Network login cracker (brute-force testing) |

### Visual Regression

| Tool | Description |
|------|-------------|
| **backstopjs** | Visual regression testing |

---

## Tool Usage by Scan Type

| Scan Type | Primary Tools |
|-----------|--------------|
| `security` | nmap, nuclei, nikto, testssl, sslyze |
| `pentest` | nmap, sqlmap, hydra, wapiti, gobuster |
| `seo` | lighthouse, pa11y, blc, yellowlabtools |
| `performance` | hey, wrk, artillery, k6 |
| `api_security` | nuclei, wapiti, curl, stepci |
| `compliance` | nuclei, testssl, drheader, checkov |
| `privacy` | curl, drheader, checkdmarc |
| `cloud` | trivy, checkov, grype |
| `recon` | subfinder, whatweb, amass, dnsrecon |
| `uptime` | curl, openssl, dig |
| `full` | All tools |

The AI agent is not limited to the listed tools — it can use any available tool if it determines it's relevant during the scan.

## Further Reading

- [Security Checks](security-checks.md) — What each scan type does
- [Architecture](architecture.md) — How the agent selects and runs tools
- [API Reference](api-reference.md) — Query the tool registry via API
