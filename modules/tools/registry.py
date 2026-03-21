"""
Comprehensive tool registry for all scanning, analysis, and testing tools.

Each tool entry describes: what it does, how to invoke it, what category it belongs to,
and example usage patterns the AI agent can reference.

Total: 80+ tools across 22 categories.
"""

TOOL_REGISTRY = {
    # ─── Network & Port Scanning ───────────────────────────────────────
    "nmap": {
        "category": "network",
        "description": "Network discovery and security auditing — port scanning, service/OS detection, NSE scripts",
        "binary": "nmap",
        "examples": [
            "nmap -sV -sC -oN /output/nmap.txt {target}",
            "nmap -p- --min-rate 1000 -oN /output/nmap-allports.txt {target}",
            "nmap --script vuln -oN /output/nmap-vuln.txt {target}",
        ],
        "output_formats": ["txt", "xml", "json"],
    },
    "masscan": {
        "category": "network",
        "description": "Fast port scanner for large-scale network discovery",
        "binary": "masscan",
        "examples": [
            "masscan {target} -p0-65535 --rate 1000 -oJ /output/masscan.json",
        ],
        "output_formats": ["json", "xml"],
    },

    # ─── Vulnerability Scanning ────────────────────────────────────────
    "nuclei": {
        "category": "vulnerability",
        "description": "Template-based vulnerability scanner with 8000+ community templates for CVEs, misconfigs, exposed panels",
        "binary": "nuclei",
        "examples": [
            "nuclei -u {target} -o /output/nuclei.txt",
            "nuclei -u {target} -severity critical,high -o /output/nuclei-critical.txt",
            "nuclei -u {target} -j -o /output/nuclei.json",
        ],
        "output_formats": ["txt", "json", "sarif"],
    },
    "nikto": {
        "category": "vulnerability",
        "description": "Web server scanner detecting 6700+ dangerous files, outdated software, misconfigurations",
        "binary": "nikto",
        "examples": [
            "nikto -h {target} -Format json -o /output/nikto.json",
        ],
        "output_formats": ["txt", "json", "xml", "html"],
    },
    "zap-cli": {
        "category": "vulnerability",
        "description": "OWASP ZAP — dynamic application security testing (DAST) for web apps",
        "binary": "zap-cli",
        "examples": [
            "zap-cli quick-scan -s xss,sqli {target}",
            "zap-cli active-scan {target}",
            "zap-cli report -o /output/zap-report.html -f html",
        ],
        "output_formats": ["html", "json", "xml"],
    },
    "wapiti": {
        "category": "vulnerability",
        "description": "Black-box web app vulnerability scanner — fuzzes pages, injects payloads, detects XSS/SQLi/SSRF/XXE",
        "binary": "wapiti",
        "examples": [
            "wapiti -u {target} -o /output/wapiti/ -f json",
        ],
        "output_formats": ["json", "html", "xml", "txt"],
    },
    "sqlmap": {
        "category": "vulnerability",
        "description": "Automated SQL injection detection and exploitation",
        "binary": "sqlmap",
        "examples": [
            "sqlmap -u '{target}?id=1' --batch --output-dir=/output/sqlmap/",
            "sqlmap -u '{target}' --forms --batch --crawl=2 --output-dir=/output/sqlmap/",
        ],
        "output_formats": ["txt"],
    },

    # ─── API Security Testing ──────────────────────────────────────────
    "cats": {
        "category": "api_security",
        "description": "REST API fuzzer — auto-generates tests from OpenAPI specs using 140+ built-in fuzzers",
        "binary": "cats",
        "examples": [
            "cats --server=http://localhost:8080 --contract=openapi.yaml",
        ],
        "output_formats": ["json", "html", "junit"],
    },
    "stepci": {
        "category": "api_security",
        "description": "API quality assurance — REST, GraphQL, gRPC testing with fuzzing from OpenAPI specs",
        "binary": "stepci",
        "examples": [
            "stepci run workflow.yaml",
        ],
        "output_formats": ["json", "junit"],
    },
    "apifuzzer": {
        "category": "api_security",
        "description": "OpenAPI/Swagger fuzzer — reads API definitions and fuzzes fields to validate robustness",
        "binary": "APIFuzzer",
        "examples": [
            "APIFuzzer -s openapi_spec.json -u http://localhost:8080 --report /output/apifuzzer.json",
        ],
        "output_formats": ["json"],
    },

    # ─── SSL/TLS Testing ──────────────────────────────────────────────
    "testssl": {
        "category": "ssl",
        "description": "Comprehensive SSL/TLS configuration tester — protocols, ciphers, vulnerabilities (Heartbleed, ROBOT)",
        "binary": "testssl",
        "examples": [
            "testssl --json /output/testssl.json {target}",
        ],
        "output_formats": ["json", "html", "txt"],
    },
    "sslscan": {
        "category": "ssl",
        "description": "Identifies supported cipher suites, protocols, and key exchange methods",
        "binary": "sslscan",
        "examples": [
            "sslscan --xml=/output/sslscan.xml {target}",
        ],
        "output_formats": ["txt", "xml"],
    },
    "sslyze": {
        "category": "ssl",
        "description": "Fast Python-based SSL/TLS scanner — cipher suites, certificates, Heartbleed, ROBOT",
        "binary": "sslyze",
        "examples": [
            "sslyze {target} --json_out /output/sslyze.json",
        ],
        "output_formats": ["json", "txt"],
    },
    "openssl": {
        "category": "ssl",
        "description": "SSL/TLS toolkit — certificate inspection, protocol testing, cipher checks",
        "binary": "openssl",
        "examples": [
            "echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
        ],
        "output_formats": ["txt"],
    },

    # ─── Web Reconnaissance ───────────────────────────────────────────
    "whatweb": {
        "category": "recon",
        "description": "Web technology fingerprinting — identifies CMS, frameworks, libraries, server software",
        "binary": "whatweb",
        "examples": [
            "whatweb {target} --log-json=/output/whatweb.json",
        ],
        "output_formats": ["json", "txt"],
    },
    "subfinder": {
        "category": "recon",
        "description": "Subdomain discovery using passive sources",
        "binary": "subfinder",
        "examples": [
            "subfinder -d {target} -o /output/subdomains.txt",
        ],
        "output_formats": ["txt", "json"],
    },
    "httpx": {
        "category": "recon",
        "description": "HTTP toolkit — probes for live hosts, status codes, titles, technologies",
        "binary": "httpx",
        "examples": [
            "echo {target} | httpx -status-code -title -tech-detect -json -o /output/httpx.json",
        ],
        "output_formats": ["json", "txt"],
    },
    "gobuster": {
        "category": "recon",
        "description": "Directory/file brute-forcing and DNS subdomain enumeration",
        "binary": "gobuster",
        "examples": [
            "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o /output/gobuster.txt",
        ],
        "output_formats": ["txt"],
    },
    "dirb": {
        "category": "recon",
        "description": "Web content scanner for hidden directories and files",
        "binary": "dirb",
        "examples": ["dirb {target} -o /output/dirb.txt"],
        "output_formats": ["txt"],
    },
    "ffuf": {
        "category": "recon",
        "description": "Fast web fuzzer for directories, parameters, and virtual hosts",
        "binary": "ffuf",
        "examples": [
            "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o /output/ffuf.json -of json",
        ],
        "output_formats": ["json", "txt"],
    },
    "wafw00f": {
        "category": "recon",
        "description": "Web Application Firewall (WAF) detection and fingerprinting",
        "binary": "wafw00f",
        "examples": ["wafw00f {target} -o /output/waf.txt"],
        "output_formats": ["txt", "json"],
    },

    # ─── OSINT & Advanced Recon ────────────────────────────────────────
    "amass": {
        "category": "osint",
        "description": "OWASP Amass — in-depth attack surface mapping and subdomain enumeration from 50+ data sources",
        "binary": "amass",
        "examples": [
            "amass enum -d {target} -o /output/amass.txt",
            "amass enum -d {target} -passive -o /output/amass-passive.txt",
        ],
        "output_formats": ["txt", "json"],
    },
    "theharvester": {
        "category": "osint",
        "description": "OSINT harvester — gathers emails, subdomains, IPs from Bing, Shodan, LinkedIn, etc.",
        "binary": "theHarvester",
        "examples": [
            "theHarvester -d {target} -b all --file /output/harvester",
        ],
        "output_formats": ["xml", "json", "html"],
    },
    "spiderfoot": {
        "category": "osint",
        "description": "Automates OSINT across 200+ modules — IPs, domains, emails, names, dark web exposure",
        "binary": "spiderfoot",
        "examples": [
            "python3 sf.py -s {target} -m all -o json > /output/spiderfoot.json",
        ],
        "output_formats": ["json", "csv"],
    },

    # ─── Security Headers & Content Security ──────────────────────────
    "drheader": {
        "category": "headers",
        "description": "Security header auditor against OWASP ASVS 4.0 — checks CSP, HSTS, X-Frame-Options",
        "binary": "drheader",
        "examples": [
            "drheader scan single {target} --json > /output/drheader.json",
        ],
        "output_formats": ["json", "txt"],
    },
    "shcheck": {
        "category": "headers",
        "description": "Security header checker — quick validation of HTTP security headers",
        "binary": "shcheck.py",
        "examples": ["shcheck.py {target}"],
        "output_formats": ["json", "txt"],
    },

    # ─── CORS Testing ─────────────────────────────────────────────────
    "corsy": {
        "category": "cors",
        "description": "CORS misconfiguration scanner — checks reflected origins, null origin, wildcard, credential leaks",
        "binary": "corsy",
        "examples": [
            "python3 corsy.py -u {target} -j > /output/corsy.json",
        ],
        "output_formats": ["json", "txt"],
    },
    "corscanner": {
        "category": "cors",
        "description": "Fast CORS misconfiguration scanner across multiple domains",
        "binary": "cors_scan.py",
        "examples": [
            "python3 cors_scan.py -u {target} -o /output/corscanner.json",
        ],
        "output_formats": ["json"],
    },

    # ─── Subdomain Takeover ────────────────────────────────────────────
    "subjack": {
        "category": "takeover",
        "description": "Detects subdomain takeovers — dangling CNAME records pointing to unclaimed cloud resources",
        "binary": "subjack",
        "examples": [
            "subjack -w /output/subdomains.txt -t 100 -timeout 30 -o /output/subjack.txt -ssl",
        ],
        "output_formats": ["txt", "json"],
    },
    "dnsreaper": {
        "category": "takeover",
        "description": "Fast subdomain takeover scanner — 50+ takeover signatures, 50 subdomains/sec",
        "binary": "dnsreaper",
        "examples": [
            "dnsreaper scan --domain {target} --out /output/dnsreaper.json --out-format json",
        ],
        "output_formats": ["json", "csv"],
    },

    # ─── Secret Detection ──────────────────────────────────────────────
    "trufflehog": {
        "category": "secrets",
        "description": "Finds and verifies leaked credentials across Git repos, S3, Docker — 700+ credential detectors",
        "binary": "trufflehog",
        "examples": [
            "trufflehog git https://github.com/example/repo --json > /output/trufflehog.json",
            "trufflehog filesystem /path/to/code --json > /output/trufflehog.json",
        ],
        "output_formats": ["json"],
    },
    "gitleaks": {
        "category": "secrets",
        "description": "Scans Git repos and directories for hardcoded secrets using regex and entropy detection",
        "binary": "gitleaks",
        "examples": [
            "gitleaks detect --source=. --report-format=json --report-path=/output/gitleaks.json",
        ],
        "output_formats": ["json", "csv", "sarif"],
    },

    # ─── Container & Image Security ────────────────────────────────────
    "trivy": {
        "category": "container",
        "description": "Comprehensive scanner for vulnerabilities, misconfigs, secrets, SBOM in container images, repos, IaC",
        "binary": "trivy",
        "examples": [
            "trivy image --format json --output /output/trivy.json nginx:latest",
            "trivy fs --format json --output /output/trivy-fs.json /path/to/code",
            "trivy config --format json --output /output/trivy-iac.json /path/to/terraform",
        ],
        "output_formats": ["json", "sarif", "cyclonedx", "spdx"],
    },
    "grype": {
        "category": "container",
        "description": "Fast vulnerability scanner for container images and filesystems",
        "binary": "grype",
        "examples": [
            "grype nginx:latest -o json > /output/grype.json",
            "grype sbom:/output/sbom.spdx.json -o json > /output/grype-sbom.json",
        ],
        "output_formats": ["json", "cyclonedx", "sarif"],
    },

    # ─── Infrastructure as Code (IaC) Security ────────────────────────
    "checkov": {
        "category": "iac",
        "description": "Static analysis for IaC — 2500+ policies for Terraform, CloudFormation, K8s, Helm, Docker",
        "binary": "checkov",
        "examples": [
            "checkov -d ./terraform --output json > /output/checkov.json",
            "checkov -f Dockerfile --output json > /output/checkov-docker.json",
        ],
        "output_formats": ["json", "sarif", "junit"],
    },
    "kics": {
        "category": "iac",
        "description": "KICS — scans 22+ IaC platforms for misconfigurations and compliance issues",
        "binary": "kics",
        "examples": [
            "kics scan -p ./infrastructure --report-formats json -o /output/kics/",
        ],
        "output_formats": ["json", "sarif", "html", "pdf"],
    },

    # ─── Supply Chain & SBOM ───────────────────────────────────────────
    "syft": {
        "category": "supply_chain",
        "description": "Generates Software Bills of Materials (SBOMs) from container images and filesystems",
        "binary": "syft",
        "examples": [
            "syft nginx:latest -o spdx-json=/output/sbom.spdx.json",
            "syft dir:/path/to/code -o cyclonedx-json=/output/sbom.cdx.json",
        ],
        "output_formats": ["spdx-json", "cyclonedx-json", "json"],
    },
    "retire": {
        "category": "supply_chain",
        "description": "Retire.js — scans JavaScript libraries for known vulnerabilities, generates SBOMs",
        "binary": "retire",
        "examples": [
            "retire --path /path/to/project --outputformat json --outputpath /output/retire.json",
            "retire --outputformat cyclonedxJSON --outputpath /output/retire-sbom.json",
        ],
        "output_formats": ["json", "cyclonedx"],
    },

    # ─── JavaScript & Frontend Security ────────────────────────────────
    "semgrep": {
        "category": "sast",
        "description": "Lightweight SAST for 30+ languages — finds bugs, security issues, enforces standards",
        "binary": "semgrep",
        "examples": [
            "semgrep scan --config p/javascript --json --output /output/semgrep.json .",
            "semgrep scan --config p/security-audit --json --output /output/semgrep-security.json .",
            "semgrep scan --config p/owasp-top-ten --json --output /output/semgrep-owasp.json .",
        ],
        "output_formats": ["json", "sarif", "junit"],
    },

    # ─── Email Security ────────────────────────────────────────────────
    "checkdmarc": {
        "category": "email",
        "description": "Validates SPF, DMARC, and MX records with detailed diagnostics and DNSSEC checking",
        "binary": "checkdmarc",
        "examples": [
            "checkdmarc {target} -f json -o /output/checkdmarc.json",
        ],
        "output_formats": ["json", "csv"],
    },

    # ─── Phishing & Brand Protection ──────────────────────────────────
    "dnstwist": {
        "category": "phishing",
        "description": "Domain permutation engine — detects typosquatting, homograph phishing, brand impersonation",
        "binary": "dnstwist",
        "examples": [
            "dnstwist --registered --format json {target} > /output/dnstwist.json",
        ],
        "output_formats": ["json", "csv"],
    },

    # ─── SEO & Frontend Quality ────────────────────────────────────────
    "lighthouse": {
        "category": "seo",
        "description": "Google Lighthouse — audits performance, SEO, accessibility, best practices, PWA",
        "binary": "lighthouse",
        "examples": [
            "lighthouse {target} --output json --output-path /output/lighthouse.json --chrome-flags='--headless --no-sandbox'",
            "lighthouse {target} --only-categories=seo,accessibility --output json --output-path /output/lighthouse-seo.json --chrome-flags='--headless --no-sandbox'",
        ],
        "output_formats": ["json", "html"],
    },
    "yellowlab": {
        "category": "seo",
        "description": "Yellow Lab Tools — front-end quality analysis (page weight, DOM complexity, CSS complexity)",
        "binary": "yellowlabtools",
        "examples": ["yellowlabtools {target} > /output/yellowlab.json"],
        "output_formats": ["json"],
    },
    "broken-link-checker": {
        "category": "seo",
        "description": "Finds broken links on websites recursively",
        "binary": "blc",
        "examples": [
            "blc {target} --ordered --recursive --exclude-external -o /output/broken-links.txt",
        ],
        "output_formats": ["txt"],
    },
    "sitespeed": {
        "category": "seo",
        "description": "Comprehensive web performance analysis — Lighthouse, WebPageTest, real browser testing, budgets",
        "binary": "sitespeed.io",
        "examples": [
            "sitespeed.io {target} --outputFolder /output/sitespeed/ --budget.configPath budget.json",
        ],
        "output_formats": ["json", "html", "har", "junit"],
    },

    # ─── Accessibility Testing ─────────────────────────────────────────
    "pa11y": {
        "category": "accessibility",
        "description": "Automated accessibility testing against WCAG 2.1 rules",
        "binary": "pa11y",
        "examples": [
            "pa11y {target} --standard WCAG2AA --reporter json > /output/pa11y.json",
        ],
        "output_formats": ["json", "txt"],
    },
    "axe-core": {
        "category": "accessibility",
        "description": "Deque axe accessibility engine — tests against WCAG 2.0/2.1 rules",
        "binary": "axe",
        "examples": [
            "axe {target} --tags wcag2a,wcag2aa --save /output/axe-results.json",
        ],
        "output_formats": ["json"],
    },

    # ─── Performance & Load Testing ────────────────────────────────────
    "k6": {
        "category": "performance",
        "description": "Modern load testing — simulates concurrent users, measures response times, scripted in JS",
        "binary": "k6",
        "examples": [
            "k6 run --vus 10 --duration 30s /output/loadtest.js",
            "k6 run --out json=/output/k6-results.json /output/loadtest.js",
        ],
        "output_formats": ["json", "txt"],
    },
    "vegeta": {
        "category": "performance",
        "description": "HTTP load testing with constant request rate — precise rate control for API stress testing",
        "binary": "vegeta",
        "examples": [
            "echo 'GET {target}' | vegeta attack -duration=30s -rate=100 | vegeta report --type=json > /output/vegeta.json",
        ],
        "output_formats": ["json", "txt", "hdr"],
    },
    "locust": {
        "category": "performance",
        "description": "Scalable Python-based load testing — scriptable, distributed, real-time dashboard",
        "binary": "locust",
        "examples": [
            "locust --headless --users 100 --spawn-rate 10 -H {target} --json > /output/locust.json",
        ],
        "output_formats": ["json", "csv", "html"],
    },
    "artillery": {
        "category": "performance",
        "description": "Load testing for HTTP, WebSocket, Socket.IO — YAML-configured, rich reporting",
        "binary": "artillery",
        "examples": [
            "artillery run test.yaml --output /output/artillery.json",
            "artillery report /output/artillery.json --output /output/artillery.html",
        ],
        "output_formats": ["json", "html"],
    },
    "hey": {
        "category": "performance",
        "description": "Simple HTTP load generator — quick benchmarking like Apache ab but better",
        "binary": "hey",
        "examples": [
            "hey -n 1000 -c 50 {target}",
            "hey -n 1000 -c 50 -o csv {target} > /output/hey.csv",
        ],
        "output_formats": ["txt", "csv"],
    },
    "wrk": {
        "category": "performance",
        "description": "Modern HTTP benchmarking — high load generation on multi-core CPUs, Lua scripting",
        "binary": "wrk",
        "examples": [
            "wrk -t12 -c400 -d30s {target}",
        ],
        "output_formats": ["txt"],
    },

    # ─── Protocol Testing ──────────────────────────────────────────────
    "h2spec": {
        "category": "protocol",
        "description": "HTTP/2 conformance testing — validates server compliance against RFC 7540",
        "binary": "h2spec",
        "examples": [
            "h2spec http2 -h {target} -p 443 -t -j /output/h2spec.xml",
        ],
        "output_formats": ["txt", "junit"],
    },
    "wscat": {
        "category": "protocol",
        "description": "WebSocket client for testing and debugging WebSocket connections",
        "binary": "wscat",
        "examples": [
            "wscat -c wss://{target}/ws",
        ],
        "output_formats": ["txt"],
    },

    # ─── DNS & Domain Analysis ─────────────────────────────────────────
    "dig": {
        "category": "dns",
        "description": "DNS lookup utility — query records, check propagation, DNSSEC validation",
        "binary": "dig",
        "examples": [
            "dig {target} ANY +noall +answer",
            "dig {target} MX +short",
            "dig +dnssec {target}",
        ],
        "output_formats": ["txt"],
    },
    "whois": {
        "category": "dns",
        "description": "Domain registration information lookup",
        "binary": "whois",
        "examples": ["whois {target}"],
        "output_formats": ["txt"],
    },
    "dnsrecon": {
        "category": "dns",
        "description": "DNS enumeration — zone transfers, brute force, reverse lookups, SRV records",
        "binary": "dnsrecon",
        "examples": [
            "dnsrecon -d {target} -t std -j /output/dnsrecon.json",
        ],
        "output_formats": ["json", "txt"],
    },

    # ─── Certificate Transparency ──────────────────────────────────────
    "certspotter": {
        "category": "ct",
        "description": "Certificate Transparency log monitor — alerts on new certificates issued for your domains",
        "binary": "certspotter",
        "examples": [
            "certspotter -watchlist /output/watchlist.txt -start_from all",
        ],
        "output_formats": ["json", "txt"],
    },

    # ─── CMS-Specific Scanners ────────────────────────────────────────
    "wpscan": {
        "category": "cms",
        "description": "WordPress vulnerability scanner — plugins, themes, users, core version",
        "binary": "wpscan",
        "examples": [
            "wpscan --url {target} --enumerate vp,vt,u --output /output/wpscan.json --format json",
        ],
        "output_formats": ["json", "txt"],
    },
    "droopescan": {
        "category": "cms",
        "description": "CMS scanner for Drupal, Joomla, WordPress, SilverStripe, Moodle",
        "binary": "droopescan",
        "examples": [
            "droopescan scan drupal -u {target} -o json > /output/droopescan.json",
        ],
        "output_formats": ["json", "txt"],
    },

    # ─── Visual Regression & Defacement Detection ─────────────────────
    "backstopjs": {
        "category": "visual",
        "description": "Visual regression testing — compares DOM screenshots over time to detect CSS/layout changes",
        "binary": "backstop",
        "examples": [
            "backstop test --config=backstop.json",
        ],
        "output_formats": ["html", "json", "junit"],
    },

    # ─── Rate Limiting & Auth Testing ──────────────────────────────────
    "hydra": {
        "category": "auth",
        "description": "Network login cracker — tests brute force protections across 50+ protocols (SSH, HTTP, FTP, etc.)",
        "binary": "hydra",
        "examples": [
            "hydra -l admin -P /usr/share/wordlists/common-passwords.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:Invalid' -t 4",
        ],
        "output_formats": ["txt", "json"],
    },

    # ─── Cloud Security ────────────────────────────────────────────────
    "prowler": {
        "category": "cloud",
        "description": "Cloud security auditing — AWS, Azure, GCP against CIS, NIST, GDPR, HIPAA, PCI-DSS",
        "binary": "prowler",
        "examples": [
            "prowler aws --output-modes json-ocsf --output-directory /output/prowler/",
        ],
        "output_formats": ["json", "csv", "html"],
    },

    # ─── Utilities ─────────────────────────────────────────────────────
    "curl": {
        "category": "utility",
        "description": "HTTP client — check headers, timing, redirects, cookies, API responses",
        "examples": [
            "curl -sI {target}",
            "curl -s -o /dev/null -w '%{{http_code}} %{{time_total}}s TTFB:%{{time_starttransfer}}s' {target}",
            "curl -s {target}/robots.txt",
            "curl -s {target}/.well-known/security.txt",
        ],
        "output_formats": ["txt"],
    },
    "wget": {
        "category": "utility",
        "description": "Web content retriever — download pages, mirror sites, check links",
        "binary": "wget",
        "examples": [
            "wget --spider --recursive --level=2 --no-verbose {target} 2>&1 | grep -i 'broken\\|error'",
        ],
        "output_formats": ["txt"],
    },
    "jq": {
        "category": "utility",
        "description": "JSON processor — parse, filter, and transform JSON output from other tools",
        "binary": "jq",
        "examples": ["cat /output/nuclei.json | jq '.info.severity'"],
        "output_formats": ["json"],
    },
    "ping": {
        "category": "network",
        "description": "ICMP echo for connectivity and latency testing",
        "binary": "ping",
        "examples": ["ping -c 5 {target}"],
        "output_formats": ["txt"],
    },
    "traceroute": {
        "category": "network",
        "description": "Trace network path to target — identify hops and latency",
        "binary": "traceroute",
        "examples": ["traceroute -m 20 {target}"],
        "output_formats": ["txt"],
    },
}

# ─── Categories ────────────────────────────────────────────────────────────────

CATEGORIES = {
    "network": "Network & Port Scanning",
    "vulnerability": "Vulnerability Scanning",
    "api_security": "API Security Testing",
    "ssl": "SSL/TLS Testing",
    "recon": "Web Reconnaissance",
    "osint": "OSINT & Attack Surface",
    "headers": "Security Headers & Content Security",
    "cors": "CORS Misconfiguration Testing",
    "takeover": "Subdomain Takeover Detection",
    "secrets": "Secret & Credential Detection",
    "container": "Container & Image Security",
    "iac": "Infrastructure as Code Security",
    "supply_chain": "Supply Chain & SBOM",
    "sast": "Static Application Security Testing",
    "email": "Email Security (SPF/DKIM/DMARC)",
    "phishing": "Phishing & Brand Protection",
    "seo": "SEO & Frontend Quality",
    "accessibility": "Accessibility Testing",
    "performance": "Performance & Load Testing",
    "protocol": "Protocol Testing (HTTP/2, WebSocket)",
    "dns": "DNS & Domain Analysis",
    "ct": "Certificate Transparency",
    "cms": "CMS-Specific Scanners",
    "visual": "Visual Regression & Defacement",
    "auth": "Authentication & Rate Limit Testing",
    "cloud": "Cloud Security",
    "utility": "Utilities",
}

# Scan type → which tool categories are relevant
SCAN_TYPE_CATEGORIES = {
    "security": ["network", "vulnerability", "ssl", "recon", "headers", "cors", "secrets", "takeover"],
    "pentest": ["network", "vulnerability", "ssl", "recon", "cms", "auth", "cors", "takeover", "osint"],
    "performance": ["performance", "seo", "protocol", "utility"],
    "seo": ["seo", "accessibility", "utility", "headers", "protocol", "visual"],
    "compliance": ["vulnerability", "ssl", "headers", "utility", "email", "iac", "container"],
    "uptime": ["network", "dns", "ssl", "ct", "utility"],
    "full": list(CATEGORIES.keys()),
    "api_security": ["api_security", "vulnerability", "auth", "headers", "cors"],
    "cloud": ["cloud", "container", "iac", "secrets", "supply_chain"],
    "recon": ["recon", "osint", "dns", "takeover", "ct", "email", "phishing"],
    "privacy": ["headers", "seo", "accessibility", "email"],
}


def get_tools_for_category(category: str) -> dict:
    """Return all tools in a given category."""
    return {name: tool for name, tool in TOOL_REGISTRY.items() if tool["category"] == category}


def get_tools_for_scan_type(scan_type: str) -> dict:
    """Return all tools relevant to a scan type."""
    categories = SCAN_TYPE_CATEGORIES.get(scan_type, list(CATEGORIES.keys()))
    return {name: tool for name, tool in TOOL_REGISTRY.items() if tool["category"] in categories}


def get_all_tool_names() -> list[str]:
    """Return all tool names."""
    return list(TOOL_REGISTRY.keys())


def get_tool_summary(scan_type: str = "full") -> str:
    """Generate a tool summary string for use in agent prompts."""
    tools = get_tools_for_scan_type(scan_type)
    lines = []
    by_category = {}
    for name, tool in tools.items():
        cat = tool["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append((name, tool))

    for cat, cat_tools in by_category.items():
        cat_name = CATEGORIES.get(cat, cat)
        lines.append(f"\n### {cat_name}")
        for name, tool in cat_tools:
            lines.append(f"- **{name}**: {tool['description']}")
            if tool.get("examples"):
                lines.append(f"  Example: `{tool['examples'][0]}`")

    return "\n".join(lines)
