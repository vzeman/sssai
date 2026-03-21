"""
Agent tool definitions — everything the Claude AI agent can do during a scan.

Tools are registered with the Anthropic SDK and executed by the agent loop.
Includes PentAGI-inspired: sub-agent delegation, web search, exploit search, memory.
"""

TOOLS = [
    {
        "name": "run_command",
        "description": (
            "Execute a shell command in the scanning environment. "
            "Available tools by category:\n"
            "  Network: nmap, masscan, ping, traceroute\n"
            "  Vulnerability: nuclei, nikto, zap-cli, wapiti, sqlmap\n"
            "  API Security: cats, stepci, apifuzzer\n"
            "  SSL/TLS: testssl, sslscan, sslyze, openssl\n"
            "  Recon: whatweb, subfinder, httpx, gobuster, dirb, ffuf, wafw00f\n"
            "  OSINT: amass, theHarvester, spiderfoot\n"
            "  Headers: drheader, shcheck.py, curl\n"
            "  CORS: corsy, corscanner\n"
            "  Takeover: subjack, dnsreaper\n"
            "  Secrets: trufflehog, gitleaks\n"
            "  Container: trivy, grype\n"
            "  IaC: checkov, kics\n"
            "  Supply Chain: syft, retire\n"
            "  SAST: semgrep\n"
            "  Email: checkdmarc\n"
            "  Phishing: dnstwist\n"
            "  SEO: lighthouse, broken-link-checker (blc), yellowlabtools, sitespeed.io\n"
            "  Accessibility: pa11y, axe\n"
            "  CMS: wpscan, droopescan\n"
            "  Performance: k6, vegeta, locust, artillery, hey, wrk\n"
            "  Protocol: h2spec, wscat\n"
            "  DNS: dig, whois, dnsrecon\n"
            "  CT: certspotter\n"
            "  Visual: backstopjs\n"
            "  Auth: hydra\n"
            "  Cloud: prowler\n"
            "  Utility: curl, wget, jq, python3, node\n"
            "Save output files to /output/ for later reference."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default 300)",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read contents of a file from the /output/ directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to read",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write content to a file in /output/.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to write",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write",
                },
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "http_request",
        "description": (
            "Make an HTTP request and return headers, status, body. "
            "Useful for checking security headers, API responses, robots.txt, "
            "sitemap.xml, .well-known/security.txt, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to request",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (default GET)",
                    "enum": ["GET", "HEAD", "POST", "OPTIONS"],
                },
                "headers": {
                    "type": "object",
                    "description": "Custom request headers",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Follow redirects (default true)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Perform DNS lookups — A, AAAA, MX, TXT, NS, CNAME, SOA records.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to look up",
                },
                "record_type": {
                    "type": "string",
                    "description": "DNS record type (default ANY)",
                    "enum": ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "ANY"],
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "parse_json",
        "description": "Parse a JSON file and extract specific fields using jq-like path expressions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to JSON file",
                },
                "query": {
                    "type": "string",
                    "description": "jq expression to extract data (e.g., '.findings[] | .severity')",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "compare_results",
        "description": (
            "Compare current scan results with a previous scan to identify "
            "new, resolved, or changed findings. Useful for monitoring trends."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "current_file": {
                    "type": "string",
                    "description": "Path to current results file",
                },
                "previous_file": {
                    "type": "string",
                    "description": "Path to previous results file",
                },
            },
            "required": ["current_file", "previous_file"],
        },
    },
    {
        "name": "screenshot",
        "description": "Capture a screenshot of a web page using headless Chrome. Saved to /output/.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to screenshot",
                },
                "output_path": {
                    "type": "string",
                    "description": "Output file path (default /output/screenshot.png)",
                },
                "width": {
                    "type": "integer",
                    "description": "Viewport width (default 1920)",
                },
                "height": {
                    "type": "integer",
                    "description": "Viewport height (default 1080)",
                },
                "mobile": {
                    "type": "boolean",
                    "description": "Simulate mobile viewport (default false)",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "report",
        "description": "Submit the final structured scan report with all findings, risk score, and recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Executive summary of findings",
                },
                "risk_score": {
                    "type": "number",
                    "description": "Overall risk score 0-100 (100 = critical)",
                },
                "findings": {
                    "type": "array",
                    "description": "List of findings",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "enum": ["critical", "high", "medium", "low", "info"],
                            },
                            "category": {
                                "type": "string",
                                "description": "Finding category (e.g., 'ssl', 'headers', 'seo', 'xss', 'sqli')",
                            },
                            "description": {"type": "string"},
                            "evidence": {"type": "string"},
                            "cve_ids": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "cwes": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "CWE identifiers (e.g., 'CWE-79')",
                            },
                            "owasp_category": {
                                "type": "string",
                                "description": "OWASP Top 10 category if applicable",
                            },
                            "compliance_frameworks": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Affected compliance frameworks (PCI-DSS, GDPR, etc.)",
                            },
                            "remediation": {"type": "string"},
                            "remediation_commands": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "remediation_priority": {
                                "type": "string",
                                "enum": ["immediate", "short-term", "long-term"],
                                "description": "How urgently this should be fixed",
                            },
                            "affected_urls": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific URLs where the issue was found",
                            },
                            "references": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Reference URLs for more information",
                            },
                        },
                        "required": ["title", "severity", "description", "remediation"],
                    },
                },
                "technologies_detected": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "seo_scores": {
                    "type": "object",
                    "description": "SEO-specific scores (if applicable)",
                    "properties": {
                        "performance": {"type": "number", "description": "0-100"},
                        "seo": {"type": "number", "description": "0-100"},
                        "accessibility": {"type": "number", "description": "0-100"},
                        "best_practices": {"type": "number", "description": "0-100"},
                    },
                },
                "compliance_summary": {
                    "type": "object",
                    "description": "Compliance status per framework",
                    "properties": {
                        "owasp_top10": {"type": "string", "enum": ["pass", "partial", "fail"]},
                        "pci_dss": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "gdpr": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "tls_best_practices": {"type": "string", "enum": ["pass", "partial", "fail"]},
                    },
                },
                "attack_surface": {
                    "type": "object",
                    "description": "Attack surface summary",
                    "properties": {
                        "open_ports": {"type": "array", "items": {"type": "integer"}},
                        "subdomains_found": {"type": "integer"},
                        "exposed_services": {"type": "array", "items": {"type": "string"}},
                        "entry_points": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "improvement_roadmap": {
                    "type": "array",
                    "description": "Prioritized list of improvements",
                    "items": {
                        "type": "object",
                        "properties": {
                            "priority": {"type": "integer", "description": "1 = highest"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "effort": {"type": "string", "enum": ["low", "medium", "high"]},
                            "impact": {"type": "string", "enum": ["low", "medium", "high"]},
                        },
                    },
                },
                "scan_metadata": {
                    "type": "object",
                    "properties": {
                        "tools_used": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "duration_seconds": {"type": "integer"},
                        "commands_executed": {"type": "integer"},
                    },
                },
            },
            "required": ["summary", "risk_score", "findings"],
        },
    },
]


# ── Sub-agent, search, and memory tools ──────────────────────────────────

SUBAGENT_TOOLS = [
    {
        "name": "delegate_to_pentester",
        "description": (
            "Delegate a specific penetration testing task to a specialized pentester sub-agent. "
            "The sub-agent has access to all scanning tools and will focus exclusively on the "
            "delegated task. Use for: deep vulnerability analysis, exploit verification, "
            "attack chain exploration, or any task requiring focused security testing."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Specific task for the pentester (e.g., 'Test for SQL injection on login endpoint')",
                },
                "context": {
                    "type": "string",
                    "description": "Relevant context from your current scan (e.g., discovered endpoints, technologies)",
                },
            },
            "required": ["task"],
        },
    },
    {
        "name": "delegate_to_searcher",
        "description": (
            "Delegate a research task to a specialized searcher sub-agent. "
            "The sub-agent will search the web and exploit databases for relevant information. "
            "Use for: CVE research, exploit lookup, vulnerability details, security advisories, "
            "or understanding a specific technology's known weaknesses."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Research question (e.g., 'Find known CVEs for Apache 2.4.49')",
                },
                "context": {
                    "type": "string",
                    "description": "Relevant context from your scan",
                },
            },
            "required": ["task"],
        },
    },
    {
        "name": "delegate_to_coder",
        "description": (
            "Delegate a coding task to a specialized coder sub-agent. "
            "The sub-agent can write scripts, process scan data, create custom tools, "
            "or automate repetitive tasks. Use for: custom exploit scripts, data processing, "
            "or creating tool configurations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Coding task description",
                },
                "context": {
                    "type": "string",
                    "description": "Relevant context (e.g., data formats, requirements)",
                },
            },
            "required": ["task"],
        },
    },
    {
        "name": "web_search",
        "description": (
            "Search the web using DuckDuckGo. Returns titles, URLs, and snippets. "
            "Use for researching vulnerabilities, finding documentation, checking "
            "if a technology version has known issues, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max results to return (default 5)",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "exploit_search",
        "description": (
            "Search for exploits and CVEs across NVD and Exploit-DB. "
            "Returns CVE IDs, CVSS scores, descriptions, and exploit references. "
            "Use when you discover a specific software version and want to find known vulnerabilities."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g., 'Apache 2.4.49', 'CVE-2021-41773', 'WordPress 6.0')",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "search_memory",
        "description": (
            "Search cross-scan memory for reusable guides, findings, or answers from previous scans. "
            "Use before running a tool to check if you already have relevant information."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What to search for",
                },
                "type": {
                    "type": "string",
                    "description": "Memory type to search",
                    "enum": ["guide", "finding", "answer"],
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "store_memory",
        "description": (
            "Store a reusable guide, finding, or answer in cross-scan memory. "
            "Use to save: scanning methodologies that worked well, important findings "
            "about a target, or answers to research questions that may be useful in future scans."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Content to store",
                },
                "type": {
                    "type": "string",
                    "description": "Memory type",
                    "enum": ["guide", "finding", "answer"],
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Tags for searchability",
                },
            },
            "required": ["content"],
        },
    },
]
