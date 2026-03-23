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
            "  Breach Monitoring: holehe, breach-parse\n"
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
                            "cvss_score": {
                                "type": "number",
                                "description": "CVSS base score (0.0–10.0). Will be auto-calculated if omitted.",
                            },
                            "cvss_vector": {
                                "type": "string",
                                "description": "CVSS vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'). Will be auto-calculated if omitted.",
                            },
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
                    "description": "High-level compliance status per framework",
                    "properties": {
                        "owasp_top10": {"type": "string", "enum": ["pass", "partial", "fail"]},
                        "pci_dss": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "gdpr": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "soc2": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "iso27001": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "hipaa": {"type": "string", "enum": ["pass", "partial", "fail", "n/a"]},
                        "tls_best_practices": {"type": "string", "enum": ["pass", "partial", "fail"]},
                    },
                },
                "compliance_reports": {
                    "type": "object",
                    "description": (
                        "Detailed per-requirement compliance reports for each framework. "
                        "Include this when performing a compliance_audit scan or when findings "
                        "map to specific compliance requirements. Each key is a framework ID "
                        "(pci_dss_4, soc2, iso27001, hipaa, gdpr, owasp_top10)."
                    ),
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "overall": {"type": "string", "enum": ["pass", "partial", "fail"]},
                            "framework_name": {"type": "string"},
                            "requirements": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string", "description": "Requirement ID, e.g. '6.2.4'"},
                                        "title": {"type": "string"},
                                        "status": {"type": "string", "enum": ["pass", "fail", "partial"]},
                                        "findings": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "Finding IDs (e.g. F-001) that caused this requirement to fail",
                                        },
                                        "evidence": {"type": "string", "description": "Evidence text for the failure"},
                                        "remediation": {"type": "string"},
                                    },
                                    "required": ["id", "title", "status"],
                                },
                            },
                            "pass_rate": {"type": "number", "description": "0.0–1.0 fraction of requirements passing"},
                            "critical_gaps": {"type": "integer", "description": "Count of critical/high-weight failing requirements"},
                        },
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
                "attack_chains": {
                    "type": "array",
                    "description": (
                        "Attack chains — sequences of vulnerabilities that combine into a higher-risk scenario. "
                        "Identify chains where multiple low/medium findings can be chained into a critical attack path."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {
                                "type": "string",
                                "description": "Short descriptive title, e.g. 'Account Takeover via Open Redirect + Session Fixation'",
                            },
                            "chain_risk_score": {
                                "type": "number",
                                "description": "Combined risk score 0-100 (typically higher than individual findings)",
                            },
                            "steps": {
                                "type": "array",
                                "description": "Ordered exploitation steps referencing individual findings",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "finding_ref": {
                                            "type": "string",
                                            "description": "Reference to a finding title or ID (e.g. 'Open Redirect on /oauth/callback')",
                                        },
                                        "action": {
                                            "type": "string",
                                            "description": "What the attacker does at this step",
                                        },
                                    },
                                    "required": ["finding_ref", "action"],
                                },
                            },
                            "impact": {
                                "type": "string",
                                "description": "End impact if the chain is successfully exploited",
                            },
                            "likelihood": {
                                "type": "string",
                                "enum": ["low", "medium", "high"],
                                "description": "Likelihood of a real attacker exploiting this chain",
                            },
                            "prerequisites": {
                                "type": "string",
                                "description": "What the attacker needs to execute this chain (e.g. 'Victim clicks crafted link')",
                            },
                        },
                        "required": ["title", "chain_risk_score", "steps", "impact", "likelihood"],
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
    # ── Breach & Dark Web Monitoring ─────────────────────────────────────────
    {
        "name": "breach_check",
        "description": (
            "Check if a domain has appeared in known data breaches using the Have I Been Pwned API "
            "and other breach intelligence sources. Returns breach names, dates, data types exposed, "
            "and affected account counts. Always run this during Phase 0 Discovery for security scans."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to check for breaches (e.g., 'example.com')",
                },
                "save_path": {
                    "type": "string",
                    "description": "Output path for results (default /output/breach_check.json)",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "credential_leak_check",
        "description": (
            "Search for exposed credentials and account registrations associated with a domain. "
            "Uses holehe and related tools to identify which services domain emails are registered on, "
            "indicating potential credential exposure surface. Run during Phase 0 Discovery."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to check for credential leaks (e.g., 'example.com')",
                },
                "emails": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific email addresses to check (if known). If not provided, uses common patterns like admin@domain, info@domain.",
                },
                "save_path": {
                    "type": "string",
                    "description": "Output path for results (default /output/credential_leak.json)",
                },
            },
            "required": ["domain"],
        },
    },
    # ── AI-first adaptive tools ──────────────────────────────────────────────
    {
        "name": "adapt_plan",
        "description": (
            "Revise your scan plan based on discoveries. Call this after Phase 0 (discovery) "
            "to create your initial test plan, and again whenever a major discovery changes "
            "what should be tested. This creates an audit trail of how the scan evolved."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Why the plan is being created or revised (e.g., 'Initial plan after discovery', 'Found chatbot on /chat endpoint')",
                },
                "discoveries": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Key discoveries that inform this plan",
                },
                "plan_steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "step": {"type": "string", "description": "What to test"},
                            "tools": {"type": "array", "items": {"type": "string"}, "description": "Tools to use"},
                            "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                            "triggered_by": {"type": "string", "description": "What discovery triggered this step"},
                        },
                        "required": ["step", "priority"],
                    },
                    "description": "Ordered test steps with tools and priority",
                },
                "knowledge_needed": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Knowledge modules to load (e.g., 'chatbot_testing', 'api_testing', 'owasp_testing', 'ssl_tls', 'auth_testing', 'form_testing', 'recon_advanced', 'performance', 'seo', 'compliance', 'cloud', 'graphql_testing', 'grpc_testing')",
                },
            },
            "required": ["reason", "plan_steps"],
        },
    },
    {
        "name": "load_knowledge",
        "description": (
            "Load a specialized testing knowledge module with detailed methodology. "
            "Load these WHEN RELEVANT based on what you discover, not upfront. "
            "Each module contains specific tools, commands, and testing procedures."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Knowledge module name",
                    "enum": [
                        "chatbot_testing", "api_testing", "owasp_testing", "ssl_tls",
                        "recon_advanced", "performance", "seo", "compliance", "cloud",
                        "form_testing", "auth_testing", "graphql_testing", "grpc_testing",
                    ],
                },
            },
            "required": ["module"],
        },
    },
    {
        "name": "get_session_headers",
        "description": (
            "Return the current authenticated session as curl flags and HTTP headers. "
            "Use when you need to inject authentication into shell tool commands like curl, "
            "nuclei, sqlmap, ffuf, etc. Returns empty strings if no session is active. "
            "Example: pass the curl_flags into a curl command to test authenticated endpoints."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "test_auth_endpoint",
        "description": (
            "Test an endpoint both WITH and WITHOUT authentication and compare the responses. "
            "Use this to discover authenticated-only content, identify access control boundaries, "
            "detect IDOR vulnerabilities, and compare the authenticated vs unauthenticated "
            "attack surface. Reports status codes, response sizes, and key differences."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to test",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (default GET)",
                    "enum": ["GET", "HEAD", "POST", "OPTIONS"],
                },
                "extra_headers": {
                    "type": "object",
                    "description": "Additional headers to include in both requests",
                },
                "body": {
                    "type": "string",
                    "description": "Request body for POST requests",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_session",
        "description": (
            "Check the status of the current authentication session. "
            "Returns whether the session is active, which cookies/headers are set, "
            "and whether re-authentication may be needed. "
            "Use before running a long batch of authenticated tests."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reauthenticate": {
                    "type": "boolean",
                    "description": "If true, attempt to re-authenticate if session is invalid (default false)",
                },
            },
        },
    },
    {
        "name": "update_attack_surface",
        "description": (
            "Update the structured attack surface map with discoveries. "
            "Call after reconnaissance and whenever you discover new components. "
            "Returns suggestions for what to test next based on discoveries."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "technologies": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Detected technologies (e.g., 'nginx 1.24', 'React', 'WordPress 6.4')",
                },
                "chatbots": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string", "description": "Platform (Intercom, Drift, custom, etc.)"},
                            "endpoint": {"type": "string", "description": "Chat API endpoint URL"},
                            "details": {"type": "string", "description": "Additional details"},
                        },
                    },
                    "description": "Detected chatbots/AI assistants",
                },
                "api_endpoints": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "method": {"type": "string"},
                            "auth_required": {"type": "boolean"},
                            "description": {"type": "string"},
                        },
                    },
                    "description": "Discovered API endpoints",
                },
                "forms": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "type": {"type": "string", "description": "login, registration, search, contact, upload, etc."},
                            "fields": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                    "description": "Discovered HTML forms",
                },
                "auth_mechanisms": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Auth types found (cookies, JWT, OAuth, API keys, etc.)",
                },
                "infrastructure": {
                    "type": "object",
                    "properties": {
                        "waf": {"type": "string"},
                        "cdn": {"type": "string"},
                        "cloud_provider": {"type": "string"},
                        "server": {"type": "string"},
                    },
                    "description": "Infrastructure details",
                },
                "open_ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Open ports discovered",
                },
                "subdomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Discovered subdomains",
                },
                "graphql_endpoints": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "Full GraphQL endpoint URL"},
                            "introspection_enabled": {"type": "boolean", "description": "Whether introspection query succeeded"},
                            "engine": {"type": "string", "description": "GraphQL engine (Apollo, Hasura, Strawberry, etc.)"},
                            "details": {"type": "string", "description": "Additional notes"},
                        },
                    },
                    "description": "Detected GraphQL endpoints with introspection status",
                },
                "grpc_services": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "host": {"type": "string", "description": "Host and port (e.g. target:50051)"},
                            "reflection_enabled": {"type": "boolean", "description": "Whether server reflection is enabled"},
                            "tls": {"type": "boolean", "description": "Whether TLS is in use"},
                            "methods": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Discovered RPC method names",
                            },
                            "details": {"type": "string", "description": "Additional notes"},
                        },
                    },
                    "description": "Detected gRPC services with reflection and method info",
                },
            },
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
    {
        "name": "ask_human",
        "description": (
            "Ask the human operator a question and wait for their response. "
            "Use this when you need human judgment, authorization, or clarification. "
            "Examples: asking permission before aggressive testing, clarifying scope, "
            "reporting a critical finding that needs immediate attention, or suggesting "
            "next steps that require human decision. The human may take up to 5 minutes "
            "to respond. If no response, continue autonomously."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The question or message for the human operator",
                },
                "timeout": {
                    "type": "integer",
                    "description": "How long to wait for response in seconds (default 300)",
                },
            },
            "required": ["question"],
        },
    },
]
