"""
Compliance mapper — maps security findings to specific compliance framework requirements.
Generates per-requirement pass/fail status with evidence references and calculates
pass_rate and critical_gaps per framework.

Supported frameworks: pci_dss_4, soc2, iso27001, hipaa, gdpr, owasp_top10
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Framework requirement catalogs
# ---------------------------------------------------------------------------

# Each requirement: id, title, category (for severity weighting), testable (external web)
FRAMEWORK_CATALOGS: dict[str, dict] = {
    "pci_dss_4": {
        "name": "PCI DSS 4.0",
        "short": "PCI DSS",
        "requirements": [
            {"id": "1.2.5",  "title": "All services, protocols, and ports allowed are identified and approved", "weight": "medium"},
            {"id": "2.2.1",  "title": "System components use vendor-supported software", "weight": "medium"},
            {"id": "2.2.7",  "title": "All non-console administrative access encrypted", "weight": "high"},
            {"id": "4.2.1",  "title": "Strong cryptography for data in transit (TLS 1.2+)", "weight": "critical"},
            {"id": "6.2.4",  "title": "Software engineering techniques prevent common vulnerabilities (SQLi, XSS, etc.)", "weight": "critical"},
            {"id": "6.3.3",  "title": "All software components protected from known vulnerabilities", "weight": "high"},
            {"id": "6.4.1",  "title": "Public-facing web applications protected against attacks", "weight": "high"},
            {"id": "7.2.1",  "title": "All access to system components and data is restricted", "weight": "high"},
            {"id": "8.2.1",  "title": "User IDs and authentication credentials managed properly", "weight": "high"},
            {"id": "8.3.4",  "title": "Invalid authentication attempts limited (account lockout)", "weight": "high"},
            {"id": "8.3.6",  "title": "Passwords meet minimum complexity requirements", "weight": "medium"},
            {"id": "8.4.2",  "title": "MFA implemented for all access into the CDE", "weight": "high"},
            {"id": "11.3.2", "title": "External vulnerability scans performed regularly", "weight": "medium"},
            {"id": "3.4.1",  "title": "PAN masked when displayed (first six/last four digits maximum)", "weight": "critical"},
            {"id": "6.4.3",  "title": "All payment page scripts managed and authorized (SRI / integrity controls)", "weight": "high"},
            {"id": "2.2.5",  "title": "Unnecessary functionality is removed or disabled on system components", "weight": "medium"},
        ],
    },
    "soc2": {
        "name": "SOC 2 (Trust Services Criteria)",
        "short": "SOC 2",
        "requirements": [
            {"id": "CC6.1",  "title": "Logical access security measures restrict unauthorized access", "weight": "critical"},
            {"id": "CC6.6",  "title": "Logical access security measures protect against external threats", "weight": "high"},
            {"id": "CC6.7",  "title": "Information transmission restricted to authorized parties (encryption)", "weight": "critical"},
            {"id": "CC7.1",  "title": "Vulnerabilities and threats are detected and monitored", "weight": "high"},
            {"id": "CC7.2",  "title": "System components monitored for anomalous behavior", "weight": "medium"},
            {"id": "CC8.1",  "title": "Infrastructure and software changes controlled to meet objectives", "weight": "medium"},
            {"id": "CC9.2",  "title": "Risks associated with vendors and third parties are managed", "weight": "medium"},
            {"id": "C1.1",   "title": "Confidential information identified and maintained", "weight": "high"},
            {"id": "PI1.2",  "title": "System inputs are complete, accurate, and valid", "weight": "high"},
            {"id": "P1.0",   "title": "Privacy notice provided to individuals about information practices", "weight": "medium"},
            {"id": "P2.0",   "title": "Choice and consent mechanisms established for personal data", "weight": "medium"},
            {"id": "A1.1",   "title": "Availability commitments and performance objectives met", "weight": "medium"},
        ],
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "short": "ISO 27001",
        "requirements": [
            {"id": "8.2",  "title": "Privileged access rights managed and controlled", "weight": "high"},
            {"id": "8.3",  "title": "Information access restriction based on need-to-know", "weight": "high"},
            {"id": "8.4",  "title": "Access to source code restricted", "weight": "medium"},
            {"id": "8.5",  "title": "Secure authentication controls implemented", "weight": "critical"},
            {"id": "8.7",  "title": "Protection against malware implemented", "weight": "high"},
            {"id": "8.8",  "title": "Management of technical vulnerabilities", "weight": "critical"},
            {"id": "8.9",  "title": "Configuration management — secure baseline configurations", "weight": "high"},
            {"id": "8.20", "title": "Network security controls implemented", "weight": "high"},
            {"id": "8.24", "title": "Use of cryptography — TLS and encryption standards", "weight": "critical"},
            {"id": "8.26", "title": "Application security requirements defined and implemented", "weight": "high"},
            {"id": "8.28", "title": "Secure coding practices (input validation, injection prevention)", "weight": "critical"},
            {"id": "8.29", "title": "Security testing in development and acceptance", "weight": "high"},
            {"id": "6.8",  "title": "Information security event reporting mechanism", "weight": "low"},
        ],
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "short": "HIPAA",
        "requirements": [
            {"id": "164.312(a)(2)(i)",    "title": "Unique user identification for ePHI access", "weight": "critical"},
            {"id": "164.312(a)(2)(iii)",  "title": "Automatic logoff — session timeout after inactivity", "weight": "medium"},
            {"id": "164.312(b)",          "title": "Audit controls — hardware/software activity recording", "weight": "high"},
            {"id": "164.312(c)(1)",       "title": "Integrity controls — ePHI not altered or destroyed improperly", "weight": "high"},
            {"id": "164.312(d)",          "title": "Person or entity authentication for ePHI access", "weight": "critical"},
            {"id": "164.312(e)(2)(ii)",   "title": "Encryption of ePHI in transit (TLS 1.2+)", "weight": "critical"},
            {"id": "164.308(a)(1)",       "title": "Security management process and risk analysis", "weight": "high"},
            {"id": "164.308(a)(4)(ii)(B)", "title": "Access authorization to ePHI systems", "weight": "high"},
        ],
    },
    "gdpr": {
        "name": "GDPR",
        "short": "GDPR",
        "requirements": [
            {"id": "Art. 5(1)(f)",  "title": "Integrity and confidentiality of personal data", "weight": "critical"},
            {"id": "Art. 13",      "title": "Information to be provided to data subjects (privacy notice)", "weight": "high"},
            {"id": "Art. 25",      "title": "Data protection by design and by default", "weight": "high"},
            {"id": "Art. 32",      "title": "Security of processing — appropriate technical measures", "weight": "critical"},
            {"id": "Art. 33",      "title": "Notification of personal data breach to supervisory authority", "weight": "medium"},
            {"id": "Art. 7",       "title": "Conditions for consent — freely given, specific, informed", "weight": "high"},
        ],
    },
    "owasp_top10": {
        "name": "OWASP Top 10 2021",
        "short": "OWASP",
        "requirements": [
            {"id": "A01:2021", "title": "Broken Access Control", "weight": "critical"},
            {"id": "A02:2021", "title": "Cryptographic Failures", "weight": "critical"},
            {"id": "A03:2021", "title": "Injection (SQLi, XSS, command injection)", "weight": "critical"},
            {"id": "A04:2021", "title": "Insecure Design", "weight": "high"},
            {"id": "A05:2021", "title": "Security Misconfiguration", "weight": "high"},
            {"id": "A06:2021", "title": "Vulnerable and Outdated Components", "weight": "high"},
            {"id": "A07:2021", "title": "Identification and Authentication Failures", "weight": "critical"},
            {"id": "A08:2021", "title": "Software and Data Integrity Failures", "weight": "high"},
            {"id": "A09:2021", "title": "Security Logging and Monitoring Failures", "weight": "medium"},
            {"id": "A10:2021", "title": "Server-Side Request Forgery (SSRF)", "weight": "high"},
        ],
    },
}

# ---------------------------------------------------------------------------
# Category-to-requirement mappings
# Each entry: finding_category_keyword → {framework: [requirement_ids]}
# ---------------------------------------------------------------------------

_CATEGORY_MAP: list[tuple[str, dict[str, list[str]]]] = [
    # TLS / SSL / Cryptography
    ("ssl", {
        "pci_dss_4": ["4.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.24"],
        "hipaa": ["164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32", "Art. 5(1)(f)"],
        "owasp_top10": ["A02:2021"],
    }),
    ("tls", {
        "pci_dss_4": ["4.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.24"],
        "hipaa": ["164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32", "Art. 5(1)(f)"],
        "owasp_top10": ["A02:2021"],
    }),
    ("certificate", {
        "pci_dss_4": ["4.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.24"],
        "hipaa": ["164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A02:2021"],
    }),
    ("cipher", {
        "pci_dss_4": ["4.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.24"],
        "hipaa": ["164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A02:2021"],
    }),
    ("hsts", {
        "pci_dss_4": ["4.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.24"],
        "hipaa": ["164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A02:2021"],
    }),
    ("cryptograph", {
        "pci_dss_4": ["4.2.1"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.24"],
        "hipaa": ["164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A02:2021"],
    }),
    # Injection
    ("sql", {
        "pci_dss_4": ["6.2.4", "6.4.1"],
        "soc2": ["CC6.1", "PI1.2"],
        "iso27001": ["8.28", "8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32", "Art. 5(1)(f)"],
        "owasp_top10": ["A03:2021"],
    }),
    ("injection", {
        "pci_dss_4": ["6.2.4", "6.4.1"],
        "soc2": ["CC6.1", "PI1.2"],
        "iso27001": ["8.28", "8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A03:2021"],
    }),
    ("command injection", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A03:2021"],
    }),
    # XSS
    ("xss", {
        "pci_dss_4": ["6.2.4", "6.4.1"],
        "soc2": ["CC6.1", "PI1.2"],
        "iso27001": ["8.28", "8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A03:2021"],
    }),
    ("cross-site scripting", {
        "pci_dss_4": ["6.2.4", "6.4.1"],
        "soc2": ["CC6.1", "PI1.2"],
        "iso27001": ["8.28", "8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A03:2021"],
    }),
    # CSRF
    ("csrf", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    ("cross-site request forgery", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    # SSRF
    ("ssrf", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A10:2021"],
    }),
    ("server-side request forgery", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A10:2021"],
    }),
    # Authentication / Authorization
    ("authentication", {
        "pci_dss_4": ["8.2.1", "8.3.4", "8.4.2"],
        "soc2": ["CC6.1", "CC6.6"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(d)", "164.312(a)(2)(i)"],
        "gdpr": ["Art. 32", "Art. 25"],
        "owasp_top10": ["A07:2021"],
    }),
    ("account lockout", {
        "pci_dss_4": ["8.3.4"],
        "soc2": ["CC6.6"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(d)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A07:2021"],
    }),
    ("brute force", {
        "pci_dss_4": ["8.3.4"],
        "soc2": ["CC6.6"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(d)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A07:2021"],
    }),
    ("password", {
        "pci_dss_4": ["8.3.6"],
        "soc2": ["CC6.6"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(d)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A07:2021"],
    }),
    ("mfa", {
        "pci_dss_4": ["8.4.2"],
        "soc2": ["CC6.6"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(d)"],
        "gdpr": ["Art. 25"],
        "owasp_top10": ["A07:2021"],
    }),
    ("multi-factor", {
        "pci_dss_4": ["8.4.2"],
        "soc2": ["CC6.6"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(d)"],
        "gdpr": ["Art. 25"],
        "owasp_top10": ["A07:2021"],
    }),
    ("default credential", {
        "pci_dss_4": ["8.2.1"],
        "soc2": ["CC6.6"],
        "iso27001": ["8.5", "8.9"],
        "hipaa": ["164.312(d)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A07:2021"],
    }),
    ("session", {
        "pci_dss_4": ["8.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.5"],
        "hipaa": ["164.312(a)(2)(iii)", "164.312(d)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A07:2021"],
    }),
    # Access Control
    ("access control", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.2", "8.3"],
        "hipaa": ["164.308(a)(4)(ii)(B)", "164.312(a)(2)(i)"],
        "gdpr": ["Art. 32", "Art. 25"],
        "owasp_top10": ["A01:2021"],
    }),
    ("directory listing", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.3"],
        "hipaa": ["164.308(a)(4)(ii)(B)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    ("unauthorized access", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.2", "8.3"],
        "hipaa": ["164.312(a)(2)(i)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    ("idor", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.3"],
        "hipaa": ["164.312(a)(2)(i)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    ("broken access", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.3"],
        "hipaa": ["164.312(a)(2)(i)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    # Security Headers / Misconfiguration
    ("header", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.26", "8.9"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("misconfiguration", {
        "pci_dss_4": ["2.2.1", "6.4.1"],
        "soc2": ["CC8.1"],
        "iso27001": ["8.9"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("cors", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("clickjacking", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("csp", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("content security policy", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.26"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    # Vulnerabilities / CVEs
    ("cve", {
        "pci_dss_4": ["6.3.3", "11.3.2"],
        "soc2": ["CC7.1"],
        "iso27001": ["8.8"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A06:2021"],
    }),
    ("outdated", {
        "pci_dss_4": ["6.3.3", "2.2.1"],
        "soc2": ["CC7.1", "CC8.1"],
        "iso27001": ["8.8", "8.9"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A06:2021"],
    }),
    ("vulnerable component", {
        "pci_dss_4": ["6.3.3"],
        "soc2": ["CC7.1"],
        "iso27001": ["8.8"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A06:2021"],
    }),
    # Information Disclosure
    ("information disclosure", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["C1.1"],
        "iso27001": ["8.9"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 5(1)(f)", "Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("sensitive data", {
        "pci_dss_4": ["3.4.1", "7.2.1"],
        "soc2": ["C1.1"],
        "iso27001": ["8.9"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 5(1)(f)", "Art. 32"],
        "owasp_top10": ["A02:2021"],
    }),
    ("data exposure", {
        "pci_dss_4": ["3.4.1", "7.2.1"],
        "soc2": ["C1.1"],
        "iso27001": ["8.3"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 5(1)(f)", "Art. 32"],
        "owasp_top10": ["A02:2021"],
    }),
    ("stack trace", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["C1.1"],
        "iso27001": ["8.9"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("version disclosure", {
        "pci_dss_4": ["2.2.1"],
        "soc2": ["CC8.1"],
        "iso27001": ["8.9"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    # Open ports / Network
    ("open port", {
        "pci_dss_4": ["1.2.5"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.20"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("exposed service", {
        "pci_dss_4": ["1.2.5", "2.2.5"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.20"],
        "hipaa": ["164.308(a)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    ("admin panel", {
        "pci_dss_4": ["7.2.1", "2.2.7"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.2"],
        "hipaa": ["164.308(a)(4)(ii)(B)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    # Cookie security
    ("cookie", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.7"],
        "iso27001": ["8.26"],
        "hipaa": ["164.312(d)", "164.312(e)(2)(ii)"],
        "gdpr": ["Art. 32", "Art. 7"],
        "owasp_top10": ["A05:2021"],
    }),
    # Privacy / GDPR
    ("privacy", {
        "pci_dss_4": [],
        "soc2": ["P1.0", "P2.0"],
        "iso27001": [],
        "hipaa": [],
        "gdpr": ["Art. 13", "Art. 7"],
        "owasp_top10": [],
    }),
    ("cookie consent", {
        "pci_dss_4": [],
        "soc2": ["P2.0"],
        "iso27001": [],
        "hipaa": [],
        "gdpr": ["Art. 7"],
        "owasp_top10": [],
    }),
    ("privacy policy", {
        "pci_dss_4": [],
        "soc2": ["P1.0"],
        "iso27001": [],
        "hipaa": [],
        "gdpr": ["Art. 13"],
        "owasp_top10": [],
    }),
    # Source code / git
    ("git", {
        "pci_dss_4": ["7.2.1"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.4"],
        "hipaa": ["164.308(a)(4)(ii)(B)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A05:2021"],
    }),
    # Subresource Integrity
    ("sri", {
        "pci_dss_4": ["6.4.3"],
        "soc2": ["CC9.2"],
        "iso27001": ["8.28"],
        "hipaa": [],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A08:2021"],
    }),
    ("subresource integrity", {
        "pci_dss_4": ["6.4.3"],
        "soc2": ["CC9.2"],
        "iso27001": ["8.28"],
        "hipaa": [],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A08:2021"],
    }),
    # Path traversal / File inclusion
    ("path traversal", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A01:2021"],
    }),
    ("file inclusion", {
        "pci_dss_4": ["6.2.4"],
        "soc2": ["CC6.1"],
        "iso27001": ["8.28"],
        "hipaa": ["164.312(c)(1)"],
        "gdpr": ["Art. 32"],
        "owasp_top10": ["A03:2021"],
    }),
    # Logging / Monitoring
    ("logging", {
        "pci_dss_4": [],
        "soc2": ["CC7.2"],
        "iso27001": [],
        "hipaa": ["164.312(b)"],
        "gdpr": [],
        "owasp_top10": ["A09:2021"],
    }),
    ("audit", {
        "pci_dss_4": [],
        "soc2": ["CC7.2"],
        "iso27001": [],
        "hipaa": ["164.312(b)"],
        "gdpr": [],
        "owasp_top10": ["A09:2021"],
    }),
]

# ---------------------------------------------------------------------------
# OWASP category → owasp_top10 requirement mapping
# ---------------------------------------------------------------------------

OWASP_CATEGORY_MAP: dict[str, str] = {
    "A01:2021": "A01:2021",
    "A02:2021": "A02:2021",
    "A03:2021": "A03:2021",
    "A04:2021": "A04:2021",
    "A05:2021": "A05:2021",
    "A06:2021": "A06:2021",
    "A07:2021": "A07:2021",
    "A08:2021": "A08:2021",
    "A09:2021": "A09:2021",
    "A10:2021": "A10:2021",
}

# Legacy OWASP Top 10 2017 remapping
OWASP_LEGACY_MAP: dict[str, str] = {
    "A1": "A01:2021",  "A01": "A01:2021",
    "A2": "A02:2021",  "A02": "A02:2021",
    "A3": "A03:2021",  "A03": "A03:2021",
    "A4": "A04:2021",  "A04": "A04:2021",
    "A5": "A05:2021",  "A05": "A05:2021",
    "A6": "A06:2021",  "A06": "A06:2021",
    "A7": "A07:2021",  "A07": "A07:2021",
    "A8": "A08:2021",  "A08": "A08:2021",
    "A9": "A09:2021",  "A09": "A09:2021",
    "A10": "A10:2021",
}

# Severity → weight score for gap calculation
SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

CRITICAL_SEVERITIES = {"critical", "high"}


def _normalize_owasp_category(raw: str) -> str | None:
    """Normalize OWASP category string to A0X:2021 format."""
    if not raw:
        return None
    upper = raw.upper().strip()
    if upper in OWASP_CATEGORY_MAP:
        return upper
    # Strip prefix variants
    for prefix in ("OWASP ", "OWASP TOP 10 ", "OWASP TOP10 "):
        if upper.startswith(prefix):
            upper = upper[len(prefix):]
    return OWASP_LEGACY_MAP.get(upper)


def _find_matching_requirements(
    finding: dict,
    framework: str,
) -> list[str]:
    """Return requirement IDs within a framework triggered by this finding."""
    matched: set[str] = set()

    # Build search text from finding fields
    text_fields = [
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("category", ""),
    ]
    search_text = " ".join(f.lower() for f in text_fields if f)

    # Match via category map
    for keyword, fw_map in _CATEGORY_MAP:
        if keyword in search_text and framework in fw_map:
            matched.update(fw_map[framework])

    # Match via compliance_frameworks field on the finding (agent-provided)
    cf = finding.get("compliance_frameworks") or []
    cf_lower = [c.lower() for c in cf]
    fw_aliases = {
        "pci_dss_4": ["pci-dss", "pci dss", "pci"],
        "soc2": ["soc 2", "soc2", "soc"],
        "iso27001": ["iso 27001", "iso27001", "iso/iec 27001"],
        "hipaa": ["hipaa"],
        "gdpr": ["gdpr"],
        "owasp_top10": ["owasp"],
    }
    aliases = fw_aliases.get(framework, [])
    if any(a in cf_lower_item for a in aliases for cf_lower_item in cf_lower):
        # Finding tagged with this framework — add most critical requirements if none matched
        if not matched:
            catalog = FRAMEWORK_CATALOGS.get(framework, {})
            critical_reqs = [
                r["id"] for r in catalog.get("requirements", [])
                if r.get("weight") in ("critical", "high")
            ]
            matched.update(critical_reqs[:3])  # Add top 3 critical requirements

    # Match via owasp_category for owasp_top10 framework
    if framework == "owasp_top10":
        owasp_raw = finding.get("owasp_category", "")
        normalized = _normalize_owasp_category(owasp_raw)
        if normalized:
            matched.add(normalized)

    return list(matched)


def generate_compliance_reports(report_data: dict) -> dict[str, dict]:
    """
    Generate per-framework compliance reports from scan findings.

    Returns a dict keyed by framework ID with structure:
    {
        "pci_dss_4": {
            "overall": "pass|partial|fail",
            "framework_name": "PCI DSS 4.0",
            "requirements": [
                {
                    "id": "6.2.4",
                    "title": "...",
                    "status": "pass|fail|partial",
                    "findings": ["F-001", "F-002"],
                    "evidence": "...",
                    "remediation": "..."
                }
            ],
            "pass_rate": 0.82,
            "critical_gaps": 3
        }
    }
    """
    findings = report_data.get("findings", [])
    compliance_summary = report_data.get("compliance_summary", {})

    # Determine which frameworks to include
    active_frameworks: set[str] = set()

    # Always include frameworks with overall status from agent
    if compliance_summary.get("owasp_top10") and compliance_summary["owasp_top10"] != "n/a":
        active_frameworks.add("owasp_top10")
    if compliance_summary.get("pci_dss") and compliance_summary["pci_dss"] != "n/a":
        active_frameworks.add("pci_dss_4")
    if compliance_summary.get("gdpr") and compliance_summary["gdpr"] != "n/a":
        active_frameworks.add("gdpr")

    # Include frameworks mentioned in findings
    for finding in findings:
        cf = finding.get("compliance_frameworks") or []
        for framework_tag in cf:
            tag_lower = framework_tag.lower()
            if "pci" in tag_lower:
                active_frameworks.add("pci_dss_4")
            if "soc" in tag_lower:
                active_frameworks.add("soc2")
            if "iso" in tag_lower or "27001" in tag_lower:
                active_frameworks.add("iso27001")
            if "hipaa" in tag_lower:
                active_frameworks.add("hipaa")
            if "gdpr" in tag_lower:
                active_frameworks.add("gdpr")
            if "owasp" in tag_lower:
                active_frameworks.add("owasp_top10")

    # Always include owasp_top10 (universal security baseline)
    active_frameworks.add("owasp_top10")

    # Pre-index findings by their IDs (use index as ID if no id field)
    finding_refs: list[dict] = []
    for i, f in enumerate(findings):
        finding_refs.append({
            "ref_id": f"F-{i+1:03d}",
            "finding": f,
        })

    result: dict[str, dict] = {}

    for framework_id in active_frameworks:
        catalog = FRAMEWORK_CATALOGS.get(framework_id)
        if not catalog:
            continue

        requirements_map: dict[str, dict] = {}
        for req in catalog["requirements"]:
            requirements_map[req["id"]] = {
                "id": req["id"],
                "title": req["title"],
                "status": "pass",
                "findings": [],
                "evidence": "",
                "remediation": "",
                "_weight": req.get("weight", "medium"),
                "_severity_max": "info",
            }

        # Map findings to requirements
        for ref in finding_refs:
            finding = ref["finding"]
            finding_id = ref["ref_id"]
            matched_reqs = _find_matching_requirements(finding, framework_id)

            severity = finding.get("severity", "info")
            evidence = finding.get("evidence", "")
            title = finding.get("title", "")
            remediation = finding.get("remediation", "")

            for req_id in matched_reqs:
                if req_id not in requirements_map:
                    continue
                req_entry = requirements_map[req_id]
                req_entry["findings"].append(finding_id)
                if evidence and not req_entry["evidence"]:
                    req_entry["evidence"] = f"{title}: {evidence[:200]}" if evidence else title
                elif title and req_id not in req_entry["evidence"]:
                    if req_entry["evidence"]:
                        req_entry["evidence"] += f"; {title}"
                    else:
                        req_entry["evidence"] = title
                if remediation and not req_entry["remediation"]:
                    req_entry["remediation"] = remediation

                # Update max severity for this requirement
                if SEVERITY_WEIGHT.get(severity, 0) > SEVERITY_WEIGHT.get(req_entry["_severity_max"], 0):
                    req_entry["_severity_max"] = severity

        # Determine per-requirement status
        for req_id, req_entry in requirements_map.items():
            if not req_entry["findings"]:
                req_entry["status"] = "pass"
            else:
                max_sev = req_entry["_severity_max"]
                if max_sev in ("critical", "high"):
                    req_entry["status"] = "fail"
                else:
                    req_entry["status"] = "partial"

        # Calculate metrics
        requirements_list = list(requirements_map.values())
        total = len(requirements_list)
        passed = sum(1 for r in requirements_list if r["status"] == "pass")
        failed = sum(1 for r in requirements_list if r["status"] == "fail")
        partial = sum(1 for r in requirements_list if r["status"] == "partial")

        pass_rate = round(passed / total, 2) if total > 0 else 1.0
        critical_gaps = sum(
            1 for r in requirements_list
            if r["status"] == "fail" and r["_weight"] in ("critical", "high")
        )

        # Overall status
        if failed == 0 and partial == 0:
            overall = "pass"
        elif failed > 0 and (failed / total) > 0.3:
            overall = "fail"
        elif passed / total >= 0.7:
            overall = "partial"
        else:
            overall = "fail"

        # Clean up internal fields before output
        for req_entry in requirements_list:
            req_entry.pop("_weight", None)
            req_entry.pop("_severity_max", None)

        result[framework_id] = {
            "overall": overall,
            "framework_name": catalog["name"],
            "framework_short": catalog["short"],
            "requirements": requirements_list,
            "pass_rate": pass_rate,
            "critical_gaps": critical_gaps,
            "total_requirements": total,
            "passed_requirements": passed,
            "failed_requirements": failed,
            "partial_requirements": partial,
        }

    return result
