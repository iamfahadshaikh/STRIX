"""
Tool output parsers for Phase 2A implementation.

Extracts structured findings from raw tool outputs.
"""

import re
import json
from dataclasses import replace
from typing import List, Optional, Dict, Any
from findings_model import Finding, FindingType, Severity, map_to_owasp


def _line_number_from_index(text: str, index: int) -> int:
    """Convert a string offset into a 1-based line number."""
    if index <= 0:
        return 1
    return text.count("\n", 0, index) + 1


def _attach_evidence_locations(findings: List[Finding], stdout: str, output_file: Optional[str]) -> List[Finding]:
    """Bind each finding to source file and nearest evidence line for traceability."""
    if not findings:
        return findings

    bound: List[Finding] = []
    for finding in findings:
        if finding.evidence_line > 0:
            line_num = finding.evidence_line
        else:
            line_num = 1
            snippet = (finding.evidence or "").strip()
            if snippet:
                first_line = snippet.splitlines()[0].strip()
                if first_line:
                    idx = stdout.find(first_line)
                    if idx >= 0:
                        line_num = _line_number_from_index(stdout, idx)

        bound.append(replace(
            finding,
            evidence_file=finding.evidence_file or (output_file or ""),
            evidence_line=line_num,
        ))

    return bound


class NmapParser:
    """Parse nmap output for open ports and service versions."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # Parse open ports
        port_pattern = r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?'
        for match in re.finditer(port_pattern, stdout):
            port, service, version = match.groups()
            
            # High-risk services
            risky_services = {
                'telnet': (Severity.HIGH, 'Telnet uses unencrypted communication'),
                'ftp': (Severity.MEDIUM, 'FTP may transmit credentials in cleartext'),
                'mysql': (Severity.MEDIUM, 'MySQL exposed to network'),
                'postgresql': (Severity.MEDIUM, 'PostgreSQL exposed to network'),
                'mongodb': (Severity.MEDIUM, 'MongoDB exposed to network'),
                'redis': (Severity.HIGH, 'Redis often exposed without authentication'),
                'vnc': (Severity.HIGH, 'VNC exposed'),
                'rdp': (Severity.MEDIUM, 'RDP exposed (brute-force risk)'),
                'smb': (Severity.MEDIUM, 'SMB exposed'),
            }
            
            if service.lower() in risky_services:
                severity, desc = risky_services[service.lower()]
                findings.append(Finding(
                    type=FindingType.MISCONFIGURATION,
                    severity=severity,
                    location=f"{target}:{port}",
                    description=f"{desc} on port {port}",
                    tool="nmap",
                    evidence=match.group(0),
                    owasp=map_to_owasp(FindingType.MISCONFIGURATION)
                ))
            else:
                # INFO-level finding for all discovered services (for visibility)
                findings.append(Finding(
                    type=FindingType.INFO_DISCLOSURE,
                    severity=Severity.INFO,
                    location=f"{target}:{port}",
                    description=f"Discovered {service} service on port {port}" + (f" ({version})" if version else ""),
                    tool="nmap",
                    evidence=match.group(0),
                    owasp=map_to_owasp(FindingType.INFO_DISCLOSURE)
                ))
            
            # Outdated versions
            if version and any(old in version.lower() for old in ['outdated', 'deprecated', 'unsupported']):
                findings.append(Finding(
                    type=FindingType.OUTDATED_SOFTWARE,
                    severity=Severity.MEDIUM,
                    location=f"{target}:{port}",
                    description=f"Outdated {service} version: {version}",
                    tool="nmap",
                    evidence=match.group(0),
                    owasp=map_to_owasp(FindingType.OUTDATED_SOFTWARE)
                ))
        
        # Parse vulnerabilities from vuln scripts
        vuln_pattern = r'\|\s+(.+?):\s*\n\|\s+State:\s+VULNERABLE'
        for match in re.finditer(vuln_pattern, stdout, re.MULTILINE):
            vuln_name = match.group(1).strip()
            findings.append(Finding(
                type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                location=target,
                description=f"Vulnerability detected: {vuln_name}",
                tool="nmap",
                evidence=match.group(0)[:200],
                owasp=map_to_owasp(FindingType.MISCONFIGURATION)
            ))
        
        return findings


class NiktoParser:
    """Parse nikto output for web server issues."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # OSVDB references indicate known vulnerabilities
        osvdb_pattern = r'OSVDB-(\d+):\s+(.+)'
        for match in re.finditer(osvdb_pattern, stdout):
            osvdb_id, description = match.groups()
            findings.append(Finding(
                type=FindingType.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                location=target,
                description=f"OSVDB-{osvdb_id}: {description.strip()}",
                tool="nikto",
                evidence=match.group(0)[:200],
                owasp=map_to_owasp(FindingType.MISCONFIGURATION)
            ))
        
        # Missing security headers (line-anchored, no inference by absence of generic string)
        missing_hdr_pattern = r'Suggested security header missing:\s*([^\.]+)'
        for match in re.finditer(missing_hdr_pattern, stdout, re.IGNORECASE):
            header_name = match.group(1).strip().lower()
            severity = Severity.LOW
            if header_name in {'content-security-policy', 'strict-transport-security'}:
                severity = Severity.MEDIUM

            findings.append(Finding(
                type=FindingType.MISCONFIGURATION,
                severity=severity,
                location=target,
                description=f"Missing security header: {header_name}",
                tool="nikto",
                evidence=match.group(0),
                impact="Weak browser-side hardening increases risk of clickjacking, content sniffing, and script injection abuse.",
                exploitability="Low alone, higher when chained with XSS/content injection.",
                remediation=f"Set and validate the {header_name} header at reverse-proxy/web-server level.",
                verification_steps=f"Re-run Nikto or curl -I and confirm header '{header_name}' is present in responses.",
                owasp=map_to_owasp(FindingType.MISCONFIGURATION)
            ))

        # BREACH should be contextual risk unless exploit is confirmed
        breach_pattern = r'BREACH attack'
        for match in re.finditer(breach_pattern, stdout, re.IGNORECASE):
            findings.append(Finding(
                type=FindingType.WEAK_CRYPTO,
                severity=Severity.LOW,
                location=target,
                description="Potential BREACH attack surface (contextual risk)",
                tool="nikto",
                cwe="CWE-200",
                evidence=match.group(0),
                impact="If secrets are reflected in compressed HTTPS responses, attackers may infer sensitive values.",
                exploitability="Context-dependent; requires attacker-controlled input and observable compressed responses.",
                remediation="Disable compression for secret-bearing responses and avoid reflecting secrets in response bodies.",
                verification_steps="Use testssl/response analysis to confirm compression on sensitive pages and test token reflection paths.",
                owasp=map_to_owasp(FindingType.WEAK_CRYPTO)
            ))
        
        # Server version disclosure
        server_pattern = r'Server:\s+(.+)'
        for match in re.finditer(server_pattern, stdout):
            server_info = match.group(1).strip()
            findings.append(Finding(
                type=FindingType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                location=target,
                description=f"Server version disclosure: {server_info}",
                tool="nikto",
                evidence=match.group(0),
                owasp=map_to_owasp(FindingType.INFO_DISCLOSURE)
            ))
        
        return findings


class GobusterParser:
    """Parse gobuster/dirsearch output for discovered endpoints."""
    
    @staticmethod
    def parse(stdout: str, target: str, tool_name: str = "gobuster") -> List[Finding]:
        findings = []
        
        # Sensitive endpoints
        sensitive_paths = {
            'admin': (Severity.HIGH, 'Admin panel exposed'),
            'phpinfo': (Severity.HIGH, 'phpinfo() page exposed (information disclosure)'),
            'backup': (Severity.MEDIUM, 'Backup files/directory exposed'),
            '.git': (Severity.HIGH, 'Git repository exposed'),
            '.env': (Severity.CRITICAL, 'Environment file exposed'),
            'config': (Severity.MEDIUM, 'Configuration directory exposed'),
            'wp-admin': (Severity.MEDIUM, 'WordPress admin panel'),
            'phpmyadmin': (Severity.HIGH, 'phpMyAdmin exposed'),
            'adminer': (Severity.HIGH, 'Adminer exposed'),
            'server-status': (Severity.MEDIUM, 'Apache server-status exposed'),
            'server-info': (Severity.MEDIUM, 'Apache server-info exposed'),
        }
        
        # Parse discovered paths (gobuster format: /path [Status: 200])
        path_pattern = r'(/[\w\.\-/]+)\s+\(Status:\s+(\d+)\)'
        for match in re.finditer(path_pattern, stdout):
            path, status = match.groups()
            
            # Check for sensitive paths
            path_lower = path.lower()
            for keyword, (severity, desc) in sensitive_paths.items():
                if keyword in path_lower:
                    findings.append(Finding(
                        type=FindingType.INFO_DISCLOSURE,
                        severity=severity,
                        location=f"{target}{path}",
                        description=desc,
                        tool=tool_name,
                        evidence=f"HTTP {status}: {path}",
                        owasp=map_to_owasp(FindingType.INFO_DISCLOSURE)
                    ))
                    break
        
        return findings


class DirsearchParser:
    """Parse dirsearch output (similar to gobuster but different format)."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        # Dirsearch format: [STATUS] SIZE URL
        findings = []
        
        sensitive_patterns = {
            r'\.git': (Severity.CRITICAL, 'Git repository exposed'),
            r'\.env': (Severity.CRITICAL, 'Environment configuration exposed'),
            r'backup': (Severity.HIGH, 'Backup files exposed'),
            r'admin': (Severity.HIGH, 'Admin interface exposed'),
            r'config': (Severity.MEDIUM, 'Configuration files exposed'),
        }
        
        line_pattern = r'\[(\d+)\]\s+\S+\s+(http[^\s]+)'
        for match in re.finditer(line_pattern, stdout):
            status, url = match.groups()
            
            if status.startswith('2'):  # 2xx success
                for pattern, (severity, desc) in sensitive_patterns.items():
                    if re.search(pattern, url, re.IGNORECASE):
                        findings.append(Finding(
                            type=FindingType.INFO_DISCLOSURE,
                            severity=severity,
                            location=url,
                            description=desc,
                            tool="dirsearch",
                            evidence=match.group(0),
                            owasp=map_to_owasp(FindingType.INFO_DISCLOSURE)
                        ))
                        break
        
        return findings


class XSStrikeParser:
    """Parse xsstrike output for XSS vulnerabilities."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # XSStrike outputs "Payload: ..." when it finds XSS
        payload_pattern = r'Payload:\s*(.+)'
        reflected_pattern = r'Reflections found:\s*(\d+)'
        
        payloads = re.findall(payload_pattern, stdout)
        reflections = re.findall(reflected_pattern, stdout)
        
        if payloads or reflections:
            findings.append(Finding(
                type=FindingType.XSS,
                severity=Severity.HIGH,
                location=target,
                description=f"Cross-Site Scripting vulnerability detected ({len(payloads)} payloads found)",
                tool="xsstrike",
                cwe="CWE-79",
                evidence=stdout[:500],
                owasp=map_to_owasp(FindingType.XSS)
            ))
        
        return findings


class XsserParser:
    """Parse xsser output for XSS vulnerabilities."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # XSSer reports "XSS FOUND!" or similar
        if any(keyword in stdout.lower() for keyword in ['xss found', 'vulnerability found', 'injection', 'vulnerable']):
            findings.append(Finding(
                type=FindingType.XSS,
                severity=Severity.HIGH,
                location=target,
                description="Cross-Site Scripting vulnerability detected",
                tool="xsser",
                cwe="CWE-79",
                evidence=stdout[:500],
                owasp=map_to_owasp(FindingType.XSS)
            ))
        
        return findings


class CommixParser:
    """Parse commix output for command injection."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # Commix reports injectable parameters
        injectable_pattern = r'Parameter:\s+(.+?)\s+is vulnerable'
        for match in re.finditer(injectable_pattern, stdout, re.IGNORECASE):
            param = match.group(1).strip()
            findings.append(Finding(
                type=FindingType.COMMAND_INJECTION,
                severity=Severity.CRITICAL,
                location=target,
                description=f"Command injection in parameter: {param}",
                tool="commix",
                cwe="CWE-78",
                evidence=match.group(0)[:200],
                owasp=map_to_owasp(FindingType.COMMAND_INJECTION)
            ))
        
        return findings


class SQLMapParser:
    """Enhanced SQLMap parser."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # SQLMap reports: "Parameter: X is vulnerable"
        param_pattern = r'Parameter:\s+([^\s]+)\s+.*?is vulnerable'
        for match in re.finditer(param_pattern, stdout, re.IGNORECASE):
            param = match.group(1).strip()
            findings.append(Finding(
                type=FindingType.SQLI,
                severity=Severity.CRITICAL,
                location=target,
                description=f"SQL Injection in parameter: {param}",
                tool="sqlmap",
                cwe="CWE-89",
                evidence=match.group(0)[:200],
                owasp=map_to_owasp(FindingType.SQLI)
            ))
        
        # Database enumeration
        if 'available databases' in stdout.lower():
            findings.append(Finding(
                type=FindingType.SQLI,
                severity=Severity.CRITICAL,
                location=target,
                description="SQL Injection confirmed: database enumeration successful",
                tool="sqlmap",
                cwe="CWE-89",
                evidence="Database enumeration successful",
                owasp=map_to_owasp(FindingType.SQLI)
            ))
        
        return findings


class SSLScanParser:
    """Enhanced sslscan parser."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # Weak protocols
        weak_protocols = {
            'sslv2': (Severity.CRITICAL, 'SSLv2 enabled (DROWN vulnerability)'),
            'sslv3': (Severity.HIGH, 'SSLv3 enabled (POODLE vulnerability)'),
            'tlsv1.0': (Severity.MEDIUM, 'TLS 1.0 enabled (deprecated)'),
            'tls 1.0': (Severity.MEDIUM, 'TLS 1.0 enabled (deprecated)'),
        }
        
        for protocol, (severity, desc) in weak_protocols.items():
            if re.search(rf'{re.escape(protocol)}\s+enabled', stdout, re.IGNORECASE):
                findings.append(Finding(
                    type=FindingType.WEAK_CRYPTO,
                    severity=severity,
                    location=target,
                    description=desc,
                    tool="sslscan",
                    owasp=map_to_owasp(FindingType.WEAK_CRYPTO),
                    evidence=f"Protocol {protocol} detected"
                ))
        
        # Weak ciphers
        weak_ciphers = ['null', 'anon', 'export', 'rc4', 'des', 'md5']
        for cipher in weak_ciphers:
            pattern = rf'{cipher}[^\n]*accepted'
            if re.search(pattern, stdout, re.IGNORECASE):
                findings.append(Finding(
                    type=FindingType.WEAK_CRYPTO,
                    severity=Severity.HIGH,
                    location=target,
                    description=f"Weak cipher suite accepted: {cipher.upper()}",
                    tool="sslscan",
                    owasp=map_to_owasp(FindingType.WEAK_CRYPTO),
                    evidence=f"Cipher {cipher} accepted"
                ))
        
        # Certificate issues
        cert_issues = {
            'expired': (Severity.HIGH, 'SSL certificate has expired'),
            'self-signed': (Severity.MEDIUM, 'Self-signed certificate'),
            'hostname mismatch': (Severity.HIGH, 'Certificate hostname mismatch'),
        }
        
        for issue, (severity, desc) in cert_issues.items():
            if issue in stdout.lower():
                findings.append(Finding(
                    type=FindingType.WEAK_CRYPTO,
                    severity=severity,
                    location=target,
                    description=desc,
                    tool="sslscan",
                    owasp=map_to_owasp(FindingType.WEAK_CRYPTO),
                    evidence=f"Certificate issue: {issue}"
                ))
        
        return findings


class TestSSLParser:
    """Enhanced testssl parser."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []

        # testssl.sh should only produce vulnerabilities when line explicitly indicates vulnerability,
        # and must not match "not vulnerable" / "(OK)" lines.
        vulnerabilities = {
            'heartbleed': (Severity.CRITICAL, 'CWE-119', 'Heartbleed vulnerability (CVE-2014-0160)'),
            'ccs': (Severity.HIGH, 'CWE-310', 'CCS Injection vulnerability'),
            'ticketbleed': (Severity.HIGH, 'CWE-200', 'Ticketbleed vulnerability'),
            'robot': (Severity.HIGH, 'CWE-203', 'ROBOT attack vulnerability'),
            'crime': (Severity.MEDIUM, 'CWE-310', 'CRIME attack vulnerability'),
            'poodle': (Severity.HIGH, 'CWE-310', 'POODLE vulnerability'),
            'sweet32': (Severity.MEDIUM, 'CWE-327', 'SWEET32 vulnerability'),
            'freak': (Severity.HIGH, 'CWE-327', 'FREAK attack vulnerability'),
            'drown': (Severity.CRITICAL, 'CWE-327', 'DROWN attack vulnerability'),
            'logjam': (Severity.HIGH, 'CWE-327', 'Logjam vulnerability'),
        }

        for line in stdout.splitlines():
            lower_line = line.lower()
            if not lower_line.strip():
                continue

            # BREACH is contextual by default unless exploit confirmation exists.
            if 'breach' in lower_line and ('potentially' in lower_line or 'gzip' in lower_line):
                findings.append(Finding(
                    type=FindingType.WEAK_CRYPTO,
                    severity=Severity.LOW,
                    location=target,
                    description="Potential BREACH attack surface (contextual risk)",
                    tool="testssl",
                    cwe="CWE-200",
                    owasp=map_to_owasp(FindingType.WEAK_CRYPTO),
                    evidence=line.strip(),
                    impact="Compression over HTTPS can leak secrets when attacker-controlled input is reflected.",
                    exploitability="Context-dependent; not a direct confirmed exploit.",
                    remediation="Disable compression for authenticated/secret-bearing responses or randomize secret-bearing responses.",
                    verification_steps="Validate compression behavior and reflection on secret-bearing endpoints."
                ))
                continue

            for vuln_name, (severity, cwe, desc) in vulnerabilities.items():
                if vuln_name not in lower_line:
                    continue

                # Never treat explicit negatives as vulnerable.
                if any(marker in lower_line for marker in ['not vulnerable', '(ok)', 'no heartbeat extension', 'no rc4 ciphers detected']):
                    continue

                if 'vulnerable' in lower_line or 'vulnerability' in lower_line:
                    findings.append(Finding(
                        type=FindingType.WEAK_CRYPTO,
                        severity=severity,
                        location=target,
                        description=desc,
                        tool="testssl",
                        cwe=cwe,
                        owasp=map_to_owasp(FindingType.WEAK_CRYPTO),
                        evidence=line.strip(),
                        impact="Weak TLS posture may enable interception or cryptographic attacks.",
                        exploitability="Medium to high depending on protocol/cipher exposure and attacker position.",
                        remediation="Disable vulnerable protocol/cipher options and enforce strong modern TLS configuration.",
                        verification_steps=f"Re-run testssl and confirm {vuln_name} no longer reports vulnerable status."
                    ))
                break
        
        return findings


class WhatwebParser:
    """Parse whatweb output for technology stack and CMS detection."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> Dict[str, Any]:
        """Returns structured tech stack data, not findings."""
        tech_stack = {
            'cms': None,
            'web_server': None,
            'languages': [],
            'frameworks': [],
            'javascript_libs': [],
        }
        
        lower = stdout.lower()
        
        # CMS detection
        cms_patterns = {
            'wordpress': 'WordPress',
            'drupal': 'Drupal',
            'joomla': 'Joomla',
            'magento': 'Magento',
            'shopify': 'Shopify',
        }
        for pattern, name in cms_patterns.items():
            if pattern in lower:
                tech_stack['cms'] = name
                break
        
        # Web server
        server_patterns = {
            'apache': 'Apache',
            'nginx': 'Nginx',
            'iis': 'IIS',
            'lighttpd': 'LigHTTPd',
        }
        for pattern, name in server_patterns.items():
            if pattern in lower:
                tech_stack['web_server'] = name
                break
        
        # Languages
        if 'php' in lower:
            tech_stack['languages'].append('PHP')
        if 'python' in lower or 'django' in lower or 'flask' in lower:
            tech_stack['languages'].append('Python')
        if 'java' in lower or 'jsp' in lower:
            tech_stack['languages'].append('Java')
        if 'asp' in lower or '.net' in lower:
            tech_stack['languages'].append('ASP.NET')
        if 'ruby' in lower or 'rails' in lower:
            tech_stack['languages'].append('Ruby')
        
        # Frameworks
        frameworks = ['django', 'flask', 'rails', 'laravel', 'symfony', 'spring', 'express']
        for fw in frameworks:
            if fw in lower:
                tech_stack['frameworks'].append(fw.capitalize())
        
        # JS libraries
        js_libs = ['jquery', 'react', 'vue', 'angular', 'bootstrap']
        for lib in js_libs:
            if lib in lower:
                tech_stack['javascript_libs'].append(lib.capitalize())
        
        return tech_stack


class WPScanParser:
    """Parse wpscan output for WordPress vulnerabilities."""
    
    @staticmethod
    def parse(stdout: str, target: str) -> List[Finding]:
        findings = []
        
        # Parse vulnerabilities in plugins
        plugin_vuln_pattern = r'\[!\]\s+Title:\s+(.+?)\n.*?Fixed in:\s+(.+?)\n.*?References:\s+(.+?)(?=\n\n|\Z)'
        for match in re.finditer(plugin_vuln_pattern, stdout, re.DOTALL):
            title, fixed_version, references = match.groups()
            findings.append(Finding(
                type=FindingType.VULNERABLE_COMPONENT,
                severity=Severity.HIGH,
                location=target,
                description=f"WordPress Plugin Vulnerability: {title.strip()}",
                tool="wpscan",
                evidence=f"Fixed in version: {fixed_version.strip()}",
                remediation=f"Update to version {fixed_version.strip()} or later",
                owasp=map_to_owasp(FindingType.VULNERABLE_COMPONENT)
            ))
        
        # Parse vulnerabilities in themes
        theme_vuln_pattern = r'\[!\]\s+Title:\s+(.+?)\n.*?(?:Fixed in:\s+(.+?)\n)?.*?References:\s+(.+?)(?=\n\n|\Z)'
        for match in re.finditer(theme_vuln_pattern, stdout, re.DOTALL):
            title = match.group(1)
            if 'theme' in title.lower():
                findings.append(Finding(
                    type=FindingType.VULNERABLE_COMPONENT,
                    severity=Severity.MEDIUM,
                    location=target,
                    description=f"WordPress Theme Vulnerability: {title.strip()}",
                    tool="wpscan",
                    owasp=map_to_owasp(FindingType.VULNERABLE_COMPONENT)
                ))
        
        # Parse WordPress version vulnerabilities
        wp_vuln_pattern = r'\[!\]\s+We found\s+(\d+)\s+vulnerabilities'
        for match in re.finditer(wp_vuln_pattern, stdout):
            vuln_count = match.group(1)
            findings.append(Finding(
                type=FindingType.VULNERABLE_COMPONENT,
                severity=Severity.HIGH,
                location=target,
                description=f"WordPress Core: {vuln_count} known vulnerabilities detected",
                tool="wpscan",
                remediation="Update WordPress to the latest version",
                owasp=map_to_owasp(FindingType.VULNERABLE_COMPONENT)
            ))
        
        # Parse outdated WordPress version
        version_pattern = r'WordPress version\s+([\d.]+)\s+identified.*?The version is out of date'
        for match in re.finditer(version_pattern, stdout, re.DOTALL):
            version = match.group(1)
            findings.append(Finding(
                type=FindingType.VULNERABLE_COMPONENT,
                severity=Severity.MEDIUM,
                location=target,
                description=f"Outdated WordPress version: {version}",
                tool="wpscan",
                remediation="Update WordPress to the latest stable version",
                owasp=map_to_owasp(FindingType.VULNERABLE_COMPONENT)
            ))
        
        # Parse username enumeration
        user_pattern = r'\[i\]\s+User\(s\) Identified:\n(.+?)(?=\n\n|\[|\Z)'
        for match in re.finditer(user_pattern, stdout, re.DOTALL):
            users_block = match.group(1)
            username_matches = re.findall(r'\|\s+(.+?)\s+\|', users_block)
            if username_matches:
                findings.append(Finding(
                    type=FindingType.INFORMATION_DISCLOSURE,
                    severity=Severity.LOW,
                    location=target,
                    description=f"WordPress usernames enumerated: {', '.join(username_matches[:5])}",
                    tool="wpscan",
                    evidence=f"Found {len(username_matches)} usernames",
                    remediation="Disable user enumeration or use security plugins to block enumeration attempts",
                    owasp=map_to_owasp(FindingType.INFORMATION_DISCLOSURE)
                ))
        
        return findings


def parse_tool_output(tool: str, stdout: str, stderr: str, target: str, output_file: Optional[str] = None) -> List[Finding]:
    """
    Unified parser dispatcher.
    
    Routes tool output to appropriate parser and returns findings.
    """
    if not stdout:
        return []
    
    parsers = {
        'nmap_quick': NmapParser.parse,
        'nmap_vuln': NmapParser.parse,
        'nikto': NiktoParser.parse,
        'gobuster': lambda s, t: GobusterParser.parse(s, t, 'gobuster'),
        'dirsearch': DirsearchParser.parse,
        'xsstrike': XSStrikeParser.parse,
        'xsser': XsserParser.parse,
        'commix': CommixParser.parse,
        'sqlmap': SQLMapParser.parse,
        'sslscan': SSLScanParser.parse,
        'testssl': TestSSLParser.parse,
        'wpscan': WPScanParser.parse,
    }
    
    parser = parsers.get(tool)
    if parser:
        try:
            findings = parser(stdout, target)
            return _attach_evidence_locations(findings, stdout, output_file)
        except Exception as e:
            # Log but don't crash
            print(f"[WARN] Parser error for {tool}: {e}")
            return []
    
    return []
