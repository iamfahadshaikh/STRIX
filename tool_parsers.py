"""
Tool output parsers for Phase 2A implementation.

Extracts structured findings from raw tool outputs.
"""

import re
import json
from typing import List, Optional, Dict, Any
from findings_model import Finding, FindingType, Severity, map_to_owasp


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
        
        # Missing security headers
        if 'x-frame-options' not in stdout.lower():
            findings.append(Finding(
                type=FindingType.MISCONFIGURATION,
                severity=Severity.LOW,
                location=target,
                description="Missing X-Frame-Options header (clickjacking risk)",
                tool="nikto",
                owasp=map_to_owasp(FindingType.MISCONFIGURATION)
            ))
        
        if 'x-content-type-options' not in stdout.lower():
            findings.append(Finding(
                type=FindingType.MISCONFIGURATION,
                severity=Severity.LOW,
                location=target,
                description="Missing X-Content-Type-Options header",
                tool="nikto",
                owasp=map_to_owasp(FindingType.MISCONFIGURATION)
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
            if protocol in stdout.lower() and 'enabled' in stdout.lower():
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
        
        # testssl.sh has colored output and detailed vulnerability checks
        vulnerabilities = {
            'heartbleed': (Severity.CRITICAL, 'CWE-119', 'Heartbleed vulnerability (CVE-2014-0160)'),
            'ccs injection': (Severity.HIGH, 'CWE-310', 'CCS Injection vulnerability'),
            'ticketbleed': (Severity.HIGH, 'CWE-200', 'Ticketbleed vulnerability'),
            'robot': (Severity.HIGH, 'CWE-203', 'ROBOT attack vulnerability'),
            'secure renegotiation': (Severity.MEDIUM, 'CWE-310', 'Insecure renegotiation'),
            'crime': (Severity.MEDIUM, 'CWE-310', 'CRIME attack vulnerability'),
            'breach': (Severity.MEDIUM, 'CWE-310', 'BREACH attack vulnerability'),
            'poodle': (Severity.HIGH, 'CWE-310', 'POODLE vulnerability'),
            'sweet32': (Severity.MEDIUM, 'CWE-327', 'SWEET32 vulnerability'),
            'freak': (Severity.HIGH, 'CWE-327', 'FREAK attack vulnerability'),
            'drown': (Severity.CRITICAL, 'CWE-327', 'DROWN attack vulnerability'),
            'logjam': (Severity.HIGH, 'CWE-327', 'Logjam vulnerability'),
        }
        
        for vuln_name, (severity, cwe, desc) in vulnerabilities.items():
            # testssl uses "VULNERABLE" or "vulnerable" markers
            pattern = rf'{vuln_name}[^\n]*vulnerable'
            if re.search(pattern, stdout, re.IGNORECASE):
                findings.append(Finding(
                    type=FindingType.WEAK_CRYPTO,
                    severity=severity,
                    location=target,
                    description=desc,
                    tool="testssl",
                    cwe=cwe,
                    owasp=map_to_owasp(FindingType.WEAK_CRYPTO),
                    evidence=f"Vulnerable to {vuln_name}"
                ))
        
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


def parse_tool_output(tool: str, stdout: str, stderr: str, target: str) -> List[Finding]:
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
    }
    
    parser = parsers.get(tool)
    if parser:
        try:
            return parser(stdout, target)
        except Exception as e:
            # Log but don't crash
            print(f"[WARN] Parser error for {tool}: {e}")
            return []
    
    return []
