"""
HTML Report Generator for Phase 2D implementation.

Creates interactive HTML dashboards with charts, remediation priorities,
and compliance mapping.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from intelligence_layer import CorrelatedFinding, IntelligenceEngine
from findings_model import Severity


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; }}
        .section {{ padding: 30px; border-bottom: 1px solid #eee; }}
        .section:last-child {{ border-bottom: none; }}
        .section h2 {{ color: #333; margin-bottom: 20px; font-size: 1.5em; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .stat-card .label {{ color: #666; font-size: 0.9em; margin-bottom: 5px; }}
        .stat-card .value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        .finding-card {{ background: #f8f9fa; padding: 20px; border-radius: 6px; margin-bottom: 15px; border-left: 4px solid; }}
        .finding-card.critical {{ border-color: #dc3545; }}
        .finding-card.high {{ border-color: #fd7e14; }}
        .finding-card.medium {{ border-color: #ffc107; }}
        .finding-card.low {{ border-color: #28a745; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-weight: 600; color: #333; }}
        .finding-meta {{ font-size: 0.9em; color: #666; margin-bottom: 10px; }}
        .finding-description {{ color: #444; line-height: 1.6; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 500; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: #0d6efd; color: white; }}
        .badge-exploit {{ background: #6c757d; color: white; margin-left: 5px; }}
        .chart-container {{ background: white; padding: 20px; border-radius: 6px; margin-bottom: 20px; }}
        .bar-chart {{ display: flex; align-items: flex-end; height: 200px; gap: 10px; }}
        .bar {{ flex: 1; background: linear-gradient(to top, #667eea, #764ba2); border-radius: 4px 4px 0 0; min-height: 10px; position: relative; }}
        .bar-label {{ text-align: center; margin-top: 10px; font-size: 0.85em; color: #666; }}
        .bar-value {{ position: absolute; top: -20px; width: 100%; text-align: center; font-weight: 600; }}
        .compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }}
        .compliance-card {{ background: #f8f9fa; padding: 15px; border-radius: 6px; }}
        .compliance-card h3 {{ color: #333; margin-bottom: 10px; font-size: 1.1em; }}
        .compliance-item {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #dee2e6; }}
        .compliance-item:last-child {{ border-bottom: none; }}
        .confidence-meter {{ background: #e9ecef; height: 10px; border-radius: 5px; overflow: hidden; margin-top: 5px; }}
        .confidence-fill {{ background: linear-gradient(90deg, #28a745, #ffc107, #dc3545); height: 100%; }}
        .tools-list {{ display: flex; flex-wrap: wrap; gap: 5px; margin-top: 5px; }}
        .tool-tag {{ background: #e7f3ff; color: #0056b3; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }}
        .detail-block {{ background: #f8f9fa; padding: 15px; border-radius: 6px; margin-top: 15px; }}
        .detail-block h3 {{ color: #333; margin-bottom: 10px; font-size: 1.05em; }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Scan Report</h1>
            <div class="meta">
                <div><strong>Target:</strong> {target}</div>
                <div><strong>Scan Date:</strong> {scan_date}</div>
                <div><strong>Correlation ID:</strong> {correlation_id}</div>
            </div>
        </div>

        <div class="section">
            <h2>🎯 Target Intelligence</h2>
            {target_intel_html}
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="label">Total Findings</div>
                    <div class="value">{total_findings}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Critical</div>
                    <div class="value severity-critical">{critical_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">High</div>
                    <div class="value severity-high">{high_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Medium</div>
                    <div class="value severity-medium">{medium_count}</div>
                </div>
                <div class="stat-card">
                    <div class="label">Avg Confidence</div>
                    <div class="value">{avg_confidence}%</div>
                </div>
                <div class="stat-card">
                    <div class="label">Multi-Tool Confirmed</div>
                    <div class="value">{multi_tool_count}</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🧪 Discovery Summary</h2>
            {discovery_section_html}
        </div>

        <div class="section">
            <h2>🔐 Auth + Access Control Summary</h2>
            {auth_access_control_html}
        </div>

        <div class="section">
            <h2>📝 Findings Summary</h2>
            {findings_summary_section_html}
        </div>

        <div class="section">
            <h2>🛡️ Security Strengths (Verified)</h2>
            {strengths_section_html}
        </div>

        <div class="section">
            <h2>🎯 Top 10 Critical Findings</h2>
            {top_findings_html}
        </div>

        <div class="section">
            <h2>📈 Severity Distribution</h2>
            <div class="chart-container">
                <div class="bar-chart">
                    {severity_chart_html}
                </div>
            </div>
        </div>

        <div class="section">
            <h2>✅ Compliance Mapping</h2>
            <div class="compliance-grid">
                {compliance_html}
            </div>
        </div>

        <div class="section">
            <h2>🔧 Remediation Priority Queue</h2>
            <p style="color: #666; margin-bottom: 20px;">Fix these vulnerabilities in order of priority (exploitability × confidence × attack surface):</p>
            {remediation_queue_html}
        </div>

        <div class="section">
            <h2>🧭 Vulnerability-Centric View</h2>
            {vuln_section_html}
        </div>

        <div class="section">
            <h2>🏦 Business Risk Aggregation</h2>
            {risk_section_html}
        </div>

        <div class="section">
            <h2>⚔️ Phase 5: Confirmed Active Exploitation</h2>
            {confirmed_exploitation_html}
        </div>

        <div class="section">
            <h2>🔦 Service Fingerprinting Results</h2>
            {service_fingerprints_html}
        </div>

        <div class="section">
            <h2>🔐 TLS Certificate Health (All Hosts)</h2>
            {certificate_assessments_html}
        </div>

        <div class="section">
            <h2>🌐 Host Network Assessment</h2>
            {host_network_assessment_html}
        </div>

        <div class="section">
            <h2>🎯 Prioritized Subdomain Targets</h2>
            {prioritized_subdomains_html}
        </div>

        <div class="section">
            <h2>📌 Coverage Gaps</h2>
            {coverage_section_html}
        </div>
    </div>
</body>
</html>
"""


class HTMLReportGenerator:
    """Generates interactive HTML security reports."""
    
    @staticmethod
    def generate(
        target: str,
        correlation_id: str,
        scan_date: str,
        correlated_findings: List[CorrelatedFinding],
        intelligence_report: Dict[str, Any],
        output_path: Path,
        vulnerability_report: Optional[Dict[str, Any]] = None,
        risk_report: Optional[Dict[str, Any]] = None,
        coverage_report: Optional[Dict[str, Any]] = None,
        discovery_summary: Optional[Dict[str, Any]] = None,
        findings_summary: Optional[Dict[str, Any]] = None,
        security_strengths: Optional[List[str]] = None,
        confirmed_exploitation: Optional[Dict[str, Any]] = None,
        service_fingerprints: Optional[List[Dict[str, Any]]] = None,
        certificate_assessments: Optional[List[Dict[str, Any]]] = None,
        host_network_assessment: Optional[List[Dict[str, Any]]] = None,
        prioritized_subdomains: Optional[List[Dict[str, Any]]] = None,
        auth_access_control_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Generate HTML report from intelligence data."""
        
        # Extract stats (robust to missing keys)
        total_findings = intelligence_report.get('total_findings', len(correlated_findings))
        if findings_summary:
            total_findings = int(findings_summary.get("total", total_findings) or 0)
        severity_counts = {}
        for cf in correlated_findings:
            # Support both object-based and dict-based findings
            if isinstance(cf, dict):
                sev_raw = cf.get('severity', 'INFO')
                sev = sev_raw.value if hasattr(sev_raw, 'value') else str(sev_raw)
            else:
                sev = cf.primary_finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        medium_count = severity_counts.get('MEDIUM', 0)
        avg_conf_raw = float(intelligence_report.get('confidence_stats', {}).get('average', 0.0))
        if avg_conf_raw <= 0 and vulnerability_report:
            avg_conf_raw = float(vulnerability_report.get("summary", {}).get("average_confidence", 0.0))
        avg_confidence = int(avg_conf_raw * 100) if 0 < avg_conf_raw <= 1 else int(avg_conf_raw)
        multi_tool_count = int(intelligence_report.get('multi_tool_confirmed', 0))
        if multi_tool_count == 0 and vulnerability_report:
            multi_tool_count = int(vulnerability_report.get("summary", {}).get("corroborated", 0))
        
        # Top 10 findings
        top_findings_html = HTMLReportGenerator._render_top_findings(
            intelligence_report.get('top_10_critical', [])
        )
        
        # Severity chart
        severity_chart_html = HTMLReportGenerator._render_severity_chart(severity_counts)
        
        # Compliance mapping
        compliance_html = HTMLReportGenerator._render_compliance(correlated_findings)
        
        # Remediation queue
        remediation_queue_html = HTMLReportGenerator._render_remediation_queue(
            correlated_findings[:10]
        )

        discovery_section_html = HTMLReportGenerator._render_discovery_summary(discovery_summary)
        findings_summary_section_html = HTMLReportGenerator._render_findings_summary(findings_summary)

        vuln_section_html = HTMLReportGenerator._render_vulnerabilities(vulnerability_report)
        risk_section_html = HTMLReportGenerator._render_risk(risk_report)
        coverage_section_html = HTMLReportGenerator._render_coverage(coverage_report)
        target_intel_html = HTMLReportGenerator._render_target_intel(target, discovery_summary)
        strengths_section_html = HTMLReportGenerator._render_strengths(security_strengths or [])
        auth_access_control_html = HTMLReportGenerator._render_auth_access_control(auth_access_control_summary)
        
        # PHASE 5: Confirmed exploitation findings (new)
        confirmed_exploitation_html = HTMLReportGenerator._render_confirmed_exploitation(confirmed_exploitation)
        service_fingerprints_html = HTMLReportGenerator._render_service_fingerprints(service_fingerprints or [])
        certificate_assessments_html = HTMLReportGenerator._render_certificate_assessments(certificate_assessments or [])
        host_network_assessment_html = HTMLReportGenerator._render_host_network_assessment(host_network_assessment or [])
        prioritized_subdomains_html = HTMLReportGenerator._render_prioritized_subdomains(prioritized_subdomains or [])
        
        # Fill template
        html = HTML_TEMPLATE.format(
            target=target,
            scan_date=scan_date,
            correlation_id=correlation_id,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            avg_confidence=avg_confidence,
            multi_tool_count=multi_tool_count,
            target_intel_html=target_intel_html,
            discovery_section_html=discovery_section_html,
            auth_access_control_html=auth_access_control_html,
            findings_summary_section_html=findings_summary_section_html,
            strengths_section_html=strengths_section_html,
            top_findings_html=top_findings_html,
            severity_chart_html=severity_chart_html,
            compliance_html=compliance_html,
            remediation_queue_html=remediation_queue_html,
            vuln_section_html=vuln_section_html,
            risk_section_html=risk_section_html,
            coverage_section_html=coverage_section_html,
            confirmed_exploitation_html=confirmed_exploitation_html,
            service_fingerprints_html=service_fingerprints_html,
            certificate_assessments_html=certificate_assessments_html,
            host_network_assessment_html=host_network_assessment_html,
            prioritized_subdomains_html=prioritized_subdomains_html
        )
        
        # Write to file
        output_path.write_text(html, encoding='utf-8')
    
    @staticmethod
    def _render_top_findings(top_findings: List[Dict]) -> str:
        """Render top 10 findings as HTML cards."""
        if not top_findings:
            return "<p>No critical findings detected.</p>"
        
        html = []
        for idx, finding in enumerate(top_findings, 1):
            severity_class = finding['severity'].lower()
            confidence_pct = int(finding['confidence'] * 100)
            
            html.append(f"""
            <div class="finding-card {severity_class}">
                <div class="finding-header">
                    <div class="finding-title">#{idx}. {finding['type']}</div>
                    <div>
                        <span class="badge badge-{severity_class}">{finding['severity']}</span>
                        <span class="badge badge-exploit">{finding['exploitability']}</span>
                    </div>
                </div>
                <div class="finding-meta">
                    <strong>Location:</strong> {finding['location']}<br>
                    <strong>Confidence:</strong> {confidence_pct}%
                    <div class="confidence-meter">
                        <div class="confidence-fill" style="width: {confidence_pct}%"></div>
                    </div>
                </div>
                <div class="finding-description">{finding['description']}</div>
            </div>
            """)
        
        return '\n'.join(html)
    
    @staticmethod
    def _render_severity_chart(severity_counts: Dict[str, int]) -> str:
        """Render severity distribution bar chart."""
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        max_count = max(severity_counts.values()) if severity_counts else 1
        
        html = []
        for sev in severities:
            count = severity_counts.get(sev, 0)
            height_pct = (count / max_count * 100) if max_count > 0 else 0
            html.append(f"""
            <div style="flex: 1;">
                <div class="bar" style="height: {height_pct}%">
                    <div class="bar-value">{count}</div>
                </div>
                <div class="bar-label">{sev}</div>
            </div>
            """)
        
        return '\n'.join(html)
    
    @staticmethod
    def _render_compliance(correlated_findings: List[CorrelatedFinding]) -> str:
        """Render compliance mapping for OWASP, PCI-DSS, CWE Top 25."""
        # OWASP Top 10 2021
        owasp_counts = {}
        cwe_counts = {}
        
        for cf in correlated_findings:
            if isinstance(cf, dict):
                owasp = cf.get('owasp') or "Unmapped"
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
                cwe_val = cf.get('cwe')
                if cwe_val:
                    cwe_counts[cwe_val] = cwe_counts.get(cwe_val, 0) + 1
            else:
                owasp = cf.primary_finding.owasp or "Unmapped"
                owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
                if cf.primary_finding.cwe:
                    cwe = cf.primary_finding.cwe
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # OWASP card
        owasp_items = '\n'.join([
            f'<div class="compliance-item"><span>{owasp}</span><span><strong>{count}</strong></span></div>'
            for owasp, count in sorted(owasp_counts.items(), key=lambda x: -x[1])[:5]
        ])
        
        # CWE card
        cwe_items = '\n'.join([
            f'<div class="compliance-item"><span>{cwe}</span><span><strong>{count}</strong></span></div>'
            for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1])[:5]
        ])
        
        # PCI-DSS mapping (simplified)
        def _type_str(cf) -> str:
            if isinstance(cf, dict):
                return str(cf.get('type', '')).lower()
            return cf.primary_finding.type.value.lower()
        pci_items = """
        <div class=\"compliance-item\"><span>Req 6.5.1 (Injection)</span><span><strong>{sqli_count}</strong></span></div>
        <div class=\"compliance-item\"><span>Req 6.5.7 (XSS)</span><span><strong>{xss_count}</strong></span></div>
        <div class=\"compliance-item\"><span>Req 6.5.9 (Access Control)</span><span><strong>{ac_count}</strong></span></div>
        <div class=\"compliance-item\"><span>Req 6.5.10 (Auth)</span><span><strong>{auth_count}</strong></span></div>
        """.format(
            sqli_count=sum(1 for cf in correlated_findings if 'sqli' in _type_str(cf)),
            xss_count=sum(1 for cf in correlated_findings if 'xss' in _type_str(cf)),
            ac_count=sum(1 for cf in correlated_findings if 'idor' in _type_str(cf)),
            auth_count=sum(1 for cf in correlated_findings if 'auth' in _type_str(cf))
        )
        
        return f"""
        <div class="compliance-card">
            <h3>OWASP Top 10 2021</h3>
            {owasp_items}
        </div>
        <div class="compliance-card">
            <h3>CWE Top 25</h3>
            {cwe_items or '<div class="compliance-item"><span>No CWE mappings</span></div>'}
        </div>
        <div class="compliance-card">
            <h3>PCI-DSS 3.2.1</h3>
            {pci_items}
        </div>
        """
    
    @staticmethod
    def _render_remediation_queue(priority_findings: List[CorrelatedFinding]) -> str:
        """Render remediation priority queue."""
        if not priority_findings:
            return "<p>No findings require immediate remediation.</p>"
        
        html = []
        for idx, cf in enumerate(priority_findings, 1):
            if isinstance(cf, dict):
                severity_raw = cf.get('severity', 'MEDIUM')
                severity_class = (severity_raw.value if hasattr(severity_raw, 'value') else str(severity_raw)).lower()
                f_type = str(cf.get('title') or cf.get('type', 'UNKNOWN'))
                location = cf.get('location', '')
                description = cf.get('description', '')
                conf_val = cf.get('confidence', 0)
                conf_pct = int(float(conf_val) * 100) if float(conf_val) <= 1 else int(float(conf_val))
                remediation = cf.get('remediation') or HTMLReportGenerator._get_remediation(str(cf.get('type', 'UNKNOWN')))
                root_cause = HTMLReportGenerator._get_root_cause(f_type)
                evidence = cf.get("evidence", "")
                impact = cf.get("impact") or "Not provided"
                exploitability = cf.get("exploitability") or "Not provided"
                verification_steps = cf.get("verification_steps") or "Retest manually with the same payload and endpoint."
                evidence_file = cf.get("evidence_file", "")
                evidence_line = cf.get("evidence_line", 0)
                evidence_ref = f"{evidence_file}:{evidence_line}" if evidence_file and evidence_line else (evidence_file or "n/a")
                html.append(f"""
                <div class=\"finding-card {severity_class}\">
                    <div class=\"finding-header\">
                        <div class=\"finding-title\">Priority #{idx}: {f_type}</div>
                        <div>
                            <span class=\"badge badge-{severity_class}\">{severity_raw}</span>
                            <span class=\"badge badge-exploit\">Exploit: n/a</span>
                        </div>
                    </div>
                    <div class=\"finding-meta\">
                        <strong>Location:</strong> {location}<br>
                        <strong>Confidence:</strong> {conf_pct}%
                    </div>
                    <div class=\"finding-description\">
                        <strong>Issue:</strong> {description}<br>
                        <strong>Why Present:</strong> {root_cause}<br>
                        <strong>How Identified:</strong> {HTMLReportGenerator._safe_text(evidence) or 'Tool output matched vulnerability signatures.'}<br>
                        <strong>Evidence Ref:</strong> {evidence_ref}<br>
                        <strong>Impact:</strong> {impact}<br>
                        <strong>Exploitability:</strong> {exploitability}<br>
                        <strong>Remediation:</strong> {remediation}<br>
                        <strong>Verification Steps:</strong> {verification_steps}
                    </div>
                </div>
                """)
            else:
                finding = cf.primary_finding
                severity_class = finding.severity.value.lower()
                remediation = HTMLReportGenerator._get_remediation(finding.type.value)
                root_cause = HTMLReportGenerator._get_root_cause(finding.type.value)
                html.append(f"""
                <div class=\"finding-card {severity_class}\">
                    <div class=\"finding-header\">
                        <div class=\"finding-title\">Priority #{idx}: {finding.type.value}</div>
                        <div>
                            <span class=\"badge badge-{severity_class}\">{finding.severity.value}</span>
                            <span class=\"badge badge-exploit\">Exploit: {cf.exploitability}</span>
                        </div>
                    </div>
                    <div class=\"finding-meta\">
                        <strong>Location:</strong> {finding.location}<br>
                        <strong>Attack Surface:</strong> {cf.attack_surface_score:.1f}/10<br>
                        <strong>Confidence:</strong> {int(cf.confidence.score * 100)}%
                    </div>
                    <div class=\"finding-description\">
                        <strong>Issue:</strong> {finding.description}<br>
                        <strong>Why Present:</strong> {root_cause}<br>
                        <strong>How Identified:</strong> {HTMLReportGenerator._safe_text(finding.evidence) or 'Tool output matched vulnerability signatures.'}<br>
                        <strong>Remediation:</strong> {remediation}
                    </div>
                </div>
                """)
        
        return '\n'.join(html)

    @staticmethod
    def _safe_text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        return text[:400]

    @staticmethod
    def _get_root_cause(finding_type: str) -> str:
        root_cause_map = {
            'SQLi': 'Unsanitized user input is reaching SQL query construction without strict parameterization.',
            'XSS': 'Untrusted input is reflected or stored without context-aware output encoding.',
            'Command Injection': 'User-controlled input is likely passed into shell or command execution contexts.',
            'SSRF': 'Server-side requests accept attacker-influenced URLs or destinations without allow-list validation.',
            'Authentication Bypass': 'Authentication/authorization checks can be skipped or are inconsistently applied.',
            'IDOR': 'Object references are exposed without ownership/authorization validation.',
            'Information Disclosure': 'Service banners, metadata, or debug/config responses expose internal details.',
            'Misconfiguration': 'Security hardening controls are absent or weakly configured.',
            'Weak Cryptography': 'Legacy protocols/ciphers or weak key exchange options remain enabled.',
            'Outdated Software': 'Software versions with known vulnerabilities remain in deployment.',
        }
        return root_cause_map.get(finding_type, 'Security controls are incomplete for this finding category.')

    @staticmethod
    def _render_target_intel(target: str, discovery_summary: Optional[Dict[str, Any]]) -> str:
        discovery_summary = discovery_summary or {}
        target_ips = discovery_summary.get('target_ips', []) or []
        tech_stack = discovery_summary.get('tech_stack', {}) or {}
        os_guess = discovery_summary.get('detected_os') or 'unknown'

        server = tech_stack.get('server', []) or []
        cms = tech_stack.get('cms', []) or []
        languages = tech_stack.get('languages', []) or []
        frameworks = tech_stack.get('frameworks', []) or []
        javascript = tech_stack.get('javascript', []) or []

        return f"""
        <div class=\"stats-grid\">
            <div class=\"stat-card\"><div class=\"label\">Target</div><div class=\"value mono\">{target}</div></div>
            <div class=\"stat-card\"><div class=\"label\">Target IP(s)</div><div class=\"value mono\">{', '.join(target_ips) if target_ips else 'not resolved'}</div></div>
            <div class=\"stat-card\"><div class=\"label\">Detected OS</div><div class=\"value\">{os_guess}</div></div>
        </div>
        <div class=\"detail-block\">
            <h3>Tech Stack (from WhatWeb + parsed discoveries)</h3>
            <div class=\"tools-list\">{''.join([f'<span class="tool-tag">Server: {x}</span>' for x in server]) or '<span class="tool-tag">Server: unknown</span>'}</div>
            <div class=\"tools-list\">{''.join([f'<span class="tool-tag">CMS: {x}</span>' for x in cms]) or '<span class="tool-tag">CMS: none detected</span>'}</div>
            <div class=\"tools-list\">{''.join([f'<span class="tool-tag">Lang: {x}</span>' for x in languages]) or '<span class="tool-tag">Lang: unknown</span>'}</div>
            <div class=\"tools-list\">{''.join([f'<span class="tool-tag">Framework: {x}</span>' for x in frameworks]) or '<span class="tool-tag">Framework: none detected</span>'}</div>
            <div class=\"tools-list\">{''.join([f'<span class="tool-tag">JS: {x}</span>' for x in javascript]) or '<span class="tool-tag">JS: none detected</span>'}</div>
        </div>
        """
    
    @staticmethod
    def _get_remediation(finding_type: str) -> str:
        """Get remediation guidance for finding type."""
        remediation_map = {
            'SQLi': 'Use parameterized queries or ORM. Validate and sanitize all user inputs.',
            'XSS': 'Encode output, implement Content-Security-Policy headers, sanitize inputs.',
            'Command Injection': 'Avoid shell execution, use libraries with built-in escaping, whitelist inputs.',
            'SSRF': 'Validate and whitelist URLs, disable unnecessary protocols, use network segmentation.',
            'Authentication Bypass': 'Implement proper authentication, use framework-provided auth mechanisms.',
            'IDOR': 'Implement proper authorization checks, use indirect references.',
            'Information Disclosure': 'Remove sensitive data, disable debug mode, configure proper error handling.',
            'Misconfiguration': 'Review and harden server configuration, follow security best practices.',
            'Weak Cryptography': 'Upgrade to TLS 1.2+, disable weak ciphers, renew certificates.',
            'Outdated Software': 'Update to latest stable version, apply security patches.',
        }
        return remediation_map.get(finding_type, 'Review security best practices for this vulnerability type.')

    @staticmethod
    def _render_vulnerabilities(vuln_report: Optional[Dict[str, Any]]) -> str:
        if not vuln_report:
            return "<p>No vulnerability-centric data available.</p>"

        by_sev = vuln_report.get("by_severity", {})
        vulns = vuln_report.get("vulnerabilities", [])[:10]

        sev_cards = []
        for sev, items in by_sev.items():
            sev_cards.append(
                f"<div class=\"stat-card\"><div class=\"label\">{sev}</div><div class=\"value\">{len(items)}</div></div>"
            )

        vuln_cards = []
        for v in vulns:
            ev = (v.get('evidence') or [])
            first_ev = ev[0] if ev else {}
            ev_ref = "n/a"
            if first_ev.get("evidence_file") and first_ev.get("evidence_line"):
                ev_ref = f"{first_ev.get('evidence_file')}:{first_ev.get('evidence_line')}"
            vuln_cards.append(f"""
            <div class="finding-card {v.get('severity','').lower()}">
                <div class="finding-header">
                    <div class="finding-title">{v.get('type','UNKNOWN')} @ {v.get('endpoint','')}</div>
                    <span class="badge badge-{v.get('severity','medium').lower()}">{v.get('severity','MEDIUM')}</span>
                </div>
                <div class="finding-meta">Param: {v.get('parameter','-')} • Confidence: {v.get('confidence',0)} ({v.get('confidence_tier','LOW')}) • Verification: {v.get('verification','UNVERIFIED')} • OWASP: {v.get('owasp','n/a')}</div>
                <div class="finding-description"><strong>Evidence Ref:</strong> {ev_ref}<br><strong>Verification Reason:</strong> {v.get('verification_reason', 'n/a')}</div>
            </div>
            """)

        return f"""
        <div class="stats-grid">{''.join(sev_cards)}</div>
        {''.join(vuln_cards) or '<p>No vulnerabilities reported.</p>'}
        """

    @staticmethod
    def _render_strengths(strengths: List[str]) -> str:
        if not strengths:
            return "<p>No explicit strengths recorded.</p>"
        rows = ''.join([f"<div class='compliance-item'><span>{HTMLReportGenerator._safe_text(s)}</span><span><strong>Verified</strong></span></div>" for s in strengths[:12]])
        return f"<div class='compliance-card'><h3>Security Strengths</h3>{rows}</div>"

    @staticmethod
    def _render_risk(risk_report: Optional[Dict[str, Any]]) -> str:
        if not risk_report:
            return "<p>No risk aggregation available.</p>"

        app = risk_report.get("application_risk", {})
        per_owasp = risk_report.get("per_owasp_category", {})

        owasp_rows = []
        for owasp, data in per_owasp.items():
            total = int(data.get('critical', 0)) + int(data.get('high', 0)) + int(data.get('medium', 0)) + int(data.get('low', 0))
            owasp_rows.append(
                f"<div class='compliance-item'><span>{owasp}</span><span><strong>{data.get('critical',0)}/{data.get('high',0)}/{data.get('medium',0)}/{data.get('low',0)} (total {total})</strong></span></div>"
            )

        return f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Risk Rating</div><div class="value">{app.get('risk_rating','UNKNOWN')}</div></div>
            <div class="stat-card"><div class="label">Business Score</div><div class="value">{app.get('business_risk_score',0)}</div></div>
            <div class="stat-card"><div class="label">Total Findings</div><div class="value">{app.get('total_findings',0)}</div></div>
        </div>
        <div class="compliance-card">
            <h3>OWASP Concentration</h3>
            <p style="color:#666; margin-bottom:10px;">Format is Critical/High/Medium/Low. If an OWASP row looks like 0/0/0/0 with findings elsewhere, those findings are often INFO-level and not counted in risk scoring.</p>
            {''.join(owasp_rows) or '<p>No OWASP aggregation.</p>'}
        </div>
        """

    @staticmethod
    def _render_coverage(coverage_report: Optional[Dict[str, Any]]) -> str:
        if not coverage_report:
            return "<p>No coverage report available.</p>"

        missed = coverage_report.get("missing", {})
        summary_items = []
        for area, details in missed.items():
            summary_items.append(
                f"<div class='compliance-item'><span>{area}</span><span><strong>{len(details)}</strong></span></div>"
            )

        blocked = coverage_report.get("blocked", {})
        blocked_tools = blocked.get("tools", [])
        blocked_reasons = blocked.get("reasons", {})
        skipped_tools = coverage_report.get("skipped", {}).get("tools", [])
        denied_tools = coverage_report.get("denied", {}).get("tools", [])
        missing_tools = (coverage_report.get("missing", {}) or {}).get("missing_tools", [])
        manual = coverage_report.get("manual_out_of_scope", {}) or {}
        blocked_rows = []
        for tool in blocked_tools:
            blocked_rows.append(
                f"<div class='compliance-item'><span>{tool}</span><span><strong>{blocked_reasons.get(tool, 'unknown')}</strong></span></div>"
            )

        skipped_rows = ''.join([f"<span class='tool-tag mono'>{t}</span>" for t in skipped_tools]) or "<span class='tool-tag'>None</span>"
        denied_rows = ''.join([f"<span class='tool-tag mono'>{t}</span>" for t in denied_tools]) or "<span class='tool-tag'>None</span>"
        missing_rows = ''.join([f"<span class='tool-tag mono'>{t}</span>" for t in missing_tools]) or "<span class='tool-tag'>None</span>"

        manual_summary = f"""
        <div class='compliance-item'><span>Prompt Response</span><span><strong>{manual.get('prompt_response', 'skip')}</strong></span></div>
        <div class='compliance-item'><span>Attempted</span><span><strong>{manual.get('attempted', False)}</strong></span></div>
        <div class='compliance-item'><span>Executed</span><span><strong>{len(manual.get('executed', []))}</strong></span></div>
        <div class='compliance-item'><span>Failed (Actionable)</span><span><strong>{len(manual.get('failed', []))}</strong></span></div>
        <div class='compliance-item'><span>Failed (Non-Actionable)</span><span><strong>{len(manual.get('non_actionable_failures', []))}</strong></span></div>
        <div class='compliance-item'><span>Unavailable</span><span><strong>{len(manual.get('missing_or_unavailable', []))}</strong></span></div>
        """

        return f"""
        <div class="compliance-card">
            <h3>Coverage Gaps</h3>
            {''.join(summary_items) or '<p>No gaps logged.</p>'}
            <h3 style="margin-top:12px;">Blocked/Skipped Tools</h3>
            {''.join(blocked_rows) or '<p>No blocked tools logged.</p>'}
            <h3 style="margin-top:12px;">Skipped Tools</h3>
            <div class="tools-list">{skipped_rows}</div>
            <h3 style="margin-top:12px;">Denied (Out-of-Scope) Tools</h3>
            <div class="tools-list">{denied_rows}</div>
            <h3 style="margin-top:12px;">Missing Tools</h3>
            <div class="tools-list">{missing_rows}</div>
            <h3 style="margin-top:12px;">Manual Out-of-Scope Sweep</h3>
            {manual_summary}
        </div>
        """

    @staticmethod
    def _render_discovery_summary(discovery_summary: Optional[Dict[str, Any]]) -> str:
        if not discovery_summary:
            return "<p>No discovery summary available.</p>"

        def _render_tags(values: Any, empty_label: str) -> str:
            values = values or []
            if not values:
                return f"<span class='tool-tag'>{empty_label}</span>"
            return ''.join([f"<span class='tool-tag mono'>{v}</span>" for v in values[:100]])

        return f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Endpoints</div><div class="value">{discovery_summary.get('endpoints', 0)}</div></div>
            <div class="stat-card"><div class="label">Live Endpoints</div><div class="value">{discovery_summary.get('live_endpoints', 0)}</div></div>
            <div class="stat-card"><div class="label">Parameters</div><div class="value">{discovery_summary.get('params', 0)}</div></div>
            <div class="stat-card"><div class="label">Command Params</div><div class="value">{discovery_summary.get('command_params', 0)}</div></div>
            <div class="stat-card"><div class="label">SSRF Params</div><div class="value">{discovery_summary.get('ssrf_params', 0)}</div></div>
            <div class="stat-card"><div class="label">Reflections</div><div class="value">{discovery_summary.get('reflections', 0)}</div></div>
            <div class="stat-card"><div class="label">Subdomains</div><div class="value">{discovery_summary.get('subdomains', 0)}</div></div>
            <div class="stat-card"><div class="label">Open Ports</div><div class="value">{discovery_summary.get('ports', 0)}</div></div>
            <div class="stat-card"><div class="label">JS Endpoints</div><div class="value">{discovery_summary.get('js_endpoints', 0)}</div></div>
            <div class="stat-card"><div class="label">JS API Endpoints</div><div class="value">{discovery_summary.get('js_api_endpoints', 0)}</div></div>
            <div class="stat-card"><div class="label">Auth Roles</div><div class="value">{discovery_summary.get('auth_roles', 0)}</div></div>
        </div>
        <div class="detail-block">
            <h3>API Endpoints Found</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('api_endpoints_list', []), 'No API endpoints found')}</div>
            <h3 style="margin-top:12px;">All Endpoints / Directories / Pages</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('endpoints_list', []), 'No endpoints found')}</div>
            <h3 style="margin-top:12px;">Parameters</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('parameters_list', []), 'No parameters found')}</div>
            <h3 style="margin-top:12px;">Reflections</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('reflections_list', []), 'No reflections found')}</div>
            <h3 style="margin-top:12px;">Subdomains</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('subdomains_list', []), 'No subdomains found')}</div>
            <h3 style="margin-top:12px;">Open Ports</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('ports_list', []), 'No open ports found')}</div>
            <h3 style="margin-top:12px;">Command Params</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('command_params_list', []), 'No command params found')}</div>
            <h3 style="margin-top:12px;">SSRF Params</h3>
            <div class="tools-list">{_render_tags(discovery_summary.get('ssrf_params_list', []), 'No ssrf params found')}</div>
        </div>
        """

    @staticmethod
    def _render_findings_summary(findings_summary: Optional[Dict[str, Any]]) -> str:
        if not findings_summary:
            return "<p>No findings summary available.</p>"

        owasp = findings_summary.get("owasp", {}) or {}
        confirmed_by_type = findings_summary.get("confirmed_by_type", {}) or {}
        owasp_rows = []
        for category, count in sorted(owasp.items(), key=lambda item: (-item[1], item[0]))[:10]:
            owasp_rows.append(
                f"<div class='compliance-item'><span>{category}</span><span><strong>{count}</strong></span></div>"
            )

        return f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Critical</div><div class="value severity-critical">{findings_summary.get('critical', 0)}</div></div>
            <div class="stat-card"><div class="label">High</div><div class="value severity-high">{findings_summary.get('high', 0)}</div></div>
            <div class="stat-card"><div class="label">Medium</div><div class="value severity-medium">{findings_summary.get('medium', 0)}</div></div>
            <div class="stat-card"><div class="label">Low</div><div class="value severity-low">{findings_summary.get('low', 0)}</div></div>
            <div class="stat-card"><div class="label">Info</div><div class="value">{findings_summary.get('info', 0)}</div></div>
            <div class="stat-card"><div class="label">Total</div><div class="value">{findings_summary.get('total', 0)}</div></div>
            <div class="stat-card"><div class="label">Confirmed SQLi/SSRF/XSS</div><div class="value">{confirmed_by_type.get('SQLi', 0)}/{confirmed_by_type.get('SSRF', 0)}/{confirmed_by_type.get('XSS', 0)}</div></div>
        </div>
        <div class="compliance-card">
            <h3>OWASP Mapping Distribution</h3>
            {''.join(owasp_rows) or '<p>No OWASP-mapped findings.</p>'}
        </div>
        """

    @staticmethod
    def _render_auth_access_control(summary: Optional[Dict[str, Any]]) -> str:
        if not summary:
            return "<p>No auth/access-control assessment data available.</p>"

        enabled_roles = summary.get("enabled_roles", []) or []
        authenticated_roles = summary.get("authenticated_roles", []) or []
        errors = summary.get("errors", []) or []

        role_tags = ''.join([f"<span class='tool-tag mono'>{r}</span>" for r in authenticated_roles])
        if not role_tags:
            role_tags = "<span class='tool-tag'>No authenticated roles</span>"

        error_rows = ''.join([
            f"<div class='compliance-item'><span>{HTMLReportGenerator._safe_text(err)}</span></div>"
            for err in errors[:10]
        ])

        return f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Executed</div><div class="value">{'Yes' if summary.get('executed') else 'No'}</div></div>
            <div class="stat-card"><div class="label">Configured Roles</div><div class="value">{len(enabled_roles)}</div></div>
            <div class="stat-card"><div class="label">Authenticated Roles</div><div class="value">{len(authenticated_roles)}</div></div>
            <div class="stat-card"><div class="label">Endpoints Tested</div><div class="value">{summary.get('endpoints_tested', 0)}</div></div>
            <div class="stat-card"><div class="label">IDOR Findings</div><div class="value">{summary.get('idor_findings', 0)}</div></div>
            <div class="stat-card"><div class="label">Access-Control Findings</div><div class="value">{summary.get('access_control_findings', 0)}</div></div>
        </div>
        <div class="detail-block">
            <h3>Authenticated Roles</h3>
            <div class="tools-list">{role_tags}</div>
            <h3 style="margin-top:12px;">Errors</h3>
            {error_rows or '<p>No errors recorded.</p>'}
        </div>
        """
    
    @staticmethod
    def _render_confirmed_exploitation(confirmed_exploitation: Optional[Dict[str, Any]]) -> str:
        """Render Phase 5 confirmed active exploitation findings."""
        if not confirmed_exploitation:
            return "<p>No confirmed exploitations detected.</p>"
        
        summary = confirmed_exploitation.get("summary", {})
        total = summary.get("total_confirmed", 0)
        tested = summary.get("tested_vectors", 0)
        discarded = summary.get("discarded_vectors", 0)
        rejected_low_conf = summary.get("rejected_low_confidence", 0)
        discarded_patterns = summary.get("discarded_false_positive_patterns", 0)
        severity_breakdown = summary.get("by_severity", {})
        by_type = summary.get("by_type", {})
        
        # Build summary cards
        summary_html = f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Tested Vectors</div><div class="value">{tested}</div></div>
            <div class="stat-card"><div class="label">Confirmed</div><div class="value">{total}</div></div>
            <div class="stat-card"><div class="label">Discarded</div><div class="value">{discarded}</div></div>
            <div class="stat-card"><div class="label">Discarded (Low Confidence)</div><div class="value">{rejected_low_conf}</div></div>
            <div class="stat-card"><div class="label">Discarded (Pattern Kill Switch)</div><div class="value">{discarded_patterns}</div></div>
            <div class="stat-card"><div class="label">Confirmed SQLi/SSRF/XSS</div><div class="value">{by_type.get('SQLi', 0)}/{by_type.get('SSRF', 0)}/{by_type.get('XSS', 0)}</div></div>
        </div>
        """
        
        # Build findings cards
        findings_html = ""
        findings_list = confirmed_exploitation.get("findings", [])
        for finding in findings_list[:15]:  # Show top 15
            ftype = finding.get("type", "Unknown")
            severity = finding.get("severity", "MEDIUM").lower()
            endpoint = finding.get("endpoint", "?")
            param = finding.get("parameter", "?")
            proof = finding.get("proof", {}) if isinstance(finding.get("proof"), dict) else {}
            confidence = int(float(proof.get("confidence", finding.get("confidence", 0)) or 0.0) * 100)
            proof_type = proof.get("method", finding.get("proof_type", "response_diff"))
            
            findings_html += f"""
            <div class="finding-card {severity}">
                <div class="finding-header">
                    <div class="finding-title">{ftype}</div>
                    <div>
                        <span class="badge badge-{severity}">{severity.upper()}</span>
                        <span class="badge badge-info">{proof_type}</span>
                    </div>
                </div>
                <div class="finding-meta">
                    <strong>Location:</strong> {endpoint} [{param}]<br>
                    <strong>Confidence:</strong> {confidence}%
                </div>
            </div>
            """
        
        return summary_html + findings_html if findings_html else summary_html + "<p>No detailed exploitation findings available.</p>"
    
    @staticmethod
    def _render_service_fingerprints(fingerprints: List[Dict[str, Any]]) -> str:
        """Render service fingerprinting results."""
        if not fingerprints:
            return "<p>No service fingerprints detected.</p>"
        
        rows = []
        for fp in fingerprints:
            host = fp.get("host", "?")
            port = fp.get("port", "?")
            protocol = fp.get("protocol", "unknown")
            service = fp.get("service", "unknown")
            version = fp.get("version", "unknown")
            tech_stack = fp.get("technology_stack", []) or []
            confidence = int(fp.get("confidence", 0) * 100)
            
            tech_html = "".join(f'<span class="tool-tag">{t}</span>' for t in tech_stack[:3])
            
            rows.append(f"""
            <tr>
                <td><strong>{host}:{port}</strong></td>
                <td>{protocol}/{service}</td>
                <td>{version}</td>
                <td>{tech_html}</td>
                <td><strong>{confidence}%</strong></td>
            </tr>
            """)
        
        return f"""
        <div class="chart-container">
            <table style="width: 100%; border-collapse: collapse;">
                <thead style="background: #f8f9fa;">
                    <tr>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Host:Port</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Protocol</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Version</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Tech Stack</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """

    @staticmethod
    def _render_certificate_assessments(cert_checks: List[Dict[str, Any]]) -> str:
        """Render TLS certificate chain validity and expiry data."""
        if not cert_checks:
            return "<p>No certificate checks available.</p>"

        rows = []
        for cert in cert_checks:
            host = cert.get("host", "?")
            port = cert.get("port", "?")
            status = cert.get("status", "UNKNOWN")
            chain_valid = cert.get("chain_valid", False)
            chain_complete = cert.get("chain_complete", False)
            expires_at = cert.get("expires_at", "n/a")
            days_left = cert.get("days_until_expiry", "n/a")
            issuer = cert.get("issuer", "n/a")

            rows.append(f"""
            <tr>
                <td><strong>{host}:{port}</strong></td>
                <td>{status}</td>
                <td>{'Yes' if chain_valid else 'No'}</td>
                <td>{'Yes' if chain_complete else 'No'}</td>
                <td>{days_left}</td>
                <td>{expires_at}</td>
                <td>{issuer}</td>
            </tr>
            """)

        return f"""
        <div class="chart-container">
            <table style="width: 100%; border-collapse: collapse;">
                <thead style="background: #f8f9fa;">
                    <tr>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Host:Port</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Status</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Chain Valid</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Chain Complete</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Days Left</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Expires At</th>
                        <th style="padding: 10px; text-align: left; border-bottom: 2px solid #ddd;">Issuer</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """

    @staticmethod
    def _render_host_network_assessment(host_rows: List[Dict[str, Any]]) -> str:
        """Render per-host open ports + assessment summary."""
        if not host_rows:
            return "<p>No host network assessment data available.</p>"

        cards = []
        for row in host_rows:
            host = row.get("host", "?")
            ports = row.get("open_ports", []) or []
            port_tags = ''.join([f"<span class='tool-tag mono'>{p}</span>" for p in ports]) or "<span class='tool-tag'>No open common ports</span>"
            fp_count = len(row.get("fingerprints", []) or [])
            cert_count = len(row.get("certificate_checks", []) or [])

            cards.append(f"""
            <div class="compliance-card" style="margin-bottom:12px;">
                <h3>{host}</h3>
                <div class="compliance-item"><span>Service Fingerprints</span><span><strong>{fp_count}</strong></span></div>
                <div class="compliance-item"><span>Certificate Checks</span><span><strong>{cert_count}</strong></span></div>
                <div style="margin-top:8px;"><strong>Open Ports:</strong></div>
                <div class="tools-list" style="margin-top:6px;">{port_tags}</div>
            </div>
            """)

        return ''.join(cards)
    
    @staticmethod
    def _render_prioritized_subdomains(subdomains: List[Dict[str, Any]]) -> str:
        """Render subdomain prioritization results."""
        if not subdomains:
            return "<p>No prioritized subdomains detected.</p>"
        
        rows = []
        for idx, subdomain in enumerate(subdomains[:15], 1):  # Show top 15
            name = subdomain.get("subdomain", "?")
            score = float(subdomain.get("score", 0))
            param_count = subdomain.get("parameter_count", 0)
            
            rows.append(f"""
            <div class="finding-card low" style="margin-bottom: 10px;">
                <div class="finding-header">
                    <div class="finding-title">#{idx}. {name}</div>
                    <div><span class="badge badge-info">Score: {score:.1f}</span></div>
                </div>
                <div class="finding-meta">
                    <strong>Attack Surface:</strong> {param_count} parameters<br>
                    <strong>Prioritization Score:</strong> {score:.1f}/100.0 (40% exposure + 25% params + 20% tech + 15% ports)
                </div>
            </div>
            """)
        
        return "".join(rows) if rows else "<p>No subdomain prioritization data available.</p>"
