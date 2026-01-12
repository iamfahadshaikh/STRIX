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
    ) -> None:
        """Generate HTML report from intelligence data."""
        
        # Extract stats
        total_findings = intelligence_report['total_findings']
        severity_counts = {}
        for cf in correlated_findings:
            sev = cf.primary_finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        medium_count = severity_counts.get('MEDIUM', 0)
        avg_confidence = int(intelligence_report['confidence_stats']['average'] * 100)
        multi_tool_count = intelligence_report['multi_tool_confirmed']
        
        # Top 10 findings
        top_findings_html = HTMLReportGenerator._render_top_findings(
            intelligence_report['top_10_critical']
        )
        
        # Severity chart
        severity_chart_html = HTMLReportGenerator._render_severity_chart(severity_counts)
        
        # Compliance mapping
        compliance_html = HTMLReportGenerator._render_compliance(correlated_findings)
        
        # Remediation queue
        remediation_queue_html = HTMLReportGenerator._render_remediation_queue(
            correlated_findings[:10]
        )

        vuln_section_html = HTMLReportGenerator._render_vulnerabilities(vulnerability_report)
        risk_section_html = HTMLReportGenerator._render_risk(risk_report)
        coverage_section_html = HTMLReportGenerator._render_coverage(coverage_report)
        
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
            top_findings_html=top_findings_html,
            severity_chart_html=severity_chart_html,
            compliance_html=compliance_html,
            remediation_queue_html=remediation_queue_html,
            vuln_section_html=vuln_section_html,
            risk_section_html=risk_section_html,
            coverage_section_html=coverage_section_html
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
            tools_html = ''.join([f'<span class="tool-tag">{tool}</span>' for tool in finding['tools']])
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
                    <strong>Confirmed by:</strong>
                    <div class="tools-list">{tools_html}</div>
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
        pci_items = """
        <div class="compliance-item"><span>Req 6.5.1 (Injection)</span><span><strong>{sqli_count}</strong></span></div>
        <div class="compliance-item"><span>Req 6.5.7 (XSS)</span><span><strong>{xss_count}</strong></span></div>
        <div class="compliance-item"><span>Req 6.5.9 (Access Control)</span><span><strong>{ac_count}</strong></span></div>
        <div class="compliance-item"><span>Req 6.5.10 (Auth)</span><span><strong>{auth_count}</strong></span></div>
        """.format(
            sqli_count=sum(1 for cf in correlated_findings if 'sqli' in cf.primary_finding.type.value.lower()),
            xss_count=sum(1 for cf in correlated_findings if 'xss' in cf.primary_finding.type.value.lower()),
            ac_count=sum(1 for cf in correlated_findings if 'idor' in cf.primary_finding.type.value.lower()),
            auth_count=sum(1 for cf in correlated_findings if 'auth' in cf.primary_finding.type.value.lower())
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
            finding = cf.primary_finding
            severity_class = finding.severity.value.lower()
            
            # Simple remediation suggestion based on type
            remediation = HTMLReportGenerator._get_remediation(finding.type.value)
            
            html.append(f"""
            <div class="finding-card {severity_class}">
                <div class="finding-header">
                    <div class="finding-title">Priority #{idx}: {finding.type.value}</div>
                    <div>
                        <span class="badge badge-{severity_class}">{finding.severity.value}</span>
                        <span class="badge badge-exploit">Exploit: {cf.exploitability}</span>
                    </div>
                </div>
                <div class="finding-meta">
                    <strong>Location:</strong> {finding.location}<br>
                    <strong>Attack Surface:</strong> {cf.attack_surface_score:.1f}/10<br>
                    <strong>Confidence:</strong> {int(cf.confidence.score * 100)}%
                </div>
                <div class="finding-description">
                    <strong>Issue:</strong> {finding.description}<br>
                    <strong>Remediation:</strong> {remediation}
                </div>
            </div>
            """)
        
        return '\n'.join(html)
    
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
            tools = ''.join([f"<span class='tool-tag'>{t}</span>" for t in v.get("tools", [])])
            vuln_cards.append(f"""
            <div class="finding-card {v.get('severity','').lower()}">
                <div class="finding-header">
                    <div class="finding-title">{v.get('type','UNKNOWN')} @ {v.get('endpoint','')}</div>
                    <span class="badge badge-{v.get('severity','medium').lower()}">{v.get('severity','MEDIUM')}</span>
                </div>
                <div class="finding-meta">Param: {v.get('parameter','-')} • Confidence: {v.get('confidence',0)} • OWASP: {v.get('owasp','n/a')}</div>
                <div class="tools-list">{tools}</div>
            </div>
            """)

        return f"""
        <div class="stats-grid">{''.join(sev_cards)}</div>
        {''.join(vuln_cards) or '<p>No vulnerabilities reported.</p>'}
        """

    @staticmethod
    def _render_risk(risk_report: Optional[Dict[str, Any]]) -> str:
        if not risk_report:
            return "<p>No risk aggregation available.</p>"

        app = risk_report.get("application_risk", {})
        per_owasp = risk_report.get("per_owasp_category", {})

        owasp_rows = []
        for owasp, data in per_owasp.items():
            owasp_rows.append(
                f"<div class='compliance-item'><span>{owasp}</span><span><strong>{data.get('critical',0)}/{data.get('high',0)}/{data.get('medium',0)}</strong></span></div>"
            )

        return f"""
        <div class="stats-grid">
            <div class="stat-card"><div class="label">Risk Rating</div><div class="value">{app.get('risk_rating','UNKNOWN')}</div></div>
            <div class="stat-card"><div class="label">Business Score</div><div class="value">{app.get('business_risk_score',0)}</div></div>
            <div class="stat-card"><div class="label">Total Findings</div><div class="value">{app.get('total_findings',0)}</div></div>
        </div>
        <div class="compliance-card"><h3>OWASP Concentration</h3>{''.join(owasp_rows) or '<p>No OWASP aggregation.</p>'}</div>
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

        return f"""
        <div class="compliance-card">
            <h3>Coverage Gaps</h3>
            {''.join(summary_items) or '<p>No gaps logged.</p>'}
        </div>
        """
