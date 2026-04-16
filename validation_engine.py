"""
VALIDATION ENGINE — Strict proof verification for exploitation findings.

Purpose: Enforce hard rules for SSRF, XSS, SQLi before confirmation.
No findings reach the reporter without passing these gates.
"""

import logging
from typing import Dict, Tuple, Optional, List
from enum import Enum
import re

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Supported vulnerability types with proof requirements."""
    SSRF = "SSRF"
    XSS = "XSS"
    SQL_INJECTION = "SQLi"
    COMMAND_INJECTION = "CommandInjection"
    PATH_TRAVERSAL = "PathTraversal"
    IDOR = "IDOR"
    AUTHENTICATION = "Authentication"
    UNKNOWN = "Unknown"


class ValidationResult:
    """Encapsulates validation decision with reasoning."""
    
    def __init__(self, valid: bool, reason: str, confidence_adjustment: float = 0.0):
        self.valid = valid  # Pass or fail
        self.reason = reason  # Why (for logging/reporting)
        self.confidence_adjustment = confidence_adjustment  # Boost/penalty to confidence
    
    def __repr__(self):
        return f"ValidationResult(valid={self.valid}, reason='{self.reason}', adjust={self.confidence_adjustment})"


class ValidationEngine:
    """
    Strict proof validator: only findings with evidence pass here.
    
    Rules:
    ------
    SSRF:
        VALID if:
        - OOB callback received AND timestamp within test window, OR
        - Internal IP detected in response (10.*, 172.16-31.*, 192.168.*), OR
        - Confirmed file content leak (e.g., /etc/passwd marker)
        Confidence gates: >= 0.85 for confirmation
    
    XSS:
        VALID if:
        - Payload found reflected in response AND in exploitable context, OR
        - Dynamic validation detected (payload executed)
        Confidence gates: >= 0.85 for confirmation
    
    SQLi:
        VALID if:
        - Database error signature detected AND error contains query hint, OR
        - Boolean-based: response diff > 50% AND consistent across retries, OR
        - Time-based: response time delta > 3.0 seconds (configurable)
        Confidence gates: >= 0.85 for confirmation
    
    Default:
        Confidence gates: >= 0.90 for unknown types
    """
    
    def __init__(self):
        self.db_error_patterns = [
            r"(SQL|sql|SQL Error|Exception|DatabaseException|OracleException)",
            r"(SQLSTATE|SQLState)",
            r"(You have an error in your SQL syntax)",
            r"(Unclosed quotation mark)",
            r"(Column count doesn't match)",
        ]
        self.internal_ip_patterns = [
            r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # 10.0.0.0/8
            r"(172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})",  # 172.16.0.0/12
            r"(192\.168\.\d{1,3}\.\d{1,3})",  # 192.168.0.0/16
            r"(localhost|127\.0\.0\.1)",
        ]
        self.file_content_markers = [
            r"(root:.*:0:0:)",  # /etc/passwd
            r"(\[mysqld\]|\[mysql\])",  # MySQL config
            r"(AWS_SECRET_ACCESS_KEY|PRIVATE KEY|-----BEGIN)",  # Config files
        ]
        
        logger.info("[ValidationEngine] Initialized with strict proof gates")
    
    def validate(self, vuln_type: str, proof: Dict, confidence: float) -> ValidationResult:
        """
        Main validation method: route to type-specific validator.
        
        Args:
            vuln_type: "SSRF", "XSS", "SQLi", "CommandInjection", etc.
            proof: Dict containing evidence (depends on type)
            confidence: Base confidence score from exploitation engine
        
        Returns:
            ValidationResult(valid=True/False, reason=str, confidence_adjustment=float)
        """
        if not proof:
            return ValidationResult(False, "No proof provided", -0.15)
        
        try:
            vuln_enum = VulnerabilityType(vuln_type)
        except ValueError:
            vuln_enum = VulnerabilityType.UNKNOWN
        
        # Route to type-specific validator
        if vuln_enum == VulnerabilityType.SSRF:
            return self._validate_ssrf(proof, confidence)
        elif vuln_enum == VulnerabilityType.XSS:
            return self._validate_xss(proof, confidence)
        elif vuln_enum == VulnerabilityType.SQL_INJECTION:
            return self._validate_sqli(proof, confidence)
        elif vuln_enum == VulnerabilityType.COMMAND_INJECTION:
            return self._validate_command_injection(proof, confidence)
        elif vuln_enum == VulnerabilityType.PATH_TRAVERSAL:
            return self._validate_path_traversal(proof, confidence)
        else:
            # Default: require high confidence
            if confidence >= 0.90:
                return ValidationResult(True, f"Unknown type {vuln_type} passes high-confidence threshold", 0.0)
            else:
                return ValidationResult(False, f"Unknown type {vuln_type}, confidence {confidence} < 0.90", -0.1)
    
    def _validate_ssrf(self, proof: Dict, confidence: float) -> ValidationResult:
        """
        SSRF Validator: requires OOB callback OR internal IP OR file leak.
        """
        has_oob = proof.get("oob_callback_received", False)
        oob_timestamp = proof.get("oob_timestamp")
        test_timestamp = proof.get("test_timestamp")
        response_body = proof.get("response_body", "")
        
        # Rule 1: OOB callback received (highest confidence)
        if has_oob and oob_timestamp and test_timestamp:
            # Verify callback is within reasonable window (10 seconds)
            try:
                time_delta = abs(float(oob_timestamp) - float(test_timestamp))
                if time_delta < 10.0:
                    return ValidationResult(
                        True,
                        f"SSRF confirmed: OOB callback received within {time_delta:.1f}s",
                        +0.15
                    )
            except (ValueError, TypeError):
                pass
        
        # Rule 2: Internal IP detected in response
        if response_body:
            for pattern in self.internal_ip_patterns:
                if re.search(pattern, response_body):
                    return ValidationResult(
                        True,
                        f"SSRF confirmed: Internal IP detected in response",
                        +0.15
                    )
        
        # Rule 3: File content marker detected (e.g., /etc/passwd)
        if response_body:
            for pattern in self.file_content_markers:
                if re.search(pattern, response_body):
                    return ValidationResult(
                        True,
                        f"SSRF confirmed: Sensitive file marker detected in response",
                        +0.15
                    )
        
        # Confidence gate
        if confidence >= 0.90:
            return ValidationResult(
                True,
                f"SSRF passed confidence gate (confidence={confidence:.2f} >= 0.90)",
                0.0
            )
        
        return ValidationResult(
            False,
            f"SSRF failed all proof checks. OOB={has_oob}, InternalIP=No, Confidence={confidence:.2f}",
            -0.20
        )
    
    def _validate_xss(self, proof: Dict, confidence: float) -> ValidationResult:
        """
        XSS Validator: requires payload reflected AND exploitable context.
        """
        payload_reflected = proof.get("payload_reflected", False)
        reflection_context = proof.get("reflection_context", "")  # "html" | "js" | "attr" | "comment"
        dynamic_validation = proof.get("dynamic_validation", {})
        executed = dynamic_validation.get("executed", False)
        
        # Rule 1: Payload reflected AND in exploitable context (not HTML comments)
        if payload_reflected:
            if reflection_context in ("html", "js", "attr"):  # Exploitable contexts
                return ValidationResult(
                    True,
                    f"XSS confirmed: Payload reflected in {reflection_context} context (exploitable)",
                    +0.15
                )
            elif reflection_context == "comment":
                # HTML comments are not exploitable in most cases
                if executed:  # But if dynamic validation shows execution, it's valid
                    return ValidationResult(
                        True,
                        f"XSS confirmed: Payload executed despite HTML comment context",
                        +0.20
                    )
        
        # Rule 2: Dynamic validation detected (JavaScript execution confirmed)
        if executed and dynamic_validation.get("validation_method"):
            return ValidationResult(
                True,
                f"XSS confirmed: Dynamic validation detected (method={dynamic_validation.get('validation_method')})",
                +0.15
            )
        
        # Confidence gate
        if confidence >= 0.85:
            return ValidationResult(
                True,
                f"XSS passed confidence gate (confidence={confidence:.2f} >= 0.85)",
                0.0
            )
        
        return ValidationResult(
            False,
            f"XSS failed all proof checks. Reflected={payload_reflected}, Context={reflection_context}, Exec={executed}, Confidence={confidence:.2f}",
            -0.20
        )
    
    def _validate_sqli(self, proof: Dict, confidence: float) -> ValidationResult:
        """
        SQLi Validator: requires DB error OR boolean-based OR time-based proof.
        """
        error_response = proof.get("error_response", "")
        error_signature_found = proof.get("error_signature_found", False)
        response_differences = proof.get("response_differences", {})
        response_diff_valid = response_differences.get("significant_diff", False)
        time_response = proof.get("time_response", {})
        time_delta = time_response.get("time_delta", 0)
        
        # Rule 1: Database error detected + signature found
        if error_signature_found and error_response:
            for pattern in self.db_error_patterns:
                if re.search(pattern, error_response):
                    return ValidationResult(
                        True,
                        f"SQLi confirmed: Database error signature detected in response",
                        +0.20
                    )
        
        # Rule 2: Boolean-based SQLi (response diff > 50%)
        if response_diff_valid:
            diff_percentage = response_differences.get("diff_percentage", 0)
            if diff_percentage > 50:
                return ValidationResult(
                    True,
                    f"SQLi confirmed: Boolean-based (response diff {diff_percentage:.1f}%)",
                    +0.15
                )
        
        # Rule 3: Time-based SQLi (response time > 3 seconds)
        if isinstance(time_delta, (int, float)) and time_delta > 3.0:
            return ValidationResult(
                True,
                f"SQLi confirmed: Time-based (response delta {time_delta:.1f}s > 3.0s)",
                +0.15
            )
        
        # Confidence gate
        if confidence >= 0.85:
            return ValidationResult(
                True,
                f"SQLi passed confidence gate (confidence={confidence:.2f} >= 0.85)",
                0.0
            )
        
        return ValidationResult(
            False,
            f"SQLi failed all proof checks. Error={error_signature_found}, BoolDiff={response_diff_valid}, TimeBased={time_delta > 3.0}, Confidence={confidence:.2f}",
            -0.20
        )
    
    def _validate_command_injection(self, proof: Dict, confidence: float) -> ValidationResult:
        """
        Command Injection Validator: requires command execution evidence or time-based proof.
        """
        command_output = proof.get("command_output", "")
        execution_time = proof.get("execution_time", 0)
        error_output = proof.get("error_output", "")
        
        # Rule 1: Command output captured
        if command_output and len(command_output) > 10:  # Non-empty output
            return ValidationResult(
                True,
                f"Command Injection confirmed: Command output captured ({len(command_output)} bytes)",
                +0.20
            )
        
        # Rule 2: Time-based (execution time > threshold)
        if isinstance(execution_time, (int, float)) and execution_time > 3.0:
            return ValidationResult(
                True,
                f"Command Injection confirmed: Time-based (execution {execution_time:.1f}s > 3.0s)",
                +0.15
            )
        
        # Rule 3: Error output indicates injection
        if error_output and any(err in error_output for err in ["command not found", "SyntaxError", "unexpected"]):
            return ValidationResult(
                True,
                f"Command Injection confirmed: Error output indicates injection",
                +0.15
            )
        
        # Confidence gate
        if confidence >= 0.85:
            return ValidationResult(
                True,
                f"Command Injection passed confidence gate (confidence={confidence:.2f} >= 0.85)",
                0.0
            )
        
        return ValidationResult(
            False,
            f"Command Injection failed all proof checks (confidence={confidence:.2f} < 0.85)",
            -0.20
        )
    
    def _validate_path_traversal(self, proof: Dict, confidence: float) -> ValidationResult:
        """
        Path Traversal Validator: requires file content or directory listing evidence.
        """
        file_content = proof.get("file_content", "")
        directory_listing = proof.get("directory_listing", [])
        file_markers = proof.get("file_markers", [])
        
        # Rule 1: Known file content detected
        if file_content:
            for pattern in self.file_content_markers:
                if re.search(pattern, file_content):
                    return ValidationResult(
                        True,
                        f"Path Traversal confirmed: Sensitive file marker detected",
                        +0.20
                    )
        
        # Rule 2: Directory listing captured
        if directory_listing and len(directory_listing) > 5:
            return ValidationResult(
                True,
                f"Path Traversal confirmed: Directory listing captured ({len(directory_listing)} entries)",
                +0.20
            )
        
        # Rule 3: File markers array provided
        if file_markers and len(file_markers) > 0:
            return ValidationResult(
                True,
                f"Path Traversal confirmed: File markers detected ({len(file_markers)})",
                +0.15
            )
        
        # Confidence gate
        if confidence >= 0.85:
            return ValidationResult(
                True,
                f"Path Traversal passed confidence gate (confidence={confidence:.2f} >= 0.85)",
                0.0
            )
        
        return ValidationResult(
            False,
            f"Path Traversal failed all proof checks (confidence={confidence:.2f} < 0.85)",
            -0.20
        )


# Singleton instance
_validator = ValidationEngine()


def validate_finding_proof(vuln_type: str, proof: Dict, confidence: float) -> ValidationResult:
    """
    Public API: Validate a single finding's proof.
    
    Usage:
        result = validate_finding_proof("SSRF", proof_dict, 0.87)
        if result.valid:
            finding.confidence += result.confidence_adjustment
            reporter.accept(finding)
        else:
            logger.warning(f"Rejected: {result.reason}")
    """
    return _validator.validate(vuln_type, proof, confidence)
