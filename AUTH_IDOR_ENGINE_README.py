"""
AUTH + IDOR ENGINE INTEGRATION GUIDE
================================================================================

OVERVIEW
--------
This is a production-grade authentication + IDOR/access control testing engine
for the VAPT automated framework.

COMPONENTS
----------

1. CORE INFRASTRUCTURE
   ├── core/request_engine.py      : Central HTTP request handler with auth injection
   └── core/session_manager.py     : Per-role session management

2. AUTHENTICATION ENGINE
   └── modules/auth_engine.py      : Multi-role login + token extraction

3. VULNERABILITY DETECTION
   ├── modules/idor_engine.py      : IDOR detection with proof validation
   └── modules/access_control_engine.py : Privilege escalation & unauthorized access

4. UTILITIES
   ├── auth_utils/param_extractor.py    : Identify parameters for mutation testing
   └── auth_utils/response_analyzer.py  : Detect sensitive data in responses

5. CONFIGURATION
   └── auth_config/auth_config.json : Role definitions, endpoints, credentials

6. ORCHESTRATION
   └── auth_idor_orchestrator.py   : Complete workflow integration


QUICK START
===========

1. CONFIGURE AUTHENTICATION
   
   Edit auth_config/auth_config.json:
   
   {
     "authentication_engines": [
       {
         "enabled": true,
         "role": "user",
         "auth_type": "form_login",
         "login_url": "/login",
         "username": "user@example.com",
         "password": "password123",
         "login_data": {
           "email": "user@example.com",
           "password": "password123"
         },
         "token_field_path": "data.access_token"
       }
     ]
   }


2. INITIALIZE ENGINES

   from core.request_engine import RequestEngine
   from modules.auth_engine import AuthEngine
   from auth_utils.param_extractor import ParameterExtractor
   from auth_utils.response_analyzer import ResponseAnalyzer
   from modules.idor_engine import IDOREngine
   
   async with RequestEngine() as request_engine:
       auth_engine = AuthEngine(request_engine)
       idor_engine = IDOREngine(
           request_engine,
           ParameterExtractor(),
           ResponseAnalyzer()
       )


3. AUTHENTICATE USERS

   await auth_engine.register_login_flow(login_config)
   results = await auth_engine.authenticate_all_roles()


4. TEST FOR IDOR

   findings = await idor_engine.test_endpoint(
       endpoint="/api/users/123",
       roles=["user", "admin"]
   )


5. TEST ACCESS CONTROL

   findings = await access_control_engine.test_privilege_escalation(
       endpoint="/admin/users",
       low_role="user",
       high_role="admin"
   )


ARCHITECTURE DETAILS
====================

REQUEST FLOW
------------

1. User initiates authenticated request
2. RequestEngine intercepts
3. AuthEngine injects credentials (cookies, headers, tokens)
4. RequestEngine sends HTTP request
5. ResponseAnalyzer inspects response for sensitive data
6. Vulnerability engines detect issues


SESSION MANAGEMENT
------------------

Each role maintains isolated session:
  
  SessionData per role contains:
  ├── Cookies (if cookie-based auth)
  ├── Headers (including Authorization)
  ├── Token info (JWT, API keys)
  └── Metadata (creation time, expiry, etc)

Sessions auto-refresh on expiry.


IDOR DETECTION WORKFLOW
-----------------------

1. PARAMETER IDENTIFICATION
   - Extract from URL query strings
   - Extract from JSON request bodies
   - Classify type (numeric ID, UUID, etc)

2. MUTATION GENERATION
   - Increment: 123 → 124
   - Decrement: 123 → 122
   - Zero: 123 → 0
   - Random: 123 → 9847
   - Known IDs: 123 → 456 (previously seen)

3. BASELINE COMPARISON
   - Get baseline response (user's own resource)
   - Make request with mutated parameter
   - Compare responses for unauthorized data

4. SENSITIVITY ANALYSIS
   - Detect exposed PII (email, phone, SSN)
   - Detect tokens/keys
   - Detect financial data
   - Calculate risk score

5. PROOF VALIDATION
   - Requires new sensitive data in response
   - High confidence = critical/high data exposed
   - Medium confidence = medium sensitivity data
   - Excludes low-confidence matches


ACCESS CONTROL TESTING
----------------------

1. PRIVILEGE ESCALATION
   - Low role accessing high-role endpoints
   - Example: user → admin API access

2. UNAUTHORIZED ACCESS
   - Unauthenticated users accessing protected resources
   - Example: Anonymous → admin dashboard

3. METHOD TAMPERING
   - POST denied but GET allowed
   - DELETE possible via method override

4. ROLE HEADER BYPASS
   - Setting X-Role: admin header
   - Manipulating is_admin parameters
   - Spoofing role in custom headers


INTEGRATION WITH EXISTING FRAMEWORK
====================================

The Auth+IDOR engine integrates with your existing framework via:

1. FINDINGS MODEL
   - Uses existing FindingType enums (IDOR, AUTH_BYPASS)
   - Generates Finding objects compatible with reporting
   - Adds to existing FindingsRegistry

2. FINDINGS REPORTING
   - Findings include CWE/OWASP mapping
   - Evidence with proof of exploitation
   - Impact/remediation guidance

3. DEDUPLICATION
   - Findings automatically deduplicated by:
     (type, location, cwe)
   - Severity aggregation in registry

4. PROOF-BASED REPORTING
   - All vulnerabilities must include evidence
   - Proof includes actual response data
   - Sensitivity level of exposed data


EXAMPLE: COMPLETE WORKFLOW
===========================

import asyncio
from auth_idor_orchestrator import AuthenticationAndIDOROrchestrator

async def main():
    orchestrator = AuthenticationAndIDOROrchestrator(
        target_url="https://api.example.com"
    )
    
    await orchestrator.run_full_assessment(
        config_path="auth_config/auth_config.json",
        endpoints=[
            "/api/users/123",
            "/api/accounts/456",
            "/admin/dashboard",
        ],
        roles=["user", "admin"],
        output_file="findings.json"
    )

asyncio.run(main())


DETECTION STRICTNESS
====================

To minimize false positives:

1. IDOR DETECTION requires:
   ✅ Status 200-399 (access granted)
   ✅ Different response than baseline
   ✅ Sensitive data in new response
   ✅ High/Critical sensitivity level
   ❌ NOT flagged if only status code changes
   ❌ NOT flagged if response identical to baseline
   ❌ NOT flagged if only low-sensitivity data

2. ACCESS CONTROL requires:
   ✅ Successful access (200-299)
   ✅ Protected endpoint accessed
   ✅ Proper authorization bypass confirmed
   ❌ NOT flagged if access denied (4xx, 5xx)

3. CONFIDENCE SCORING:
   - Numeric IDs: high confidence (0.95)
   - UUIDs: very high confidence (0.95)
   - Custom alphanumeric: medium confidence (0.5-0.85)
   - Unknown format: low confidence (0.3)


CUSTOMIZATION
=============

1. ADD CUSTOM MUTATION STRATEGY:
   
   class IDOREngine:
       def _generate_mutations(self, param):
           mutations.append(MutationStrategy.CUSTOM)
           
       def _mutate_value(self, value, strategy):
           if strategy == MutationStrategy.CUSTOM:
               return your_custom_mutation(value)

2. ADD CUSTOM SENSITIVE FIELD:
   
   ResponseAnalyzer.SENSITIVE_FIELD_NAMES["your_field"] = SensitivityLevel.HIGH

3. ADD CUSTOM ENDPOINT:
   
   AccessControlEngine.ADMIN_ENDPOINTS.append("/your/admin/path")

4. ADD CUSTOM AUTH TYPE:
   
   AuthType.OAUTH2 = "oauth2"
   AuthEngine._handle_oauth2(role, config, session)


PERFORMANCE NOTES
=================

- Async/await for concurrent testing
- Configurable timeouts and retries
- Parameter extraction is fast (regex-based)
- Mutation testing scales with endpoint count
- Concurrent role testing reduces total time

Example: 100 endpoints × 5 mutations × 3 roles
  Without concurrency: ~500 requests per endpoint
  With concurrency: ~10-15 minutes for full test


SECURITY CONSIDERATIONS
=======================

1. CREDENTIALS
   - Config file MUST be protected
   - Never commit auth_config.json to repo
   - Use environment variables for sensitive data

2. SSL VERIFICATION
   - verify_ssl=False only for internal testing
   - Enable for production/cloud targets

3. RATE LIMITING
   - Respect target rate limits
   - Add delays between requests if needed
   - Check for WAF/IDS triggers


TROUBLESHOOTING
===============

Issue: Authentication fails
  → Check login_url, credentials, expected_status_success
  → Verify network connectivity to target
  → Check for WAF/rate limiting

Issue: No IDOR found but should exist
  → Check parameter extraction (endpoints must have IDs)
  → Verify mutation strategies applied to correct params
  → Check response analysis confidence thresholds

Issue: False positives (reporting non-issues)
  → Lower sensitivity thresholds
  → Increase confidence requirements
  → Manual review of evidence


REFERENCES
==========

CWE-639: Authorization Bypass Through User-Controlled Key
  https://cwe.mitre.org/data/definitions/639.html

OWASP A01:2021: Broken Access Control
  https://owasp.org/Top10/A01_2021-Broken_Access_Control/

OWASP Testing Guide - Access Control
  https://owasp.org/www-project-web-security-testing-guide/


LICENSE
=======
Part of VAPT Automated Framework
"""

# Quick syntax check - do not remove
if __name__ == "__main__":
    print(__doc__)
