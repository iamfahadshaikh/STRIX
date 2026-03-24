"""
Adaptive Fuzzing and Retry Logic Engine
Purpose: Automatically mutate payloads and retry exploitation with different techniques
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class EncodingTechnique(Enum):
    """Payload encoding/mutation techniques"""
    NONE = "none"
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HTML_ENCODE = "html_encode"
    BASE64_ENCODE = "base64_encode"
    HEX_ENCODE = "hex_encode"
    UNICODE_ESCAPE = "unicode_escape"
    CASE_VARIATION = "case_variation"
    POLYGLOT = "polyglot"
    MUTATION = "mutation"


@dataclass
class MutatedPayload:
    """Mutated payload variant"""
    original: str
    mutated: str
    technique: EncodingTechnique
    mutation_count: int  # How many times mutated


class AdaptiveFuzzingEngine:
    """
    Adaptive fuzzing and retry logic engine
    
    Automatically:
    - Mutates payloads with different encodings
    - Retries with variations if initial attempt fails
    - Tracks which mutations work (for future optimization)
    - Combines multiple techniques (polyglot payloads)
    """
    
    def __init__(self):
        self.mutation_history: Dict[str, List[MutatedPayload]] = {}
        self.successful_mutations: Dict[str, EncodingTechnique] = {}
    
    def generate_mutations(self, payload: str, max_mutations: int = 10) -> List[MutatedPayload]:
        """
        Generate multiple payload mutations
        
        Args:
            payload: Original payload
            max_mutations: Maximum variations to generate
        
        Returns: List of mutated payloads
        """
        mutations = []
        
        # 1. URL encoding
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._url_encode(payload),
            technique=EncodingTechnique.URL_ENCODE,
            mutation_count=1
        ))
        
        # 2. Double URL encoding
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._url_encode(self._url_encode(payload)),
            technique=EncodingTechnique.DOUBLE_URL_ENCODE,
            mutation_count=2
        ))
        
        # 3. HTML encoding
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._html_encode(payload),
            technique=EncodingTechnique.HTML_ENCODE,
            mutation_count=1
        ))
        
        # 4. Base64 encoding
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._base64_encode(payload),
            technique=EncodingTechnique.BASE64_ENCODE,
            mutation_count=1
        ))
        
        # 5. Hex encoding
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._hex_encode(payload),
            technique=EncodingTechnique.HEX_ENCODE,
            mutation_count=1
        ))
        
        # 6. Unicode escape
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._unicode_escape(payload),
            technique=EncodingTechnique.UNICODE_ESCAPE,
            mutation_count=1
        ))
        
        # 7. Case variation (for keywords)
        mutations.append(MutatedPayload(
            original=payload,
            mutated=self._case_variation(payload),
            technique=EncodingTechnique.CASE_VARIATION,
            mutation_count=1
        ))
        
        # 8. Generic mutations (spaces, comments, etc)
        mutations.extend(self._generic_mutations(payload))
        
        # Return limited set if requested
        return mutations[:max_mutations]
    
    def _url_encode(self, payload: str) -> str:
        """URL encode special characters"""
        from urllib.parse import quote
        return quote(payload, safe='')
    
    def _html_encode(self, payload: str) -> str:
        """HTML encode special characters"""
        import html
        return html.escape(payload)
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encode payload"""
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def _unicode_escape(self, payload: str) -> str:
        """Unicode escape payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def _case_variation(self, payload: str) -> str:
        """Vary case of keywords"""
        # For SQL: OR -> Or, Or, oR
        # For XSS: <script> -> <ScRiPt>, <SCRIPT>, etc
        result = payload
        for keyword in ['script', 'alert', 'select', 'union', 'or', 'and']:
            result = re.sub(
                f'(?i){re.escape(keyword)}',
                lambda m: ''.join([c.upper() if i % 2 else c.lower() 
                                 for i, c in enumerate(m.group(0))]),
                result
            )
        return result
    
    def _generic_mutations(self, payload: str) -> List[MutatedPayload]:
        """Generate generic mutations"""
        mutations = []
        
        # Mutation 1: Add comment syntax (SQL)
        mutated = self._add_sql_comment(payload)
        if mutated != payload:
            mutations.append(MutatedPayload(
                original=payload,
                mutated=mutated,
                technique=EncodingTechnique.MUTATION,
                mutation_count=1
            ))
        
        # Mutation 2: Add whitespace variations
        mutated = self._add_whitespace_variations(payload)
        if mutated != payload:
            mutations.append(MutatedPayload(
                original=payload,
                mutated=mutated,
                technique=EncodingTechnique.MUTATION,
                mutation_count=1
            ))
        
        # Mutation 3: String concatenation (SQL)
        mutated = self._string_concatenation(payload)
        if mutated != payload:
            mutations.append(MutatedPayload(
                original=payload,
                mutated=mutated,
                technique=EncodingTechnique.MUTATION,
                mutation_count=1
            ))
        
        # Mutation 4: Comment breaking
        mutated = self._break_comment(payload)
        if mutated != payload:
            mutations.append(MutatedPayload(
                original=payload,
                mutated=mutated,
                technique=EncodingTechnique.MUTATION,
                mutation_count=1
            ))
        
        return mutations
    
    def _add_sql_comment(self, payload: str) -> str:
        """Add SQL comment variations"""
        # ' OR '1'='1'-- -> ' OR '1'='1'/**/--
        return payload.replace('--', '/**/--')
    
    def _add_whitespace_variations(self, payload: str) -> str:
        """Replace spaces with various whitespace"""
        # In SQL, whitespace can be: space, tab, newline, /**/
        mutated = payload
        mutated = mutated.replace(' ', '/**/') if ' ' in mutated else mutated
        return mutated
    
    def _string_concatenation(self, payload: str) -> str:
        """Break payloads with string concatenation"""
        # 'select' -> 'se' 'lect'
        if len(payload) > 4:
            mid = len(payload) // 2
            if payload[0] in ('"', "'"):
                return f"{payload[:mid]}'{payload[mid:]}" if "'" in payload[mid:] else payload
        return payload
    
    def _break_comment(self, payload: str) -> str:
        """Break with different comment styles"""
        # Add line comment at specific points
        if '--' in payload:
            return payload.replace('--', '#')
        if '/*' in payload:
            return payload.replace('/*', '--')
        return payload
    
    def generate_retry_sequence(self, initial_payload: str, 
                               max_attempts: int = 10) -> List[Dict]:
        """
        Generate adaptive retry sequence
        
        Starts with simple payloads, progressively applies encoding
        
        Returns: List of payloads with metadata for iterative attempts
        """
        sequence = []
        
        # Attempt 1: Original payload
        sequence.append({
            "attempt": 1,
            "payload": initial_payload,
            "technique": EncodingTechnique.NONE.value,
            "description": "Original payload",
        })
        
        # Get mutations
        mutations = self.generate_mutations(initial_payload, max_attempts - 1)
        
        # Add mutations in sequence
        for i, mutation in enumerate(mutations, start=2):
            sequence.append({
                "attempt": i,
                "payload": mutation.mutated,
                "technique": mutation.technique.value,
                "description": f"{mutation.technique.value} mutation",
            })
        
        return sequence
    
    def track_successful_mutation(self, original: str, technique: EncodingTechnique):
        """Track which mutations successfully exploited targets"""
        key = f"{original[:30]}..."
        if key not in self.successful_mutations:
            self.successful_mutations[key] = technique
            logger.info(f"Successful mutation technique recorded: {technique.value} for {key}")
    
    def get_recommended_techniques(self, payload_type: str = "universal") -> List[EncodingTechnique]:
        """
        Get recommended encoding techniques based on payload type
        
        Args:
            payload_type: Type of payload (sqli, xss, ssrf, universal)
        
        Returns: Ordered list of techniques to try
        """
        if payload_type == "sqli":
            return [
                EncodingTechnique.CASE_VARIATION,
                EncodingTechnique.MUTATION,  # Whitespace/comments
                EncodingTechnique.NONE,
                EncodingTechnique.URL_ENCODE,
                EncodingTechnique.DOUBLE_URL_ENCODE,
            ]
        elif payload_type == "xss":
            return [
                EncodingTechnique.CASE_VARIATION,
                EncodingTechnique.HTML_ENCODE,
                EncodingTechnique.UNICODE_ESCAPE,
                EncodingTechnique.URL_ENCODE,
                EncodingTechnique.MUTATION,
            ]
        elif payload_type == "ssrf":
            return [
                EncodingTechnique.NONE,
                EncodingTechnique.URL_ENCODE,
                EncodingTechnique.DOUBLE_URL_ENCODE,
                EncodingTechnique.HEX_ENCODE,
            ]
        else:
            return [
                EncodingTechnique.NONE,
                EncodingTechnique.URL_ENCODE,
                EncodingTechnique.HTML_ENCODE,
                EncodingTechnique.CASE_VARIATION,
                EncodingTechnique.UNICODE_ESCAPE,
                EncodingTechnique.MUTATION,
            ]
    
    def should_continue_fuzzing(self, attempt_count: int, 
                               max_attempts: int = 10,
                               last_confidence: float = 0.0) -> bool:
        """
        Decide whether to continue fuzzing
        
        Args:
            attempt_count: Number of attempts so far
            max_attempts: Maximum attempts allowed
            last_confidence: Confidence from last attempt
        
        Returns: True if should continue, False to stop
        """
        # Stop if max attempts reached
        if attempt_count >= max_attempts:
            return False
        
        # Continue if we have reasonable confidence (keep trying)
        if last_confidence > 0.7:  # Already high confidence
            return False  # No need to continue
        
        # Continue for more attempts
        return True
    
    def analyze_filter_behavior(self, payloads_and_responses: List[Tuple[str, str]]) -> Dict:
        """
        Analyze filter behavior to recommend bypasses
        
        Args:
            payloads_and_responses: List of (payload, response) tuples
        
        Returns: Dict with filter behavior analysis and recommendations
        """
        analysis = {
            "filters_detected": [],
            "bypass_recommendations": [],
            "pattern": "unknown",
        }
        
        # Check if all payloads are blocked
        all_blocked = all(
            "<script>" not in resp and "error" not in resp.lower()
            for _, resp in payloads_and_responses
        )
        
        if all_blocked:
            analysis["pattern"] = "all_payloads_blocked"
            analysis["bypass_recommendations"] = [
                "Try encoding mutations",
                "Try case variations",
                "Try mixed encoding",
            ]
        
        # Check if specific keywords are filtered
        for keyword in ["script", "alert", "select", "union"]:
            if any(keyword not in p.lower() for p, _ in payloads_and_responses):
                if any(keyword in p.lower() and "<" not in r for p, r in payloads_and_responses):
                    analysis["filters_detected"].append(f"'{keyword}' keyword filtered")
        
        return analysis
