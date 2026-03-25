"""
Unit Tests for Auth + IDOR Engine
Purpose: Validate components in isolation and integration
Run with: pytest test_auth_idor_engine.py -v
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from core.request_engine import RequestEngine, RequestMethod, HTTPResponse
from core.session_manager import SessionManager, SessionData, AuthType, TokenInfo
from modules.auth_engine import AuthEngine, LoginConfig
from auth_utils.param_extractor import ParameterExtractor, ParameterType
from auth_utils.response_analyzer import ResponseAnalyzer, SensitivityLevel


class TestRequestEngine:
    """Test request engine"""
    
    @pytest.mark.asyncio
    async def test_request_engine_initialization(self):
        """Request engine should initialize properly"""
        engine = RequestEngine(timeout=30.0, verify_ssl=False)
        assert engine.timeout == 30.0
        assert engine.verify_ssl == False
    
    @pytest.mark.asyncio
    async def test_request_logging(self):
        """Requests should be logged"""
        engine = RequestEngine()
        assert isinstance(engine.request_log, list)


class TestSessionManager:
    """Test session management"""
    
    @pytest.mark.asyncio
    async def test_session_creation(self):
        """Session should be created for role"""
        manager = SessionManager()
        session = await manager.create_session("user", AuthType.FORM_LOGIN)
        assert session.role == "user"
        assert session.auth_type == AuthType.FORM_LOGIN
    
    @pytest.mark.asyncio
    async def test_session_expiry(self):
        """Session should detect expiry"""
        manager = SessionManager(default_session_timeout=1)
        session = await manager.create_session("user", AuthType.FORM_LOGIN)
        
        # Not expired immediately
        assert not session.is_expired()
        
        # Wait for expiry
        await asyncio.sleep(2)
        assert session.is_expired()
    
    @pytest.mark.asyncio
    async def test_session_cookies(self):
        """Cookies should be stored in session"""
        manager = SessionManager()
        session = await manager.create_session("user", AuthType.FORM_LOGIN)
        
        cookies = {"session_id": "abc123"}
        await manager.update_cookies("user", cookies)
        
        retrieved = await manager.get_session("user")
        assert retrieved.cookies == cookies
    
    @pytest.mark.asyncio
    async def test_session_token(self):
        """Token should be stored in session"""
        manager = SessionManager()
        session = await manager.create_session("user", AuthType.FORM_LOGIN)
        
        token = TokenInfo(
            token="jwt_token_here",
            token_field="access_token"
        )
        await manager.set_token("user", token)
        
        retrieved = await manager.get_session("user")
        assert retrieved.token_info == token


class TestParameterExtractor:
    """Test parameter extraction"""
    
    def test_numeric_id_extraction(self):
        """Should extract numeric IDs"""
        extractor = ParameterExtractor()
        url = "https://api.example.com/users?user_id=123"
        
        params = extractor.extract_from_url(url, "/users")
        assert len(params) > 0
        
        user_id = params[0]
        assert user_id.name == "user_id"
        assert user_id.param_type == ParameterType.NUMERIC_ID
    
    def test_json_parameter_extraction(self):
        """Should extract parameters from JSON"""
        extractor = ParameterExtractor()
        
        body = '{"account_id": 456}'
        params = extractor.extract_from_json_body(body, "/api/accounts")
        
        assert len(params) > 0
        assert params[0].name == "account_id"
    
    def test_excluded_fields(self):
        """Should exclude non-ID fields"""
        extractor = ParameterExtractor()
        url = "https://example.com/page?page=1&api_key=secret"
        
        params = extractor.extract_from_url(url, "/page")
        
        # api_key should be excluded
        param_names = [p.name for p in params]
        assert "api_key" not in param_names


class TestResponseAnalyzer:
    """Test response analysis"""
    
    def test_email_detection(self):
        """Should detect emails"""
        analyzer = ResponseAnalyzer()
        
        response_body = '{"email": "user@example.com"}'
        result = analyzer.analyze(200, response_body)
        
        assert result.has_sensitive_data
        assert any("email" in m.field_name for m in result.sensitive_matches)
    
    def test_api_key_detection(self):
        """Should detect API keys"""
        analyzer = ResponseAnalyzer()
        
        response_body = 'api_key="sk_live_abcd1234"'
        result = analyzer.analyze(200, response_body)
        
        # Should find high-sensitivity match
        critical = [m for m in result.sensitive_matches 
                   if m.sensitivity == SensitivityLevel.CRITICAL]
        assert len(critical) > 0
    
    def test_json_structure_parsing(self):
        """Should parse JSON structure"""
        analyzer = ResponseAnalyzer()
        
        response_body = '{"user": {"name": "John", "email": "john@example.com"}}'
        result = analyzer.analyze(200, response_body, 
                                 headers={"Content-Type": "application/json"})
        
        assert result.is_json
        assert result.json_structure is not None


class TestAuthEngine:
    """Test authentication engine"""
    
    @pytest.mark.asyncio
    async def test_login_config_registration(self):
        """Login config should be registered"""
        mock_engine = AsyncMock()
        auth_engine = AuthEngine(mock_engine)
        
        config = LoginConfig(
            role="user",
            auth_type=AuthType.FORM_LOGIN,
            login_url="https://example.com/login",
            username="test@example.com",
            password="password123"
        )
        
        success = await auth_engine.register_login_flow(config)
        assert success
        assert "user" in auth_engine.login_configs
    
    @pytest.mark.asyncio
    async def test_invalid_config_rejected(self):
        """Invalid configs should be rejected"""
        mock_engine = AsyncMock()
        auth_engine = AuthEngine(mock_engine)
        
        # Missing required fields
        invalid_config = LoginConfig(
            role="",  # Empty role
            auth_type=AuthType.FORM_LOGIN,
            login_url="https://example.com/login"
        )
        
        success = await auth_engine.register_login_flow(invalid_config)
        assert not success


class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test complete auth + testing workflow"""
        # Initialize components
        request_engine = RequestEngine()
        auth_engine = AuthEngine(request_engine)
        param_extractor = ParameterExtractor()
        response_analyzer = ResponseAnalyzer()
        
        # Register config (would come from JSON in practice)
        config = LoginConfig(
            role="user",
            auth_type=AuthType.FORM_LOGIN,
            login_url="https://example.com/login",
            username="test@example.com",
            password="password123",
            login_data={
                "email": "test@example.com",
                "password": "password123"
            }
        )
        
        success = await auth_engine.register_login_flow(config)
        assert success
        
        # Verify session manager initialized
        sessions = await auth_engine.session_manager.list_sessions()
        assert isinstance(sessions, dict)


# Run tests with: pytest test_auth_idor_engine.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
