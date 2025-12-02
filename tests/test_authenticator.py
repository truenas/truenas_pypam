"""Tests for truenas_authenticator high-level API."""

import pytest
import truenas_pypam
from truenas_authenticator import (
    UserPamAuthenticator,
    SimpleAuthenticator,
    AuthenticatorStage,
)


# Test credentials from examples/raw_basic_auth.py
TEST_USER = 'bob'
CORRECT_PASSWORD = 'Cats'
WRONG_PASSWORD = 'Dogs'


def test_user_pam_authenticator_init():
    """Test UserPamAuthenticator initialization."""
    auth = UserPamAuthenticator(username=TEST_USER)
    assert auth.username == TEST_USER
    assert auth.state.service == 'login'
    assert auth.state.stage == AuthenticatorStage.START
    assert auth.ctx is None
    assert auth.authentication_timeout == 10


@pytest.mark.parametrize("service", ['login', 'sshd', 'sudo'])
def test_user_pam_authenticator_init_service(service):
    """Test UserPamAuthenticator with different services."""
    auth = UserPamAuthenticator(username=TEST_USER, service=service)
    assert auth.state.service == service


def test_user_pam_authenticator_init_with_timeout():
    """Test UserPamAuthenticator with custom timeout."""
    auth = UserPamAuthenticator(username=TEST_USER, authentication_timeout=30)
    assert auth.authentication_timeout == 30


def test_user_pam_authenticator_init_with_rhost():
    """Test UserPamAuthenticator with remote host."""
    auth = UserPamAuthenticator(username=TEST_USER, rhost='192.168.1.1')
    assert auth.rhost == '192.168.1.1'


def test_auth_init_returns_conv_again():
    """Test auth_init returns PAM_CONV_AGAIN for conversation."""
    auth = UserPamAuthenticator(username=TEST_USER)
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert resp.stage == AuthenticatorStage.AUTH
    assert isinstance(resp.reason, tuple)
    assert auth.state.stage == AuthenticatorStage.AUTH


def test_auth_init_already_in_progress():
    """Test auth_init raises error if already in progress."""
    auth = UserPamAuthenticator(username=TEST_USER)
    auth.auth_init()

    # Should raise error on second call
    with pytest.raises(RuntimeError) as exc_info:
        auth.auth_init()

    assert "already in progress" in str(exc_info.value).lower()


def test_auth_continue_without_init():
    """Test auth_continue raises error without auth_init."""
    auth = UserPamAuthenticator(username=TEST_USER)

    with pytest.raises(RuntimeError) as exc_info:
        auth.auth_continue(['password'])

    assert "not in auth stage" in str(exc_info.value).lower()


def test_auth_continue_with_correct_password():
    """Test auth_continue with correct password."""
    auth = UserPamAuthenticator(username=TEST_USER)
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide password response
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(CORRECT_PASSWORD)
        else:
            responses.append(None)

    resp = auth.auth_continue(responses)

    # Should succeed
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert resp.stage == AuthenticatorStage.AUTH
    assert auth.state.stage == AuthenticatorStage.LOGIN
    assert auth.ctx is not None


def test_auth_continue_with_wrong_password():
    """Test auth_continue with wrong password."""
    auth = UserPamAuthenticator(username=TEST_USER)
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide wrong password
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(WRONG_PASSWORD)
        else:
            responses.append(None)

    resp = auth.auth_continue(responses)

    # Should fail
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert resp.stage == AuthenticatorStage.AUTH
    assert auth.state.stage == AuthenticatorStage.START  # Reset on failure
    assert auth.ctx is None


def test_check_stage():
    """Test check_stage method."""
    auth = UserPamAuthenticator(username=TEST_USER)

    # Should not raise for correct stage
    auth.check_stage(AuthenticatorStage.START)

    # Should raise for incorrect stage
    with pytest.raises(RuntimeError) as exc_info:
        auth.check_stage(AuthenticatorStage.LOGIN)

    assert "unexpected authenticator run state" in str(exc_info.value)


def test_open_session_without_auth():
    """Test open_session raises error without authentication."""
    auth = UserPamAuthenticator(username=TEST_USER)

    with pytest.raises(RuntimeError) as exc_info:
        auth.open_session()

    assert "unexpected authenticator run state" in str(exc_info.value)


def test_close_session_without_auth():
    """Test close_session raises error without authentication."""
    auth = UserPamAuthenticator(username=TEST_USER)

    with pytest.raises(RuntimeError) as exc_info:
        auth.close_session()

    assert "unexpected authenticator run state" in str(exc_info.value)


def test_end_cleanup():
    """Test end method cleans up resources."""
    auth = UserPamAuthenticator(username=TEST_USER)
    resp = auth.auth_init()

    # Start authentication
    assert auth._thread_state is not None
    assert auth._auth_thread is not None

    # Clean up
    auth.end()

    assert auth.ctx is None
    assert auth._thread_state is None
    assert auth._auth_thread is None
    assert auth.state.stage == AuthenticatorStage.START


def test_simple_authenticator_init():
    """Test SimpleAuthenticator initialization."""
    auth = SimpleAuthenticator(username=TEST_USER, password=CORRECT_PASSWORD)
    assert auth.username == TEST_USER
    assert auth.password == CORRECT_PASSWORD
    assert auth.state.service == 'login'


@pytest.mark.parametrize("password,expected", [
    (CORRECT_PASSWORD, True),
    (WRONG_PASSWORD, False),
])
def test_simple_authenticator_authenticate_simple(password, expected):
    """Test SimpleAuthenticator authenticate_simple method."""
    auth = SimpleAuthenticator(username=TEST_USER, password=password)
    result = auth.authenticate_simple()
    assert result == expected


def test_authenticator_response_fields():
    """Test AuthenticatorResponse fields."""
    auth = UserPamAuthenticator(username=TEST_USER)
    resp = auth.auth_init()

    assert hasattr(resp, 'stage')
    assert hasattr(resp, 'code')
    assert hasattr(resp, 'reason')
    assert hasattr(resp, 'user_info')


def test_authenticator_stage_values():
    """Test AuthenticatorStage enum values."""
    assert AuthenticatorStage.START == 'START'
    assert AuthenticatorStage.AUTH == 'AUTH'
    assert AuthenticatorStage.LOGIN == 'LOGIN'
    assert AuthenticatorStage.LOGOUT == 'LOGOUT'


@pytest.mark.parametrize("rhost,ruser", [
    ('192.168.1.1', None),
    (None, 'remoteuser'),
    ('192.168.1.1', 'remoteuser'),
])
def test_user_pam_authenticator_with_remote_params(rhost, ruser):
    """Test UserPamAuthenticator with remote parameters."""
    auth = UserPamAuthenticator(
        username=TEST_USER,
        rhost=rhost,
        ruser=ruser
    )
    assert auth.rhost == rhost
    assert auth.ruser == ruser


def test_user_pam_authenticator_with_fail_delay():
    """Test UserPamAuthenticator with fail delay."""
    auth = UserPamAuthenticator(
        username=TEST_USER,
        fail_delay=1000000  # 1 second in microseconds
    )
    assert auth.fail_delay == 1000000


def test_login_without_auth():
    """Test login raises error without authentication."""
    auth = UserPamAuthenticator(username=TEST_USER)

    with pytest.raises(RuntimeError) as exc_info:
        auth.login()

    assert "unexpected authenticator run state" in str(exc_info.value)


def test_logout_without_login():
    """Test logout raises error without login."""
    auth = UserPamAuthenticator(username=TEST_USER)

    with pytest.raises(RuntimeError) as exc_info:
        auth.logout()

    assert "unexpected authenticator run state" in str(exc_info.value)


def test_login_at_property():
    """Test login_at property."""
    auth = UserPamAuthenticator(username=TEST_USER)
    assert auth.login_at is None  # Not logged in yet
