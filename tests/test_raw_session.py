"""Tests for truenas_pypam session functionality."""

import pytest
import truenas_pypam


# Test credentials from examples/raw_basic_auth.py
TEST_USER = 'bob'
CORRECT_PASSWORD = 'Cats'
WRONG_PASSWORD = 'Dogs'


def callback_basic_auth(ctx, messages, private_data):
    """PAM conversation callback function for basic auth."""
    reply = []
    for m in messages:
        rep = None
        # PAM_PROMPT_ECHO_OFF (1) - typically password prompts
        if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            if 'Password' in m.msg:
                rep = private_data['password']
        reply.append(rep)
    return reply


def test_open_session_method_exists():
    """Test that open_session method exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    assert hasattr(ctx, 'open_session')
    assert callable(ctx.open_session)


def test_close_session_method_exists():
    """Test that close_session method exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    assert hasattr(ctx, 'close_session')
    assert callable(ctx.close_session)


def test_open_session_without_auth_fails():
    """Test that open_session fails without prior authentication."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # Opening session without authentication should fail
    with pytest.raises(ValueError):
        ctx.open_session()


def test_open_close_session_after_auth():
    """Test open and close session after successful authentication."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Authenticate first
    ctx.authenticate()

    # Now open session should work
    ctx.open_session()

    # Close session should also work
    ctx.close_session()


def test_open_session_with_silent_flag():
    """Test open_session with silent flag."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.open_session(silent=True)
    ctx.close_session()


def test_close_session_with_silent_flag():
    """Test close_session with silent flag."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.open_session()
    ctx.close_session(silent=True)


def test_multiple_session_operations():
    """Test multiple open/close session operations."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()

    # Should be able to open and close session multiple times
    for _ in range(3):
        ctx.open_session()
        ctx.close_session()


def test_close_session_without_open():
    """Test close_session without opening session first."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()

    # Closing without opening should raise ValueError
    with pytest.raises(ValueError, match="session is not opened"):
        ctx.close_session()


@pytest.mark.parametrize("silent", [True, False])
def test_session_with_silent_variations(silent):
    """Test session operations with different silent flag values."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.open_session(silent=silent)
    ctx.close_session(silent=silent)


def test_session_invalid_kwargs():
    """Test session methods with invalid keyword arguments."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()

    with pytest.raises(TypeError):
        ctx.open_session(invalid_arg=True)

    with pytest.raises(TypeError):
        ctx.close_session(invalid_arg=True)


def test_session_with_wrong_password_auth():
    """Test that session operations fail after failed authentication."""
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Authentication should fail
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.authenticate()

    assert exc_info.value.code == truenas_pypam.PAMCode.PAM_AUTH_ERR

    # Session operations should fail with ValueError (not authenticated)
    match_msg = "pam_authenticate has not been successfully"
    with pytest.raises(ValueError, match=match_msg):
        ctx.open_session()


def test_full_session_lifecycle():
    """Test complete authentication and session lifecycle."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Full lifecycle: authenticate -> setcred -> open_session -> close_session
    ctx.authenticate()
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED)
    ctx.open_session()
    ctx.close_session()
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_DELETE_CRED)


@pytest.mark.parametrize("user", [TEST_USER, 'testuser1', 'admin'])
def test_session_different_users(user):
    """Test session operations with different user contexts."""
    # Only TEST_USER will succeed with CORRECT_PASSWORD
    # Others will fail at authentication
    ctx = truenas_pypam.get_context(
        user=user,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    if user == TEST_USER:
        ctx.authenticate()
        ctx.open_session()
        ctx.close_session()
    else:
        with pytest.raises(truenas_pypam.PAMError):
            ctx.authenticate()


def test_double_open_session_fails():
    """Test that opening a session twice fails."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.open_session()

    # Trying to open session again should raise ValueError
    with pytest.raises(ValueError, match="session is already opened"):
        ctx.open_session()

    # Clean up
    ctx.close_session()


def test_close_session_without_auth():
    """Test that close_session fails without authentication."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # Closing session without authentication should fail
    with pytest.raises(ValueError, match="session is not opened"):
        ctx.close_session()


def test_session_methods_return_none():
    """Test that session methods return None on success."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()

    result = ctx.open_session()
    assert result is None

    result = ctx.close_session()
    assert result is None
