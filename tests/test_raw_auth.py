"""Tests for truenas_pypam authentication functionality."""

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


def test_authenticate_method_exists():
    """Test that authenticate method exists on context."""
    ctx = truenas_pypam.get_context(
        user='testuser',
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': 'testpass'}
    )
    assert hasattr(ctx, 'authenticate')
    assert callable(ctx.authenticate)


def test_authenticate_with_correct_password():
    """Test authenticate with correct password succeeds."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()


def test_authenticate_with_wrong_password():
    """Test authenticate with wrong password fails."""
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.authenticate()

    assert exc_info.value.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert exc_info.value.code.name == 'PAM_AUTH_ERR'
    assert exc_info.value.code.value == 7
    assert str(exc_info.value).startswith('[PAM_AUTH_ERR]')
    assert exc_info.value.message.startswith('pam_authenticate()')


@pytest.mark.parametrize("silent", [True, False])
def test_authenticate_with_silent_flag(silent):
    """Test authenticate with silent flag using correct password."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate(silent=silent)


@pytest.mark.parametrize("disallow_null_authtok", [True, False])
def test_authenticate_with_disallow_null_authtok(disallow_null_authtok):
    """Test authenticate with disallow_null_authtok flag."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate(disallow_null_authtok=disallow_null_authtok)


def test_authenticate_with_both_flags():
    """Test authenticate with both flags set."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate(silent=True, disallow_null_authtok=True)


def test_authenticate_pam_error_attributes():
    """Test PAMError exception has expected attributes."""
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.authenticate()

    e = exc_info.value
    # Check that PAMError has expected attributes
    assert hasattr(e, 'code')
    assert hasattr(e, 'name')
    assert hasattr(e, 'message')
    assert hasattr(e, 'err_str')
    assert hasattr(e, 'location')

    # Check that code is a PAMCode enum
    assert isinstance(e.code, truenas_pypam.PAMCode)

    # Check string representation
    str_repr = str(e)
    assert e.name in str_repr
    assert '[' in str_repr and ']' in str_repr


def test_authenticate_error_code():
    """Test that authenticate returns PAM_AUTH_ERR for wrong password."""
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.authenticate()

    # Should get PAM_AUTH_ERR for wrong password
    assert exc_info.value.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert hasattr(truenas_pypam.PAMCode, exc_info.value.code.name)


def test_authenticate_with_conversation_callback():
    """Test authenticate with conversation callback interaction."""
    conversation_called = []

    def test_conversation_function(ctx, messages, private_data):
        conversation_called.append(True)
        # Provide password for any password prompts
        responses = []
        for msg in messages:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append('testpassword')
            else:
                responses.append(None)
        return responses

    ctx = truenas_pypam.get_context(
        user='testuser',
        conversation_function=test_conversation_function,
        conversation_private_data={'password': 'testpassword'}
    )

    try:
        ctx.authenticate()
    except truenas_pypam.PAMError:
        pass  # Expected to fail with invalid credentials

    # Conversation may or may not be called depending on PAM configuration


def test_authenticate_invalid_kwargs():
    """Test authenticate with invalid keyword arguments."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    with pytest.raises(TypeError):
        ctx.authenticate(invalid_arg=True)


def test_authenticate_multiple_calls():
    """Test that authenticate can be called multiple times."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Should be able to call authenticate multiple times
    for _ in range(3):
        ctx.authenticate()


def test_authenticate_with_different_users():
    """Test authenticate behavior with different user contexts."""
    # Test with wrong password for different user
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user='testuser1',
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    with pytest.raises(truenas_pypam.PAMError):
        ctx.authenticate()


def test_authenticate_error_message_format():
    """Test that PAM error messages are properly formatted."""
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.authenticate()

    e = exc_info.value
    # Error message should contain function name
    assert 'pam_authenticate()' in e.message

    # String representation should start with [ERROR_NAME]
    str_repr = str(e)
    assert str_repr.startswith('[')
    assert ']' in str_repr
