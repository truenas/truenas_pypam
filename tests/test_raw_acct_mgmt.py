"""Tests for truenas_pypam account management functionality."""

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


def test_acct_mgmt_method_exists():
    """Test that acct_mgmt method exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    assert hasattr(ctx, 'acct_mgmt')
    assert callable(ctx.acct_mgmt)


def test_acct_mgmt_after_successful_auth():
    """Test account management after successful authentication."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Authenticate first
    ctx.authenticate()

    # Account management should succeed for valid account
    ctx.acct_mgmt()


def test_acct_mgmt_without_auth():
    """Test that acct_mgmt can be called without prior authentication."""
    # Note: pam_acct_mgmt can be called without authentication
    # but may have different behavior depending on PAM configuration
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # This may succeed or fail depending on PAM configuration
    # Just ensure it doesn't crash
    try:
        ctx.acct_mgmt()
    except truenas_pypam.PAMError:
        pass  # Expected in some configurations


def test_acct_mgmt_with_silent_flag():
    """Test acct_mgmt with silent flag."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.acct_mgmt(silent=True)


def test_acct_mgmt_with_disallow_null_authtok():
    """Test acct_mgmt with disallow_null_authtok flag."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.acct_mgmt(disallow_null_authtok=True)


def test_acct_mgmt_no_auth_disallow_null_authtok2():
    """Test acct_mgmt with disallow_null_authtok flag."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.acct_mgmt(disallow_null_authtok=True)


def test_acct_mgmt_with_both_flags():
    """Test acct_mgmt with both flags set."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.acct_mgmt(silent=True, disallow_null_authtok=True)


def test_acct_mgmt_invalid_kwargs():
    """Test acct_mgmt with invalid keyword arguments."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()

    with pytest.raises(TypeError):
        ctx.acct_mgmt(invalid_arg=True)


def test_acct_mgmt_after_wrong_password():
    """Test account management after failed authentication."""
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

    # Account management may still work without successful auth
    # depending on PAM configuration
    try:
        ctx.acct_mgmt()
    except truenas_pypam.PAMError:
        pass  # Expected in some configurations


def test_acct_mgmt_unknown_user():
    """Test account management for unknown user."""
    ctx = truenas_pypam.get_context(
        user='nonexistentuser12345',
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': 'anypass'}
    )

    # Should fail with user unknown or similar error
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.acct_mgmt()

    # Could be PAM_USER_UNKNOWN or PAM_AUTH_ERR depending on config
    assert exc_info.value.code in [
        truenas_pypam.PAMCode.PAM_USER_UNKNOWN,
        truenas_pypam.PAMCode.PAM_AUTH_ERR,
        truenas_pypam.PAMCode.PAM_PERM_DENIED
    ]


@pytest.mark.parametrize("silent", [True, False])
def test_acct_mgmt_silent_variations(silent):
    """Test account management with different silent flag values."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.acct_mgmt(silent=silent)


@pytest.mark.parametrize("disallow_null", [True, False])
def test_acct_mgmt_disallow_null_variations(disallow_null):
    """Test account management with different disallow_null_authtok values."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    ctx.acct_mgmt(disallow_null_authtok=disallow_null)


def test_acct_mgmt_returns_none():
    """Test that acct_mgmt returns None on success."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()
    result = ctx.acct_mgmt()
    assert result is None


def test_full_lifecycle_with_acct_mgmt():
    """Test complete PAM lifecycle including account management."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Full lifecycle: authenticate -> acct_mgmt -> setcred -> open_session
    ctx.authenticate()
    ctx.acct_mgmt()
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED)
    ctx.open_session()
    ctx.close_session()
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_DELETE_CRED)


@pytest.mark.parametrize("user", [TEST_USER, 'testuser1', 'admin'])
def test_acct_mgmt_different_users(user):
    """Test account management with different user contexts."""
    ctx = truenas_pypam.get_context(
        user=user,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # Only TEST_USER with correct password should fully succeed
    if user == TEST_USER:
        ctx.authenticate()
        ctx.acct_mgmt()
    else:
        # Others may fail at different points
        try:
            ctx.authenticate()
            ctx.acct_mgmt()
        except truenas_pypam.PAMError:
            pass  # Expected for non-existent users


def test_acct_mgmt_multiple_calls():
    """Test that acct_mgmt can be called multiple times."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    ctx.authenticate()

    # Should be able to call acct_mgmt multiple times
    for _ in range(3):
        ctx.acct_mgmt()
