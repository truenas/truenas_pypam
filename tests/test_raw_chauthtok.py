"""Tests for truenas_pypam password change (chauthtok) functionality."""

import os
import pwd
import pytest
import truenas_pypam


# Test credentials from examples/raw_basic_auth.py
TEST_USER = 'bob'
CORRECT_PASSWORD = 'Cats'
WRONG_PASSWORD = 'Dogs'
NEW_PASSWORD = 'Birds'


@pytest.fixture
def run_as_user():
    """Fixture to temporarily switch euid to test user."""
    if os.geteuid() != 0:
        # Not running as root, skip euid switching
        yield
        return

    # Get the test user's uid
    try:
        user_info = pwd.getpwnam(TEST_USER)
        test_uid = user_info.pw_uid
    except KeyError:
        # Test user doesn't exist, can't switch
        yield
        return

    original_euid = os.geteuid()
    try:
        os.seteuid(test_uid)
        yield
    finally:
        os.seteuid(original_euid)


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


def callback_change_password(ctx, messages, private_data):
    """PAM conversation callback function for password change."""
    reply = []
    for m in messages:
        rep = None
        if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            msg_lower = m.msg.lower()
            if 'new' in msg_lower:
                rep = private_data.get('new_password')
            elif 'retype' in msg_lower or 'again' in msg_lower:
                rep = private_data.get('new_password')
            elif 'current' in msg_lower or 'password' in msg_lower:
                rep = private_data.get('current_password')
            else:
                # Default to current password for unrecognized prompts
                rep = private_data.get('current_password')
        reply.append(rep)
    return reply


def test_chauthtok_method_exists():
    """Test that chauthtok method exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    assert hasattr(ctx, 'chauthtok')
    assert callable(ctx.chauthtok)


def test_chauthtok_and_verify():
    """Test that password change actually changes the password."""
    # First verify we can authenticate with the current password
    auth_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    auth_ctx.authenticate()  # Should succeed with current password

    # Try to change the password
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    change_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    # Attempt password change
    change_ctx.chauthtok()

    # Verify old password no longer works
    old_pass_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    with pytest.raises(truenas_pypam.PAMError):
        old_pass_ctx.authenticate()

    # Verify new password works
    new_pass_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': NEW_PASSWORD}
    )
    new_pass_ctx.authenticate()

    # Change password back to original
    data_back = {
        'current_password': NEW_PASSWORD,
        'new_password': CORRECT_PASSWORD
    }
    change_back_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data_back
    )
    change_back_ctx.chauthtok()

    # Verify original password works again
    final_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    final_ctx.authenticate()


def test_chauthtok_with_silent_flag():
    """Test chauthtok with silent flag and verify it works."""
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    # Change with silent flag
    ctx.chauthtok(silent=True)

    # Verify password was changed
    new_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': NEW_PASSWORD}
    )
    new_ctx.authenticate()

    # Change back
    data_back = {
        'current_password': NEW_PASSWORD,
        'new_password': CORRECT_PASSWORD
    }
    ctx_back = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data_back
    )
    ctx_back.chauthtok(silent=True)


def test_chauthtok_with_change_expired_flag():
    """Test chauthtok with change_expired_authtok flag."""
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    # With this flag, should only change if password is expired
    # Since test password likely isn't expired, PAM may return error
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.chauthtok(change_expired_authtok=True)

    # Common error codes when password is not expired
    assert exc_info.value.code in [
        truenas_pypam.PAMCode.PAM_MAXTRIES,
        truenas_pypam.PAMCode.PAM_AUTHTOK_ERR,
        truenas_pypam.PAMCode.PAM_PERM_DENIED,
        truenas_pypam.PAMCode.PAM_SUCCESS  # Some configs might succeed
    ]

    # Verify password was NOT changed (still using old password)
    verify_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    verify_ctx.authenticate()  # Should still work with old password


def test_chauthtok_with_both_flags():
    """Test chauthtok with both flags set."""
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    # With change_expired_authtok, PAM may return error if not expired
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.chauthtok(silent=True, change_expired_authtok=True)

    # Common error codes when password is not expired
    assert exc_info.value.code in [
        truenas_pypam.PAMCode.PAM_MAXTRIES,
        truenas_pypam.PAMCode.PAM_AUTHTOK_ERR,
        truenas_pypam.PAMCode.PAM_PERM_DENIED
    ]

    # Verify old password still works
    verify_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    verify_ctx.authenticate()


def test_chauthtok_invalid_kwargs():
    """Test chauthtok with invalid keyword arguments."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    with pytest.raises(TypeError):
        ctx.chauthtok(invalid_arg=True)


def test_chauthtok_unknown_user():
    """Test password change for unknown user."""
    data = {
        'current_password': 'anypass',
        'new_password': 'newpass'
    }
    ctx = truenas_pypam.get_context(
        user='nonexistentuser12345',
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    # Should fail with user unknown or similar error
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.chauthtok()

    # Common error codes for unknown user
    assert exc_info.value.code in [
        truenas_pypam.PAMCode.PAM_USER_UNKNOWN,
        truenas_pypam.PAMCode.PAM_AUTH_ERR,
        truenas_pypam.PAMCode.PAM_PERM_DENIED,
        truenas_pypam.PAMCode.PAM_AUTHTOK_ERR
    ]


def test_chauthtok_wrong_current_password(run_as_user):
    """Test password change with wrong current password."""
    data = {
        'current_password': WRONG_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    # Should fail due to wrong current password
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.chauthtok()

    # Common error codes for authentication failure
    assert exc_info.value.code in [
        truenas_pypam.PAMCode.PAM_AUTH_ERR,
        truenas_pypam.PAMCode.PAM_PERM_DENIED,
        truenas_pypam.PAMCode.PAM_AUTHTOK_ERR,
        truenas_pypam.PAMCode.PAM_AUTHTOK_RECOVERY_ERR
    ]


@pytest.mark.parametrize("silent", [True, False])
def test_chauthtok_silent_variations(silent):
    """Test password change with different silent flag values."""
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    ctx.chauthtok(silent=silent)

    # Verify password changed
    new_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': NEW_PASSWORD}
    )
    new_ctx.authenticate()

    # Change back
    data_back = {
        'current_password': NEW_PASSWORD,
        'new_password': CORRECT_PASSWORD
    }
    ctx_back = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data_back
    )
    ctx_back.chauthtok(silent=silent)


@pytest.mark.parametrize("change_expired", [True, False])
def test_chauthtok_change_expired_variations(change_expired):
    """Test password change with different change_expired_authtok values."""
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    if change_expired:
        # With change_expired=True, PAM may error if password not expired
        with pytest.raises(truenas_pypam.PAMError) as exc_info:
            ctx.chauthtok(change_expired_authtok=change_expired)

        # Common error codes when password is not expired
        assert exc_info.value.code in [
            truenas_pypam.PAMCode.PAM_MAXTRIES,
            truenas_pypam.PAMCode.PAM_AUTHTOK_ERR,
            truenas_pypam.PAMCode.PAM_PERM_DENIED
        ]

        # Verify old password still works
        verify_ctx = truenas_pypam.get_context(
            user=TEST_USER,
            conversation_function=callback_basic_auth,
            conversation_private_data={'password': CORRECT_PASSWORD}
        )
        verify_ctx.authenticate()
    else:
        # Without flag, password should be changed
        ctx.chauthtok(change_expired_authtok=change_expired)

        new_ctx = truenas_pypam.get_context(
            user=TEST_USER,
            conversation_function=callback_basic_auth,
            conversation_private_data={'password': NEW_PASSWORD}
        )
        new_ctx.authenticate()

        # Change back
        data_back = {
            'current_password': NEW_PASSWORD,
            'new_password': CORRECT_PASSWORD
        }
        ctx_back = truenas_pypam.get_context(
            user=TEST_USER,
            conversation_function=callback_change_password,
            conversation_private_data=data_back
        )
        ctx_back.chauthtok()


def test_chauthtok_returns_none():
    """Test that chauthtok returns None on success."""
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    result = ctx.chauthtok()
    assert result is None

    # Verify password was changed
    new_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': NEW_PASSWORD}
    )
    new_ctx.authenticate()

    # Change back
    data_back = {
        'current_password': NEW_PASSWORD,
        'new_password': CORRECT_PASSWORD
    }
    ctx_back = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data_back
    )
    result_back = ctx_back.chauthtok()
    assert result_back is None


def test_chauthtok_verify_persistence():
    """Test that password changes persist across multiple contexts."""
    # Change password
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )
    ctx.chauthtok()

    # Create completely new contexts to verify persistence
    for _ in range(3):
        # Verify old password fails
        old_ctx = truenas_pypam.get_context(
            user=TEST_USER,
            conversation_function=callback_basic_auth,
            conversation_private_data={'password': CORRECT_PASSWORD}
        )
        with pytest.raises(truenas_pypam.PAMError):
            old_ctx.authenticate()

        # Verify new password works
        new_ctx = truenas_pypam.get_context(
            user=TEST_USER,
            conversation_function=callback_basic_auth,
            conversation_private_data={'password': NEW_PASSWORD}
        )
        new_ctx.authenticate()

    # Change back to original
    data_back = {
        'current_password': NEW_PASSWORD,
        'new_password': CORRECT_PASSWORD
    }
    ctx_back = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data_back
    )
    ctx_back.chauthtok()

    # Verify original password works again
    final_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    final_ctx.authenticate()


def test_chauthtok_after_auth():
    """Test password change after authentication."""
    # First authenticate
    auth_data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=auth_data
    )

    ctx.authenticate()

    # Create new context for password change since we can't modify conv_data
    data = {
        'current_password': CORRECT_PASSWORD,
        'new_password': NEW_PASSWORD
    }
    change_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data
    )

    change_ctx.chauthtok()

    # Verify password changed
    new_ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': NEW_PASSWORD}
    )
    new_ctx.authenticate()

    # Change back
    data_back = {
        'current_password': NEW_PASSWORD,
        'new_password': CORRECT_PASSWORD
    }
    ctx_back = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_change_password,
        conversation_private_data=data_back
    )
    ctx_back.chauthtok()
