"""Tests for truenas_pypam credential functionality."""

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


def test_setcred_method_exists():
    """Test that setcred method exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )
    assert hasattr(ctx, 'setcred')
    assert callable(ctx.setcred)


def test_setcred_missing_operation():
    """Test setcred fails without operation argument."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    with pytest.raises(TypeError):
        ctx.setcred()


@pytest.mark.parametrize("invalid_operation", [
    42,
    "PAM_ESTABLISH_CRED",
    None,
    [],
    {},
])
def test_setcred_invalid_operation_type(invalid_operation):
    """Test setcred fails with invalid operation types."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    match_msg = "operation must be a CredOp enum member"
    with pytest.raises(TypeError, match=match_msg):
        ctx.setcred(operation=invalid_operation)


def test_setcred_keyword_only_args():
    """Test setcred requires keyword arguments."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # Should fail because operation must be keyword argument
    with pytest.raises(TypeError):
        ctx.setcred(truenas_pypam.CredOp.PAM_ESTABLISH_CRED)


@pytest.mark.parametrize("invalid_kwarg", [
    'invalid_arg',
    'unknown_param',
    'extra_flag',
])
def test_setcred_invalid_kwargs(invalid_kwarg):
    """Test setcred with invalid keyword arguments."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    kwargs = {
        'operation': truenas_pypam.CredOp.PAM_ESTABLISH_CRED,
        invalid_kwarg: True
    }

    with pytest.raises(TypeError):
        ctx.setcred(**kwargs)


@pytest.mark.parametrize("operation_name,operation_value", [
    ('PAM_ESTABLISH_CRED', truenas_pypam.CredOp.PAM_ESTABLISH_CRED),
    ('PAM_DELETE_CRED', truenas_pypam.CredOp.PAM_DELETE_CRED),
    ('PAM_REINITIALIZE_CRED', truenas_pypam.CredOp.PAM_REINITIALIZE_CRED),
    ('PAM_REFRESH_CRED', truenas_pypam.CredOp.PAM_REFRESH_CRED),
])
def test_setcred_operation_enum_attributes(operation_name, operation_value):
    """Test setcred operation enum values have correct attributes."""
    # Verify the operation has the expected name
    assert operation_value.name == operation_name
    assert isinstance(operation_value, truenas_pypam.CredOp)
    assert isinstance(operation_value, int)


def test_setcred_with_wrong_password_then_establish_cred():
    """Test setcred after failed authentication with wrong password."""
    data = {'password': WRONG_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )

    # Authentication should fail with wrong password
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.authenticate()

    assert exc_info.value.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert exc_info.value.code.name == 'PAM_AUTH_ERR'

    # This fails because we aren't authenticated
    with pytest.raises(truenas_pypam.PAMError) as exc_info:
        ctx.setcred(operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED)

    assert exc_info.value.code == truenas_pypam.PAMCode.PAM_CRED_ERR
    assert exc_info.value.code.name == 'PAM_CRED_ERR'


@pytest.mark.parametrize("operation", [
    truenas_pypam.CredOp.PAM_ESTABLISH_CRED,
    truenas_pypam.CredOp.PAM_DELETE_CRED,
    truenas_pypam.CredOp.PAM_REINITIALIZE_CRED,
    truenas_pypam.CredOp.PAM_REFRESH_CRED,
])
def test_setcred_operations_without_auth(operation):
    """Test setcred operations without prior authentication."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # Call setcred without authenticating first
    # This should either succeed (if module allows) or fail with specific error
    ctx.setcred(operation=operation)


@pytest.mark.parametrize("silent", [True, False])
def test_setcred_silent_flag(silent):
    """Test setcred with silent flag variations."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    ctx.setcred(
        operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED,
        silent=silent
    )


@pytest.mark.parametrize("operation,silent", [
    (truenas_pypam.CredOp.PAM_ESTABLISH_CRED, True),
    (truenas_pypam.CredOp.PAM_ESTABLISH_CRED, False),
    (truenas_pypam.CredOp.PAM_DELETE_CRED, True),
    (truenas_pypam.CredOp.PAM_DELETE_CRED, False),
    (truenas_pypam.CredOp.PAM_REINITIALIZE_CRED, True),
    (truenas_pypam.CredOp.PAM_REINITIALIZE_CRED, False),
    (truenas_pypam.CredOp.PAM_REFRESH_CRED, True),
    (truenas_pypam.CredOp.PAM_REFRESH_CRED, False),
])
def test_setcred_operation_silent_combinations(operation, silent):
    """Test all combinations of operations and silent flag."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    result = ctx.setcred(operation=operation, silent=silent)
    # setcred should return None on success
    assert result is None


@pytest.mark.parametrize("user", [TEST_USER, 'testuser1', 'admin'])
def test_setcred_different_users(user):
    """Test setcred with different user contexts."""
    ctx = truenas_pypam.get_context(
        user=user,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    ctx.setcred(operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED)


def test_setcred_sequence_establish_refresh_delete():
    """Test typical setcred sequence: establish, refresh, delete."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data={'password': CORRECT_PASSWORD}
    )

    # Typical credential lifecycle
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_ESTABLISH_CRED)
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_REFRESH_CRED)
    ctx.setcred(operation=truenas_pypam.CredOp.PAM_DELETE_CRED)
