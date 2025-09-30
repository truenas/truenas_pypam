"""Tests for truenas_pypam context functionality."""

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


def test_get_context_function_exists():
    """Test that get_context function is available."""
    assert hasattr(truenas_pypam, 'get_context')
    assert callable(truenas_pypam.get_context)


def test_get_context_minimal_args():
    """Test get_context with minimal required arguments."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx is not None


@pytest.mark.parametrize("service_name", [
    'login',
    'ssh',
    'sudo',
    'custom-service',
])
def test_get_context_with_service_name(service_name):
    """Test get_context with different service names."""
    ctx = truenas_pypam.get_context(
        service_name=service_name,
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx is not None


@pytest.mark.parametrize("username", [
    TEST_USER,
    'admin',
    'user123',
    'test_user',
])
def test_get_context_with_usernames(username):
    """Test get_context with different usernames."""
    ctx = truenas_pypam.get_context(
        user=username,
        conversation_function=callback_basic_auth
    )
    assert ctx is not None


def test_get_context_with_optional_args():
    """Test get_context with all optional arguments."""
    private_data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        service_name='test',
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=private_data,
        rhost='testhost',
        ruser='remoteuser',
        fail_delay=1000
    )
    assert ctx is not None


def test_get_context_missing_user():
    """Test get_context fails without user argument."""
    with pytest.raises(ValueError, match="user is required"):
        truenas_pypam.get_context(
            conversation_function=callback_basic_auth
        )


def test_get_context_missing_conversation_function():
    """Test get_context fails without conversation_function argument."""
    with pytest.raises(ValueError, match="conversation_function is required"):
        truenas_pypam.get_context(
            user=TEST_USER
        )


def test_get_context_invalid_conversation_function():
    """Test get_context fails with non-callable conversation_function."""
    match_msg = "conversation_function must be callable"
    with pytest.raises(TypeError, match=match_msg):
        truenas_pypam.get_context(
            user=TEST_USER,
            conversation_function='not_callable'
        )


@pytest.mark.parametrize("method_name", [
    'authenticate',
    'get_env',
    'set_env',
    'env_dict',
    'setcred',
])
def test_context_has_methods(method_name):
    """Test that PAM context has expected methods."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert hasattr(ctx, method_name)
    assert callable(getattr(ctx, method_name))


def test_context_type():
    """Test PAM context type."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert str(type(ctx)) == "<class 'truenas_pypam.PamContext'>"


def test_context_user_attribute():
    """Test PAM context has user attribute stored internally."""
    # Context doesn't expose user attribute directly, but we can test
    # it was set by verifying authentication works with the user we specified
    data = {'password': CORRECT_PASSWORD}
    ctx_with_data = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data
    )
    ctx_with_data.authenticate()


@pytest.mark.parametrize("fail_delay", [
    0,
    1000,
    5000,
    10000,
])
def test_get_context_with_fail_delay(fail_delay):
    """Test get_context with different fail_delay values."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        fail_delay=fail_delay
    )
    assert ctx is not None


def test_get_context_with_none_private_data():
    """Test get_context with None as private data."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=None
    )
    assert ctx is not None


def test_get_context_with_dict_private_data():
    """Test get_context with dictionary as private data."""
    private_data = {'password': CORRECT_PASSWORD, 'number': 42}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=private_data
    )
    assert ctx is not None


def test_get_context_with_list_private_data():
    """Test get_context with list as private data."""
    private_data = [CORRECT_PASSWORD, 'item2', 'item3']
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=private_data
    )
    assert ctx is not None
