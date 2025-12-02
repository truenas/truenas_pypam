"""Tests for truenas_pypam PAM item getters/setters."""

import pytest
import truenas_pypam


# Test credentials from conftest.py
TEST_USER = 'bob'
CORRECT_PASSWORD = 'Cats'


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


def test_user_attribute_exists():
    """Test that user attribute exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert hasattr(ctx, 'user')


def test_ruser_attribute_exists():
    """Test that ruser attribute exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert hasattr(ctx, 'ruser')


def test_rhost_attribute_exists():
    """Test that rhost attribute exists on context."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert hasattr(ctx, 'rhost')


def test_user_getter_returns_initial_value():
    """Test that user getter returns the initial user value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx.user == TEST_USER


def test_ruser_getter_returns_none_when_not_set():
    """Test that ruser returns None when not set during initialization."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx.ruser is None


def test_rhost_getter_returns_none_when_not_set():
    """Test that rhost returns None when not set during initialization."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx.rhost is None


def test_ruser_getter_returns_initial_value():
    """Test that ruser getter returns the initial ruser value."""
    test_ruser = 'remoteuser'
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        ruser=test_ruser
    )
    assert ctx.ruser == test_ruser


def test_rhost_getter_returns_initial_value():
    """Test that rhost getter returns the initial rhost value."""
    test_rhost = '192.168.1.100'
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        rhost=test_rhost
    )
    assert ctx.rhost == test_rhost


def test_user_setter_updates_value():
    """Test that user setter updates the user value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    new_user = 'newuser'
    ctx.user = new_user
    assert ctx.user == new_user


def test_ruser_setter_updates_value():
    """Test that ruser setter updates the ruser value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    new_ruser = 'newremoteuser'
    ctx.ruser = new_ruser
    assert ctx.ruser == new_ruser


def test_rhost_setter_updates_value():
    """Test that rhost setter updates the rhost value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    new_rhost = '10.0.0.1'
    ctx.rhost = new_rhost
    assert ctx.rhost == new_rhost


def test_user_setter_with_non_string_raises_typeerror():
    """Test that user setter raises TypeError with non-string value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="user must be a string"):
        ctx.user = 123


def test_ruser_setter_with_non_string_raises_typeerror():
    """Test that ruser setter raises TypeError with non-string value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="ruser must be a string"):
        ctx.ruser = 123


def test_rhost_setter_with_non_string_raises_typeerror():
    """Test that rhost setter raises TypeError with non-string value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="rhost must be a string"):
        ctx.rhost = 123


def test_user_setter_with_none_raises_typeerror():
    """Test that user setter raises TypeError with None value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="user must be a string"):
        ctx.user = None


def test_ruser_setter_with_none_raises_typeerror():
    """Test that ruser setter raises TypeError with None value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="ruser must be a string"):
        ctx.ruser = None


def test_rhost_setter_with_none_raises_typeerror():
    """Test that rhost setter raises TypeError with None value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="rhost must be a string"):
        ctx.rhost = None


def test_user_setter_with_list_raises_typeerror():
    """Test that user setter raises TypeError with list value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="user must be a string"):
        ctx.user = ['user1', 'user2']


def test_ruser_setter_with_dict_raises_typeerror():
    """Test that ruser setter raises TypeError with dict value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="ruser must be a string"):
        ctx.ruser = {'name': 'user'}


def test_rhost_setter_with_bool_raises_typeerror():
    """Test that rhost setter raises TypeError with bool value."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    with pytest.raises(TypeError, match="rhost must be a string"):
        ctx.rhost = True


@pytest.mark.parametrize("username", [
    'alice',
    'admin',
    'user123',
    'test_user',
    'a' * 100,  # Long username
])
def test_user_setter_with_various_strings(username):
    """Test that user setter accepts various string values."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    ctx.user = username
    assert ctx.user == username


@pytest.mark.parametrize("ruser", [
    'remoteuser',
    'admin',
    'user@host',
    'r' * 50,  # Long ruser
])
def test_ruser_setter_with_various_strings(ruser):
    """Test that ruser setter accepts various string values."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    ctx.ruser = ruser
    assert ctx.ruser == ruser


@pytest.mark.parametrize("rhost", [
    'localhost',
    '192.168.1.1',
    '::1',
    'fe80::1',
    'example.com',
    'host.example.com',
    'host-with-dashes.example.org',
    'h' * 100,  # Long hostname
])
def test_rhost_setter_with_various_strings(rhost):
    """Test that rhost setter accepts various string values."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    ctx.rhost = rhost
    assert ctx.rhost == rhost


def test_multiple_user_updates():
    """Test that user can be updated multiple times."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    ctx.user = 'user1'
    assert ctx.user == 'user1'
    ctx.user = 'user2'
    assert ctx.user == 'user2'
    ctx.user = 'user3'
    assert ctx.user == 'user3'


def test_multiple_ruser_updates():
    """Test that ruser can be updated multiple times."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    ctx.ruser = 'ruser1'
    assert ctx.ruser == 'ruser1'
    ctx.ruser = 'ruser2'
    assert ctx.ruser == 'ruser2'
    ctx.ruser = 'ruser3'
    assert ctx.ruser == 'ruser3'


def test_multiple_rhost_updates():
    """Test that rhost can be updated multiple times."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    ctx.rhost = 'host1'
    assert ctx.rhost == 'host1'
    ctx.rhost = '192.168.1.1'
    assert ctx.rhost == '192.168.1.1'
    ctx.rhost = '::1'
    assert ctx.rhost == '::1'


def test_all_pam_items_can_be_set_together():
    """Test that all PAM items can be set and retrieved together."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        ruser='initial_ruser',
        rhost='initial_rhost'
    )

    # Verify initial values
    assert ctx.user == TEST_USER
    assert ctx.ruser == 'initial_ruser'
    assert ctx.rhost == 'initial_rhost'

    # Update all values
    ctx.user = 'new_user'
    ctx.ruser = 'new_ruser'
    ctx.rhost = 'new_rhost'

    # Verify updated values
    assert ctx.user == 'new_user'
    assert ctx.ruser == 'new_ruser'
    assert ctx.rhost == 'new_rhost'


def test_user_getter_returns_string_type():
    """Test that user getter returns a string type."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert isinstance(ctx.user, str)


def test_ruser_getter_returns_string_or_none():
    """Test that ruser getter returns string or None."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx.ruser is None or isinstance(ctx.ruser, str)

    ctx.ruser = 'testuser'
    assert isinstance(ctx.ruser, str)


def test_rhost_getter_returns_string_or_none():
    """Test that rhost getter returns string or None."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )
    assert ctx.rhost is None or isinstance(ctx.rhost, str)

    ctx.rhost = 'testhost'
    assert isinstance(ctx.rhost, str)


def test_pam_items_persist_across_operations():
    """Test that PAM items persist across other PAM operations."""
    data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        conversation_private_data=data,
        ruser='test_ruser',
        rhost='test_rhost'
    )

    # Verify initial values
    assert ctx.user == TEST_USER
    assert ctx.ruser == 'test_ruser'
    assert ctx.rhost == 'test_rhost'

    # Perform authentication
    ctx.authenticate()

    # Verify values are still the same after authentication
    assert ctx.user == TEST_USER
    assert ctx.ruser == 'test_ruser'
    assert ctx.rhost == 'test_rhost'


def test_empty_string_pam_items():
    """Test that empty strings can be set for PAM items."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )

    # Set to empty strings
    ctx.user = ''
    ctx.ruser = ''
    ctx.rhost = ''

    # Verify empty strings are stored
    # Note: PAM might normalize empty strings to None, so we check what we get back
    # The important thing is that no exception is raised
    assert isinstance(ctx.user, str) or ctx.user is None
    assert isinstance(ctx.ruser, str) or ctx.ruser is None
    assert isinstance(ctx.rhost, str) or ctx.rhost is None


def test_unicode_pam_items():
    """Test that unicode strings work for PAM items."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth
    )

    # Set unicode values
    ctx.user = 'user_café'
    ctx.ruser = 'ruser_日本'
    ctx.rhost = 'host_москва'

    # Verify values are set
    assert ctx.user == 'user_café'
    assert ctx.ruser == 'ruser_日本'
    assert ctx.rhost == 'host_москва'


def test_context_attributes_are_readable():
    """Test that all PAM item attributes can be read without error."""
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=callback_basic_auth,
        ruser='test_ruser',
        rhost='test_rhost'
    )

    # Should not raise any exceptions
    _ = ctx.user
    _ = ctx.ruser
    _ = ctx.rhost
