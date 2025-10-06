"""Tests for truenas_pypam conversation functionality."""

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


def test_conversation_callback_receives_correct_parameters():
    """Test conversation callback receives expected parameters."""
    received_params = []

    def test_conversation_function(ctx, messages, private_data):
        received_params.append((ctx, messages, private_data))
        # Provide proper responses
        reply = []
        for m in messages:
            rep = None
            if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                if 'Password' in m.msg:
                    rep = private_data['password']
            reply.append(rep)
        return reply

    private_data = {'password': CORRECT_PASSWORD}
    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=test_conversation_function,
        conversation_private_data=private_data
    )

    # Trigger conversation by attempting authentication
    ctx.authenticate()

    # Check conversation was called and received correct parameters
    assert len(received_params) > 0
    ctx_param, messages_param, private_data_param = received_params[0]
    assert ctx_param is ctx
    assert messages_param is not None
    assert len(messages_param) > 0
    assert private_data_param is private_data


def test_conversation_with_none_private_data():
    """Test conversation function with None private data."""
    received_params = []

    def test_conversation_function(ctx, messages, private_data):
        received_params.append((ctx, messages, private_data))
        # Return empty responses since we have no password data
        return [None] * len(messages)

    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=test_conversation_function,
        conversation_private_data=None
    )

    # This should fail since we have no password
    with pytest.raises(truenas_pypam.PAMError):
        ctx.authenticate()

    # Check conversation was called with None private data
    assert len(received_params) > 0
    _, _, private_data_param = received_params[0]
    assert private_data_param is None


@pytest.mark.parametrize("private_data", [
    {'password': 'secret'},
    {'user': 'admin', 'token': '12345'},
    {'config': {'timeout': 30}},
    [1, 2, 3],
    'string_data',
    42,
])
def test_conversation_with_various_private_data(private_data):
    """Test conversation function with various private data types."""
    received_data = []

    def test_conversation_function(ctx, messages, data):
        received_data.append(data)
        return [None] * len(messages)

    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=test_conversation_function,
        conversation_private_data=private_data
    )

    with pytest.raises(truenas_pypam.PAMError):
        ctx.authenticate()

    assert len(received_data) > 0
    assert received_data[0] == private_data


def test_conversation_return_value_validation():
    """Test conversation function return value validation."""
    def invalid_conversation_function(ctx, messages, private_data):
        # Return wrong number of responses
        return []

    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=invalid_conversation_function
    )

    # This should raise a PAMError due to invalid response count
    with pytest.raises(ValueError):
        ctx.authenticate()


def test_conversation_messages_structure():
    """Test that conversation messages have expected structure."""
    received_messages = []

    def test_conversation_function(ctx, messages, private_data):
        received_messages.extend(messages)
        responses = []
        for msg in messages:
            # Each message should have msg_style and msg attributes
            assert hasattr(msg, 'msg_style')
            assert hasattr(msg, 'msg')

            # msg_style should be MSGStyle enum
            assert isinstance(msg.msg_style, truenas_pypam.MSGStyle)

            # msg should be string
            assert isinstance(msg.msg, str)

            responses.append(None)
        return responses

    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=test_conversation_function
    )

    with pytest.raises(truenas_pypam.PAMError):
        ctx.authenticate()


def test_conversation_exception_handling():
    """Test conversation function exception handling."""
    def failing_conversation_function(ctx, messages, private_data):
        raise ValueError("Test exception in conversation")

    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=failing_conversation_function
    )

    # Exception in conversation should result in PAMError
    with pytest.raises((truenas_pypam.PAMError, ValueError)):
        ctx.authenticate()


def test_multiple_conversation_calls():
    """Test that conversation function can be called multiple times."""
    call_count = []

    def counting_conversation_function(ctx, messages, private_data):
        call_count.append(len(messages))
        return [None] * len(messages)

    ctx = truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=counting_conversation_function
    )

    # Try multiple authenticate calls
    for _ in range(3):
        with pytest.raises(truenas_pypam.PAMError):
            ctx.authenticate()

    # Conversation may have been called (depends on PAM config)
    # This test just ensures no crashes occur with multiple calls
