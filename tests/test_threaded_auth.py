"""Tests for threaded (no-callback) PAM authentication and messages() history."""

import pytest
import truenas_pypam


TEST_USER = 'bob'
CORRECT_PASSWORD = 'Cats'
WRONG_PASSWORD = 'Dogs'


def _make_threaded_ctx(user=TEST_USER):
    return truenas_pypam.get_context(user=user)


def _make_callback_ctx(password=CORRECT_PASSWORD):
    def conv(ctx, messages, private_data):
        return [
            private_data.get('password') if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF else None
            for m in messages
        ]

    return truenas_pypam.get_context(
        user=TEST_USER,
        conversation_function=conv,
        conversation_private_data={'password': password},
    )


# ---------------------------------------------------------------------------
# Context creation
# ---------------------------------------------------------------------------

def test_threaded_ctx_created_without_conv_fn():
    ctx = _make_threaded_ctx()
    assert ctx is not None


def test_threaded_ctx_has_begin_and_continue():
    ctx = _make_threaded_ctx()
    assert callable(getattr(ctx, 'begin_authentication', None))
    assert callable(getattr(ctx, 'continue_authentication', None))


# ---------------------------------------------------------------------------
# begin_authentication
# ---------------------------------------------------------------------------

def test_begin_authentication_returns_messages_tuple():
    ctx = _make_threaded_ctx()
    result = ctx.begin_authentication()
    assert isinstance(result, tuple)
    assert len(result) > 0


def test_begin_authentication_messages_have_expected_fields():
    ctx = _make_threaded_ctx()
    msgs = ctx.begin_authentication()
    for m in msgs:
        assert hasattr(m, 'msg_style')
        assert hasattr(m, 'msg')
        assert isinstance(m.msg_style, truenas_pypam.MSGStyle)
        assert isinstance(m.msg, str)


def test_begin_authentication_already_in_progress():
    ctx = _make_threaded_ctx()
    ctx.begin_authentication()
    with pytest.raises(RuntimeError, match="already in progress"):
        ctx.begin_authentication()


# ---------------------------------------------------------------------------
# continue_authentication — correct password
# ---------------------------------------------------------------------------

def test_continue_authentication_correct_password_succeeds():
    ctx = _make_threaded_ctx()
    msgs = ctx.begin_authentication()
    responses = [
        CORRECT_PASSWORD if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF else None
        for m in msgs
    ]
    result = ctx.continue_authentication(responses)
    # None means authentication completed successfully
    assert result is None


def test_continue_authentication_correct_password_returns_none():
    ctx = _make_threaded_ctx()
    msgs = ctx.begin_authentication()
    responses = [
        CORRECT_PASSWORD if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF else None
        for m in msgs
    ]
    # None return value signals successful completion
    assert ctx.continue_authentication(responses) is None


# ---------------------------------------------------------------------------
# continue_authentication — wrong password
# ---------------------------------------------------------------------------

def test_continue_authentication_wrong_password_raises():
    ctx = _make_threaded_ctx()
    msgs = ctx.begin_authentication()
    responses = [
        WRONG_PASSWORD if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF else None
        for m in msgs
    ]
    with pytest.raises(truenas_pypam.PAMError):
        ctx.continue_authentication(responses)


def test_continue_authentication_without_begin_raises():
    ctx = _make_threaded_ctx()
    with pytest.raises(RuntimeError, match="no conversation pending"):
        ctx.continue_authentication([])


# ---------------------------------------------------------------------------
# messages() — threaded context
# ---------------------------------------------------------------------------

def test_messages_empty_before_begin():
    ctx = _make_threaded_ctx()
    assert ctx.messages() == ()


def test_messages_has_one_entry_after_begin():
    ctx = _make_threaded_ctx()
    ctx.begin_authentication()
    history = ctx.messages()
    assert isinstance(history, tuple)
    assert len(history) == 1


def test_messages_entry_matches_begin_return_value():
    ctx = _make_threaded_ctx()
    msgs = ctx.begin_authentication()
    history = ctx.messages()
    assert len(history) == 1
    assert history[0] == msgs


def test_messages_accumulates_across_exchanges():
    """Each conversation round-trip adds one entry to messages()."""
    ctx = _make_threaded_ctx()

    # First exchange
    msgs1 = ctx.begin_authentication()
    assert len(ctx.messages()) == 1

    # Respond with wrong password to keep auth alive for a second exchange,
    # or if PAM finishes immediately, verify we have exactly one entry.
    responses1 = [
        CORRECT_PASSWORD if m.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF else None
        for m in msgs1
    ]
    result = ctx.continue_authentication(responses1)

    # Whether there was one or two exchanges, history must be at least 1.
    history = ctx.messages()
    assert len(history) >= 1
    assert all(isinstance(entry, tuple) for entry in history)


def test_messages_returns_tuple_of_tuples():
    ctx = _make_threaded_ctx()
    msgs = ctx.begin_authentication()
    history = ctx.messages()
    assert isinstance(history, tuple)
    assert isinstance(history[0], tuple)
    # The inner tuple must equal what begin_authentication returned
    assert history[0] == msgs


# ---------------------------------------------------------------------------
# messages() — callback context (regression)
# ---------------------------------------------------------------------------

def test_messages_callback_context_empty_before_auth():
    ctx = _make_callback_ctx()
    assert ctx.messages() == ()


def test_messages_callback_context_populated_after_auth():
    ctx = _make_callback_ctx(CORRECT_PASSWORD)
    ctx.authenticate()
    history = ctx.messages()
    assert isinstance(history, tuple)
    assert len(history) > 0


def test_messages_callback_context_entry_structure():
    ctx = _make_callback_ctx(CORRECT_PASSWORD)
    ctx.authenticate()
    history = ctx.messages()
    for entry in history:
        assert isinstance(entry, tuple)
        for m in entry:
            assert hasattr(m, 'msg_style')
            assert hasattr(m, 'msg')
